/*
 * Copyright (c) 2010, Facebook, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * Neither the name Facebook nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific
 * prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <flashcache.h>

char buf[512];
char dmsetup_cmd[8192];
int verbose = 0;

void
usage(char *pname)
{
	fprintf(stderr, "Usage: %s ssd_devname [cachedev]\n", pname);
#ifdef COMMIT_REV
	fprintf(stderr, "git commit: %s\n", COMMIT_REV);
#endif
	exit(1);
}

static int 
module_loaded(void)
{
	FILE *fp;
	char line[8192];
	int found = 0;
	
	fp = fopen("/proc/modules", "ro");
	while (fgets(line, 8192, fp)) {
		char *s;
		
		s = strtok(line, " ");
		if (!strcmp(s, "flashcache")) {
			found = 1;
			break;
		}
	}
	return found;
}

static void
load_module(void)
{
	if (module_loaded()) {
		if (verbose)
			fprintf(stderr, "Flashcache Module already loaded\n");		
		return;
	}
	if (verbose)
		fprintf(stderr, "Loading Flashcache Module\n");
	system("modprobe flashcache");
	if (!module_loaded()) {
		fprintf(stderr, "Could not load Flashcache Module\n");
		exit(1);
	}
}

int
main(int argc, char **argv)
{
	int c, cache_fd, disk_fd;
	char *pname;
	char *disk_devname, *ssd_devname, *cachedev;
	struct flash_superblock *sb = (struct flash_superblock *)buf;
	sector_t disk_devsize, cache_devsize;
	int ret;
	int cache_mode;
	
	pname = argv[0];
	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = 1;
                        break;			
		case '?':
			usage(pname);
		}
	}

	if ((argc < 2) || (argc > 4)) {
		usage(pname);
	}
	
	ssd_devname = argv[optind++];
	cache_fd = open(ssd_devname, O_RDONLY);
	if (cache_fd < 0) {
		fprintf(stderr, "Failed to open %s\n", ssd_devname);
		exit(1);
	}
        lseek(cache_fd, 0, SEEK_SET);
	if (read(cache_fd, buf, 512) < 0) {
		fprintf(stderr, "Cannot read Flashcache superblock %s\n", ssd_devname);
		exit(1);		
	}
	if (!(sb->cache_sb_state == CACHE_MD_STATE_DIRTY ||
	      sb->cache_sb_state == CACHE_MD_STATE_CLEAN ||
	      sb->cache_sb_state == CACHE_MD_STATE_FASTCLEAN ||
	      sb->cache_sb_state == CACHE_MD_STATE_UNSTABLE)) {
		fprintf(stderr, "%s: Invalid Flashcache superblock %s\n", pname, ssd_devname);
		exit(1);
	}

	if ((strncmp(sb->cache_devname, ssd_devname, DEV_PATHLEN) == 0) && (argc == 2)) {
		fprintf(stderr, "%s: Upgrading older v2 superblock format, please supply cachedev virtual device name\n", pname);
		usage(pname);
	}
	
	// switch to new vdev name if requested by load command
	if (optind == argc) {
		cachedev = sb->cache_devname;
	} else {
		cachedev = argv[optind];
	}
	disk_devname = sb->disk_devname;

	disk_fd = open(disk_devname, O_RDONLY);
	if (disk_fd < 0) {
		fprintf(stderr, "%s: Failed to open %s\n", pname, disk_devname);
		exit(1);
	}
	if (ioctl(cache_fd, BLKGETSIZE, &cache_devsize) < 0) {
		fprintf(stderr, "%s: Cannot get cache size %s\n", pname, ssd_devname);
		exit(1);		
	}
	if (ioctl(disk_fd, BLKGETSIZE, &disk_devsize) < 0) {
		fprintf(stderr, "%s: Cannot get disk size %s\n", pname, disk_devname);
		exit(1);				
	}
	if (cache_devsize != sb->cache_devsize) {
		fprintf(stderr, "%s: Cache size mismatch, expect %lu, given %lu\n", 
			pname, sb->cache_devsize, cache_devsize);
		exit(1);		
	}
	if (disk_devsize != sb->disk_devsize) {
		fprintf(stderr, "%s: Disk size mismatch, expect %lu, given %lu\n", 
			pname, sb->disk_devsize, disk_devsize);
		exit(1);		
	}
	/* 
	 * Device Names and sizes match the ones stored in the cache superblock, 
	 * Go ahead and load the cache.
	 * XXX - Should use the device mapper library for this.
	 */
	cache_mode = FLASHCACHE_WRITE_BACK;
	sprintf(dmsetup_cmd, "echo 0 %lu flashcache %s %s %s %d 1 | dmsetup create %s",
		disk_devsize, disk_devname, ssd_devname, cachedev, cache_mode, cachedev);
	load_module();
	if (verbose)
		fprintf(stderr, "Loading FlashCache Volume : %s\n", dmsetup_cmd);
	ret = system(dmsetup_cmd);
	if (ret) {
		fprintf(stderr, "%s failed\n", dmsetup_cmd);
		exit(1);
	}
	return 0;
}
