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
#include <ctype.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include <flashcache.h>

#undef COMMIT_REV

void
usage(char *pname)
{
	fprintf(stderr, "Usage: %s [-v] [-p back|thru|around] [-w] [-b block size] [-m md block size] [-s cache size] [-a associativity] cachedev ssd_devname disk_devname\n", pname);
	fprintf(stderr, "Usage : %s Cache Mode back|thru|around is required argument\n",
		pname);
	fprintf(stderr, "Usage : %s Default units for -b, -m, -s are sectors, or specify in k/M/G. Default associativity is 512.\n",
		pname);
#ifdef COMMIT_REV
	fprintf(stderr, "git commit: %s\n", COMMIT_REV);
#endif
	exit(1);
}

char *pname;
char buf[512];
char dmsetup_cmd[8192];
int verbose = 0;
int force = 0;
int write_cache_only = 0;

static sector_t
get_block_size(char *s)
{
	sector_t size;
	char *c;
	
	size = strtoll(s, NULL, 0);
	for (c = s; isdigit(*c); c++)
		;
	switch (*c) {
		case '\0': 
			break;
		case 'k':
			size = (size * 1024) / 512;
			break;
		default:
			fprintf (stderr, "%s: Unknown block size type %c\n", pname, *c);
			exit (1);
	}
	if (size & (size - 1)) {
		fprintf(stderr, "%s: Block size must be a power of 2\n", pname);
		exit(1);
	}
	return size;
}

static sector_t
get_cache_size(char *s)
{
	sector_t size;
	char *c;
	
	size = strtoll(s, NULL, 0);
	for (c = s; isdigit (*c); c++)
		;
	switch (*c) {
		case '\0': 
			break;
		case 'k':
			size = (size * 1024) / 512;
			break;
		case 'm':
		case 'M':
			size = (size * 1024 * 1024) / 512;
			break;
		case 'g': 
		case 'G': 
			size = (size * 1024 * 1024 * 1024) / 512;
			break;
		case 't': 
		case 'T': 
			/* Cache size in terabytes?  You lucky people! */
			size = (size * 1024 * 1024 * 1024 * 1024) / 512;
			break;
		default:
			fprintf (stderr, "%s: Unknown cache size type %c\n", pname, *c);
			exit (1);
	}
	return size;
}

static int 
module_loaded(void)
{
	FILE *fp;
	char line[8192];
	int found = 0;
	
	fp = fopen("/proc/modules", "ro");
	while (fgets(line, 8190, fp)) {
		char *s;
		
		s = strtok(line, " ");
		if (!strcmp(s, "flashcache")) {
			found = 1;
			break;
		}
	}
	fclose(fp);
	return found;
}

static void
load_module(void)
{
	FILE *fp;
	char line[8192];

	if (!module_loaded()) {
		if (verbose)
			fprintf(stderr, "Loading Flashcache Module\n");
		system("modprobe flashcache");
		if (!module_loaded()) {
			fprintf(stderr, "Could not load Flashcache Module\n");
			exit(1);
		}
	} else if (verbose)
			fprintf(stderr, "Flashcache Module already loaded\n");
	fp = fopen("/proc/flashcache/flashcache_version", "ro");
	fgets(line, 8190, fp);
	if (fgets(line, 8190, fp)) {
		if (verbose)
			fprintf(stderr, "version string \"%s\"\n", line);
#ifdef COMMIT_REV
		if (!strstr(line, COMMIT_REV)) {
			fprintf(stderr, "Flashcache revision doesn't match tool revision.\n");
			exit(1);
		}
#endif
	}
	fclose(fp);
}

static void 
check_sure(void)
{
	char input;

	fprintf(stderr, "Are you sure you want to proceed ? (y/n): ");
	scanf("%c", &input);
	printf("\n");
	if (input != 'y') {
		fprintf(stderr, "Exiting FlashCache creation\n");
		exit(1);
	}
}

int
main(int argc, char **argv)
{
	int cache_fd, disk_fd, c;
	char *disk_devname, *ssd_devname, *cachedev;
	struct flash_superblock *sb = (struct flash_superblock *)buf;
	sector_t cache_devsize, disk_devsize;
	sector_t block_size = 0, md_block_size = 0, cache_size = 0;
	sector_t ram_needed;
	struct sysinfo i;
	int cache_sectorsize;
	int associativity = 512;
	int disk_associativity = 0;
	int ret;
	int cache_mode = -1;
	char *cache_mode_str;
	
	pname = argv[0];
	while ((c = getopt(argc, argv, "fs:b:d:m:va:p:w")) != -1) {
		switch (c) {
		case 's':
			cache_size = get_cache_size(optarg);
			break;
		case 'a':
			associativity = atoi(optarg);
			break;
		case 'b':
			block_size = get_block_size(optarg);
			/* Block size should be a power of 2 */
                        break;
		case 'd':
			disk_associativity = get_block_size(optarg);
			break;
		case 'm':
			md_block_size = get_block_size(optarg);
			/* MD block size should be a power of 2 */
                        break;
		case 'v':
			verbose = 1;
                        break;			
		case 'f':
			force = 1;
                        break;
		case 'p':
			if (strcmp(optarg, "back") == 0) {
				cache_mode = FLASHCACHE_WRITE_BACK;
				cache_mode_str = "WRITE_BACK";
			} else if ((strcmp(optarg, "thru") == 0) ||
				   (strcmp(optarg, "through") == 0)) {
				cache_mode = FLASHCACHE_WRITE_THROUGH;
				cache_mode_str = "WRITE_THROUGH";
			} else if (strcmp(optarg, "around") == 0) {
				cache_mode = FLASHCACHE_WRITE_AROUND;
				cache_mode_str = "WRITE_AROUND";
			} else
				usage(pname);
                        break;
		case 'w':
			write_cache_only = 1;
                        break;			
		case '?':
			usage(pname);
		}
	}
	if (cache_mode == -1)
		usage(pname);
	if (optind == argc)
		usage(pname);
	if (block_size == 0)
		block_size = 8;		/* 4KB default blocksize */
	if (md_block_size == 0)
		md_block_size = 8;	/* 4KB default blocksize */
	cachedev = argv[optind++];
	if (optind == argc)
		usage(pname);
	ssd_devname = argv[optind++];
	if (optind == argc)
		usage(pname);
	disk_devname = argv[optind];
	printf("cachedev %s, ssd_devname %s, disk_devname %s cache mode %s\n", 
	       cachedev, ssd_devname, disk_devname, cache_mode_str);
	if (cache_mode == FLASHCACHE_WRITE_BACK)
		printf("block_size %lu, md_block_size %lu, cache_size %lu\n", 
		       block_size, md_block_size, cache_size);
	else
		printf("block_size %lu, cache_size %lu\n", 
		       block_size, cache_size);
	cache_fd = open(ssd_devname, O_RDONLY);
	if (cache_fd < 0) {
		fprintf(stderr, "Failed to open %s\n", ssd_devname);
		exit(1);
	}
        lseek(cache_fd, 0, SEEK_SET);
	if (read(cache_fd, buf, 512) < 0) {
		fprintf(stderr, "Cannot read Flashcache superblock %s\n", 
			ssd_devname);
		exit(1);		
	}
	if (sb->cache_sb_state == CACHE_MD_STATE_DIRTY ||
	    sb->cache_sb_state == CACHE_MD_STATE_CLEAN ||
	    sb->cache_sb_state == CACHE_MD_STATE_FASTCLEAN ||
	    sb->cache_sb_state == CACHE_MD_STATE_UNSTABLE) {
		fprintf(stderr, "%s: Valid Flashcache already exists on %s\n", 
			pname, ssd_devname);
		fprintf(stderr, "%s: Use flashcache_destroy first and then create again %s\n", 
			pname, ssd_devname);
		exit(1);
	}
	disk_fd = open(disk_devname, O_RDONLY);
	if (disk_fd < 0) {
		fprintf(stderr, "%s: Failed to open %s\n", 
			pname, disk_devname);
		exit(1);
	}
	if (ioctl(cache_fd, BLKGETSIZE, &cache_devsize) < 0) {
		fprintf(stderr, "%s: Cannot get cache size %s\n", 
			pname, ssd_devname);
		exit(1);		
	}
	if (ioctl(disk_fd, BLKGETSIZE, &disk_devsize) < 0) {
		fprintf(stderr, "%s: Cannot get disk size %s\n", 
			pname, disk_devname);
		exit(1);				
	}
	if (ioctl(cache_fd, BLKSSZGET, &cache_sectorsize) < 0) {
		fprintf(stderr, "%s: Cannot get cache size %s\n", 
			pname, ssd_devname);
		exit(1);		
	}
	if (md_block_size > 0 &&
	    md_block_size * 512 < cache_sectorsize) {
		fprintf(stderr, "%s: SSD device (%s) sector size (%d) cannot be larger than metadata block size (%d) !\n",
		        pname, ssd_devname, cache_sectorsize, md_block_size * 512);
		exit(1);				
	}
	if (cache_size && cache_size > cache_devsize) {
		fprintf(stderr, "%s: Cache size is larger than ssd size %lu/%lu\n", 
			pname, cache_size, cache_devsize);
		exit(1);		
	}

	/* Remind users how much core memory it will take - not always insignificant.
 	 * If it's > 25% of RAM, warn.
         */
	if (cache_size == 0)
		ram_needed = (cache_devsize / block_size) * sizeof(struct cacheblock);	/* Whole device */
	else 
		ram_needed = (cache_size    / block_size) * sizeof(struct cacheblock);

	sysinfo(&i);
	printf("Flashcache metadata will use %luMB of your %luMB main memory\n",
		ram_needed >> 20, i.totalram >> 20);
	if (!force && ram_needed > (i.totalram * 25 / 100)) {
		fprintf(stderr, "Proportion of main memory needed for flashcache metadata is high.\n");
		fprintf(stderr, "You can reduce this with a smaller cache or a larger blocksize.\n");
		check_sure();
	}
	if (disk_associativity > associativity) {
		fprintf(stderr, "%s: Invalid Disk Associativity %ld\n",
			pname, disk_associativity);
		exit(1);
	}
	if (!force && cache_size > disk_devsize) {
		fprintf(stderr, "Size of cache volume (%s) is larger than disk volume (%s)\n",
			ssd_devname, disk_devname);
		check_sure();
	}
	sprintf(dmsetup_cmd, "echo 0 %lu flashcache %s %s %s %d 2 %lu %lu %d %lu %d %lu"
		" | dmsetup create %s",
		disk_devsize, disk_devname, ssd_devname, cachedev, cache_mode, block_size, 
		cache_size, associativity, disk_associativity, write_cache_only, md_block_size,
		cachedev);

	/* Go ahead and create the cache.
	 * XXX - Should use the device mapper library for this.
	 */
	load_module();
	if (verbose)
		fprintf(stderr, "Creating FlashCache Volume : \"%s\"\n", dmsetup_cmd);
	ret = system(dmsetup_cmd);
	if (ret) {
		fprintf(stderr, "%s failed\n", dmsetup_cmd);
		exit(1);
	}
	return 0;
}
