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

typedef u_int64_t sector_t;

void
usage(char *pname)
{
	fprintf(stderr, "Usage: %s [-b block size] [ -s cache size] cachedev ssd_devname disk_devname\n", pname);
	fprintf(stderr, "Usage : %s Default units for -b, -s are sectors, use k/m/g allowed\n",
		pname);
	exit(1);
}

char *pname;
char buf[512];
char dmsetup_cmd[8192];
int verbose = 0;
int force = 0;

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
	if (size & ~size) {
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
			size = (size * 1024 * 1024) / 512;
			break;
		case 'g': 
			size = (size * 1024 * 1024 * 1024) / 512;
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
	while (fgets(line, 8192, fp)) {
		char *s;
		
		s = strtok(line, " ");
		if (!strcmp(s, "flashcache_wt")) {
			found = 1;
			break;
		}
	}
	return found;
}

static void
load_module(void)
{
	FILE *fp;
	char line[8192];
	int found = 0;

	if (module_loaded()) {
		if (verbose)
			fprintf(stderr, "Flashcache Module already loaded\n");		
		return;
	}
	if (verbose)
		fprintf(stderr, "Loading Flashcache Module\n");
	system("modprobe flashcache_wt");
	if (!module_loaded()) {
		fprintf(stderr, "Could not load Flashcache Module\n");
		exit(1);
	}
}

main(int argc, char **argv)
{
	int disk_fd, c;
	char *disk_devname, *ssd_devname, *cachedev;
	sector_t block_size = 0, cache_size = 0;
	sector_t disk_devsize;
	int write_around = 0;
	
	pname = argv[0];
	while ((c = getopt(argc, argv, "fs:b:vr")) != -1) {
		switch (c) {
		case 's':
			cache_size = get_cache_size(optarg);
			break;
		case 'b':
			block_size = get_block_size(optarg);
			/* Block size should be a power of 2 */
                        break;
		case 'v':
			verbose = 1;
                        break;			
		case 'f':
			force = 1;
                        break;
		case 'r':
			write_around = 1;
                        break;
		case '?':
			usage(pname);
		}
	}
	if (optind == argc)
		usage(pname);
	if (block_size == 0)
		block_size = 8;		/* 4KB default blocksize */
	cachedev = argv[optind++];
	if (optind == argc)
		usage(pname);
	ssd_devname = argv[optind++];
	if (optind == argc)
		usage(pname);
	disk_devname = argv[optind];
	disk_fd = open(disk_devname, O_RDONLY);
	if (disk_fd < 0) {
		fprintf(stderr, "%s: Failed to open %s\n", 
			pname, disk_devname);
		exit(1);
	}
	if (ioctl(disk_fd, BLKGETSIZE, &disk_devsize) < 0) {
		fprintf(stderr, "%s: Cannot get disk size %s\n", 
			pname, disk_devname);
		exit(1);				
	}
	printf("cachedev %s, ssd_devname %s, disk_devname %s\n", 
	       cachedev, ssd_devname, disk_devname);
	printf("cache mode %s, block_size %lu, cache_size %lu\n", 
	       ((write_around) ? "WRITE_AROUND" : "WRITE_THRU"), block_size, cache_size);
	sprintf(dmsetup_cmd, "echo 0 %lu flashcache-wt %s %s %d %lu ",
		disk_devsize, disk_devname, ssd_devname, write_around, block_size);
	if (cache_size > 0) {
		char cache_size_str[4096];
		
		sprintf(cache_size_str, "%lu ", cache_size);
		strcat(dmsetup_cmd, cache_size_str);
	}
	/* Go ahead and create the cache.
	 * XXX - Should use the device mapper library for this.
	 */
	strcat(dmsetup_cmd, "| dmsetup create ");
	strcat(dmsetup_cmd, cachedev);
	strcat(dmsetup_cmd, "\n");
	load_module();
	if (verbose)
		fprintf(stderr, "Creating FlashCache_wt Volume : %s", dmsetup_cmd);
	system(dmsetup_cmd);
}
