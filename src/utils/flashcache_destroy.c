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

int force = 0;

void
usage(char *pname)
{
	fprintf(stderr, "Usage: %s ssd_devname\n", pname);
#ifdef COMMIT_REV
	fprintf(stderr, "git commit: %s\n", COMMIT_REV);
#endif
	exit(1);
}

char *pname;
char *sb_buf;
char *buf;

int
main(int argc, char **argv)
{
	int cache_fd, c;
	char *ssd_devname;
	struct flash_superblock *sb;
	u_int64_t md_block_bytes = 0;
	u_int64_t md_slots_per_block = 0;
	u_int64_t cache_size = 0;
	int dirty_blocks = 0;
	
	pname = argv[0];
	while ((c = getopt(argc, argv, "f")) != -1) {
		switch (c) {
		case 'f':
			force = 1;
                        break;
		case '?':
			usage(pname);
		}
	}
	if (optind == argc) 
		usage(pname);
	ssd_devname = argv[optind++];
	cache_fd = open(ssd_devname, O_RDWR);
	if (cache_fd < 0) {
		fprintf(stderr, "Failed to open %s\n", ssd_devname);
		exit(1);
	}
        lseek(cache_fd, 0, SEEK_SET);
	sb_buf = (char *)malloc(512);
	if (!sb_buf) {
		fprintf(stderr, "Failed to allocate sector buffer\n");
		exit(1);
	}
	if (read(cache_fd, sb_buf, 512) < 0) {
		fprintf(stderr, "Cannot read Flashcache superblock %s\n", ssd_devname);
		exit(1);		
	}
	sb = (struct flash_superblock *)sb_buf;
	if (!(sb->cache_sb_state == CACHE_MD_STATE_DIRTY ||
	      sb->cache_sb_state == CACHE_MD_STATE_CLEAN ||
	      sb->cache_sb_state == CACHE_MD_STATE_FASTCLEAN ||
	      sb->cache_sb_state == CACHE_MD_STATE_UNSTABLE)) {
		fprintf(stderr, "%s: No valid Flashcache found on %s\n", 
			pname, ssd_devname);
		exit(1);
	}

	/* Backwards compat, versions < 2 use a 1 sector metadata blocksize */
	if (sb->cache_version == 1)
		sb->md_block_size = 1;

	cache_size = sb->size;

	md_block_bytes = sb->md_block_size * 512;
        lseek(cache_fd, md_block_bytes, SEEK_SET); /* lseek past the superblock to first MD slot */
	md_slots_per_block = (md_block_bytes / (sizeof(struct flash_cacheblock)));

	buf = (char *)malloc(md_block_bytes);
	if (!buf) {
		fprintf(stderr, "Failed to allocate sector buffer\n");
		exit(1);
	}
	while (cache_size > 0 && dirty_blocks == 0) {
		struct flash_cacheblock *next_ptr;
		int j, slots_read;
		
		if (cache_size < md_slots_per_block)
			slots_read = cache_size;
		else
			slots_read = md_slots_per_block;			
		if (read(cache_fd, buf, md_block_bytes) < 0) {
			fprintf(stderr, "Cannot read Flashcache metadata %s\n", ssd_devname);
			exit(1);		
		}
		next_ptr = (struct flash_cacheblock *)buf;
		for (j = 0 ; j < slots_read ; j++) {
			if (next_ptr->cache_state & DIRTY) {
				dirty_blocks++;
				break;
			}				
			next_ptr++;
		}
		cache_size -= slots_read;
	}
	if (dirty_blocks && !force) {
		fprintf(stderr, "%s: DIRTY BLOCKS EXIST ON %s, ABORTING CACHE DESTROY\n", 
			pname, ssd_devname);
		fprintf(stderr, "%s: Use -f (force) to destroy cache with DIRTY blocks, BUT YOU WILL LOSE DATA GUARANTEED\n", 
			pname);
		fprintf(stderr, "%s: To clean the DIRTY blocks, flashcache_load, then do_sync until all dirty blocks are cleaned\n", 
			pname);
		exit(1);
	}
	fprintf(stderr, "%s: Destroying Flashcache found on %s. Any data will be lost !!\n", 
		pname, ssd_devname);
	sb->cache_sb_state = 0;
        lseek(cache_fd, 0, SEEK_SET);
	if (write(cache_fd, sb_buf, 512) < 0) {
		fprintf(stderr, "Cannot write Flashcache superblock %s\n", ssd_devname);
		exit(1);		
	}
	return 0;
}
