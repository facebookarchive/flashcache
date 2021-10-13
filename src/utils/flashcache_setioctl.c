/*
 * Copyright (c) 2012, Dmitry Golubev
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
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/types.h>
#include <flashcache_ioctl.h>

void usage(char *pname)
{
	fprintf(stderr, "Usage: %s (-c | -a | -r) (-b pid |-w pid) ssd_devname \n", pname);
	exit(1);
}

void dm_message(char *cachedev, char list, char action, pid_t pid)
{
	char pidstr[32];

	char *argv[] = {
		"/sbin/dmsetup",
		"message",
		cachedev,
		"0",
		/* command */ NULL,
		/* sub-command */ NULL,
		/* pid */ NULL,
		NULL,
	};

	switch (list) {
	case 'w':
		argv[4] = "whitelist";
		break;
	case 'b':
		argv[4] = "blacklist";
		break;
	default:
		return;
	}

	switch (action) {
	case 'a':
		argv[5] = "add";
		break;
	case 'r':
		argv[5] = "del";
		break;
	case 'c':
		argv[5] = "delall";
		break;
	}

	switch (action) {
	case 'a':
	case 'r':
		snprintf(pidstr, sizeof(pidstr), "%lld", (long long)pid);
		argv[6] = pidstr;
		break;
	}

	execv(argv[0], argv);
}

int
main(int argc, char **argv)
{
	int cache_fd, c, result;
	char action = ' ', list = ' ', *cachedev, *pname = argv[0];
	intmax_t pidmax;
	char *tmp;
	pid_t pid;
	int err;

	while ((c = getopt(argc, argv, "carb:w:")) != -1) {
		switch (c) {
			case 'c':
				action = 'c';
				break;
			case 'a':
				action = 'a';
				break;
			case 'r':
				action = 'r';
				break;
			case 'b':
				list = 'b';
				pidmax = strtoimax(optarg, &tmp, 10);
				if(tmp == optarg || *tmp != '\0' || pidmax != (pid_t)pidmax) {
					fprintf(stderr, "Bad PID!\n");
					exit(1);
				}
				else {
					pid = (pid_t)pidmax;
				}
				break;
			case 'w':
				list = 'w';
				pidmax = strtoimax(optarg, &tmp, 10);
				if (tmp == optarg || *tmp != '\0' || pidmax != (pid_t)pidmax) {
					fprintf(stderr, "Bad PID!\n");
					exit(1);
				} else {
					pid = (pid_t)pidmax;
				}
				break;
			case '?':
				usage(pname);
		}
	}
	if (action == ' ')
		usage(pname);
	if (list == ' ')
		usage(pname);
	if (optind == argc) 
		usage(pname);
	cachedev = argv[optind++];
	cache_fd = open(cachedev, O_RDONLY);
	if (cache_fd < 0) {
		fprintf(stderr, "Failed to open %s\n", cachedev);
		exit(1);
	}
	if (list == 'w') {
		switch (action) {
			case 'a':
				result=ioctl(cache_fd, FLASHCACHEADDWHITELIST, &pid);
				break;
			case 'r':
				result=ioctl(cache_fd, FLASHCACHEDELWHITELIST, &pid);
				break;
			case 'c':
				result=ioctl(cache_fd, FLASHCACHEDELALLWHITELIST, &pid);
				break;
		}
	}
	else {
		switch (action) {
			case 'a':
				result=ioctl(cache_fd, FLASHCACHEADDBLACKLIST, &pid);
				break;
			case 'r':
				result=ioctl(cache_fd, FLASHCACHEDELBLACKLIST, &pid);
				break;
			case 'c':
				result=ioctl(cache_fd, FLASHCACHEDELALLBLACKLIST, &pid);
				break;
		}
	}
	err = errno;
	close(cache_fd);
	/*
	 * Failed with an error indicating the ioctl was not appropriate for the device
	 * switch to using DM messages.
	 */
	if (result < 0 && err == ENOTTY) {
		dm_message(cachedev, list, action, pid);
	}
	if (result < 0) {
		fprintf(stderr, "ioctl failed on %s\n", cachedev);
		exit(1);
	}
	return 0;
}
