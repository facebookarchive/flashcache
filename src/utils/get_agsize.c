/*
 * Copyright (c) 2012, Facebook, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#define _GNU_SOURCE
#include <getopt.h>

void
usage(char *pname)
{
	fprintf(stderr, "%s: [-v] cache_size(in GB) vol_size(in GB)\n", pname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	size_t csize, vsize, agsize, t1, t2, diff, best_agcount = 1;
	int agcount;
	int c, verbose = 0;
	char *pname;

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
	if (optind == argc)
		usage(pname);
	csize = strtoul(argv[optind++], NULL, 0);
	if (optind == argc)
		usage(pname);
	if (!csize || csize == ULONG_MAX)
		usage(pname);
	vsize = strtoul(argv[optind], NULL, 0);
	if ( !vsize || vsize < csize ||vsize == ULONG_MAX)
		usage(pname);
	csize *= 1024;
	vsize *= 1024; /* convert to MiB */
	diff = ULONG_MAX;
	for (agcount = 1; agcount < 30; agcount++) {
		t2 = csize / agcount;
		agsize = vsize / agcount;
		/* Max agsize is 1TB, find another agcount */
		if (agsize >= 1024 * 1024)
			continue;
		/* agsize < 16GB, terminate search */
		if (agsize < 16 * 1024)
			break;
		if (agsize < csize)
			t2 = (((double)(agcount - 1)) / agcount) * csize;
		t1 = agsize % csize;
		if (abs(t1 - t2) < diff) {
			diff = abs(t1 - t2);
			best_agcount = agcount;
		}
		if (verbose)
			printf("agsize = %ld agcount = %d, t1=%d t2=%d\n", 
			       agsize/1024, agcount, t1/1024, t2/1024);
	}
	printf("best agsize = %ld agcount=%d\n", 
	       vsize / (best_agcount * 1024), best_agcount);
	return 0;
}
