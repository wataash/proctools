/*
 * pgrep [-flnvx] [-d <delim>] [-g <pgrplist>] [-G <gidlist>]
 *       [-P <ppidlist>] [-t <termlist>] [-u <euidlist>]
 *       [-U <uidlist>] [<pattern>]
 *
 *  -d <delim> : output delimiter (default newline)
 *  -f : match against full name, not just executable name
 *  -g <pgrplist> : matches process groups
 *  -G <gidlist> : matches group IDs
 *  -l : long output (default is just pids)
 *  -n : matches only newest process that matches otherwise
 *  -P <ppidlist> : matches parent pids
 *  -t <termlist> : matches terminal
 *  -u <euidlist> : matches effective uids
 *  -U <uidlist> : matches real uids
 *  -v : invert match
 *  -x : exact match (default regex)
 *
 *  <pattern> : regex (or exact string if -x) to match
 */

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "proctools.h"

static void usage();

/*
 * pgrep matches processes specified by its arguments and prints them out
 */
int
main(argc, argv)
	int argc;
	char *argv[];
{
	struct proclist *proclist, *temppl;
	struct grouplist *gidl;
	struct pidlist *pgroupl, *ppidl, *sidl;
	struct termlist *terml;
	struct uidlist *euidl, *uidl;
	int ch;
	int fflag, lflag, nflag, vflag, xflag;
	int first;
	char *delim;

	proclist = NULL;
	gidl = NULL;
	pgroupl = ppidl = sidl = NULL;
	terml = NULL;
	euidl = uidl = NULL;
	fflag = lflag = xflag = nflag = vflag = FALSE;
	first = TRUE;
	delim = NULL;

	while ((ch = getopt(argc, argv, "d:fg:G:lnP:s:t:u:U:vx")) != -1)
		switch ((char)ch) {
		case 'd':
			if (delim != NULL)
				free(delim);
			if ((delim = strdup(optarg)) == NULL)
				err(EX_OSERR, NULL);
			break;
		case 'f':
			fflag = TRUE;
			break;
		case 'g':
			(void)parsePidList(optarg, &pgroupl);
			break;
		case 'G':
			(void)parseGroupList(optarg, &gidl);
			break;
		case 'l':
			lflag = TRUE;
			break;
		case 'n':
			nflag = TRUE;
			break;
		case 'P':
			(void)parsePidList(optarg, &ppidl);
			break;
/*
		case 's':
			(void)parsePidList(optarg, &sidl);
			break;
*/
		case 't':
			(void)parseTermList(optarg, &terml);
			break;
		case 'u':
			(void)parseUidList(optarg, &euidl);
			break;
		case 'U':
			(void)parseUidList(optarg, &uidl);
			break;
		case 'v':
			vflag = TRUE;
			break;
		case 'x':
			xflag = TRUE;
			break;
		case '?':
		default:
			usage();
			/* NOTREACHED */
		}
	argc -= optind;
	argv += optind;

	if (argc > 1) {
		warn("too many arguments");
		usage();
	}

	getProcList(&proclist, euidl, uidl, gidl, ppidl, pgroupl, terml, fflag, nflag, vflag, xflag, ((argc > 0)?argv[0]:NULL));

	temppl = proclist;
	while (temppl != NULL) {
		printf("%s%d%s%s", (first?(first = FALSE, ""):(delim != NULL?delim:"\n")), temppl->pid, (lflag?" ":""), (lflag?temppl->name:""));
		temppl = temppl->next;
	}

	if (!first)
		printf("\n");

	return (1);
}

void
usage()
{
	extern char *__progname;

	(void)fprintf(stderr, "Usage: %s [-flnvx] [-d <delim>] [-g <pgrplist>] [-G <gidlist>] [-P <ppidlist>] [-t <termlist>] [-u <euidlist>] [-U <uidlist>] [<pattern>]\n", __progname);
	exit(EX_USAGE);
}

/*
 * Copyright (c) 2001
 *      William B Faulk.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution. 
 * 3. Neither the name of William B Faulk nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
