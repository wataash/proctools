/*
 * pgrep [-flnvx] [-d <delim>] [-g <pgrplist>] [-G <gidlist>]
 *       [-P <ppidlist>] [-s <sidlist>] [-t <termlist>] [-u <euidlist>]
 *       [-U <uidlist>] [<pattern>]
 *
 *  -d <delim> : output delimiter (default newline)
 *  -f : match against full name, not just executable name
 *  -g <pgrplist> : matches process groups
 *  -G <gidlist> : matches group IDs
 *  -l : long output (default is just pids)
 *  -n : matches only newest process that matches otherwise
 *  -P <ppidlist> : matches parent pids
 *  -s <sidlist> : matches session id
 *  -t <termlist> : matches terminal
 *  -u <euidlist> : matches effective uids
 *  -U <uidlist> : matches real uids
 *  -v : invert match
 *  -x : exact match (default regex)
 *
 *  <pattern> : regex (or exact string if -x) to match
 */

/*
 * To compile and pseudo-install:
 *
 *  gcc -Wall -o pgrep pgrep.c -lkvm
 *  chgrp kmem pgrep
 *  chmod 2555 pgrep
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/tty.h>
#include <sys/user.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <kvm.h>
#include <err.h>

struct uidlist {
	uid_t uid;
	struct uidlist *next;
};

struct pidlist {
	pid_t pid;
	struct pidlist *next;
};

struct grouplist {
	gid_t group;
	struct grouplist *next;
};

struct termlist {
	dev_t term;
	struct termlist *next;
};

int
parsePidList(pidstring, pidlist)
	char *pidstring;
	struct pidlist **pidlist;
{
	int invalid = 0;
	char *stringp;
	struct pidlist *head = NULL;

	*pidlist = NULL;

	while ((stringp = strsep(&pidstring, ", \t")) != NULL) {
		if (*stringp != '\0') {
			struct pidlist *pl;
			pid_t pid;
			char *endptr;
			int bad = 0;

			pid = (pid_t)strtol(stringp, &endptr, 10);
			if (*endptr != '\0') {
				warn("Unable to parse pid %s", stringp);
				bad++;
			}
			if (bad == 0) {
				pl = calloc(1, sizeof(struct pidlist));
				pl->pid = pid;
				pl->next = NULL;
				if (*pidlist == NULL) {
					*pidlist = pl;
					head = *pidlist;
				} else {
					(*pidlist)->next = pl;
					*pidlist = (*pidlist)->next;
				}
			} else
				invalid++;
		}
	}

	*pidlist = head;
	return(invalid);
}

int
parseUidList(uidstring, uidlist)
	char *uidstring;
	struct uidlist **uidlist;
{
	int invalid = 0;
	char *stringp;
	struct uidlist *head = NULL;

	*uidlist = NULL;

	while ((stringp = strsep(&uidstring, ", \t")) != NULL) {
		if (*stringp != '\0') {
			struct uidlist *ul;
			struct passwd *tempu;
			uid_t uid;
			char *endptr;
			int bad = 0;

			tempu = getpwnam(stringp);
			if (tempu == NULL) {
				uid = (uid_t)strtol(stringp, &endptr, 10);
				if (*endptr != '\0') {
					warn("Unable to parse uid %s", stringp);
					bad++;
				}
			} else
				uid = tempu->pw_uid;
			if (bad == 0) {
				ul = calloc(1, sizeof(struct uidlist));
				ul->uid = uid;
				ul->next = NULL;
				if (*uidlist == NULL) {
					*uidlist = ul;
					head = *uidlist;
				} else {
					(*uidlist)->next = ul;
					*uidlist = (*uidlist)->next;
				}
			} else
				invalid++;
		}
	}

	*uidlist = head;
	return(invalid);
}

int
parseGroupList(groupstring, grouplist)
	char *groupstring;
	struct grouplist **grouplist;
{
	int invalid = 0;
	char *stringp;
	struct grouplist *head = NULL;

	*grouplist = NULL;

	while ((stringp = strsep(&groupstring, ", \t")) != NULL) {
		if (*stringp != '\0') {
			struct grouplist *gl;
			struct group *tempg;
			gid_t group;
			char *endptr;
			int bad = 0;

			tempg = getgrnam(stringp);
			if (tempg == NULL) {
				group = (gid_t)strtol(stringp, &endptr, 10);
				if (*endptr != '\0') {
					warn("Unable to parse group %s", stringp);
					bad++;
				}
			} else
				group = tempg->gr_gid;
			if (bad == 0) {
				gl = calloc(1, sizeof(struct grouplist));
				gl->group = group;
				gl->next = NULL;
				if (*grouplist == NULL) {
					*grouplist = gl;
					head = *grouplist;
				} else {
					(*grouplist)->next = gl;
					*grouplist = (*grouplist)->next;
				}
			} else
				invalid++;
		}
	}

	*grouplist = head;
	return(invalid);
}

int
parseTermList(termstring, termlist)
	char *termstring;
	struct termlist **termlist;
{
	int invalid = 0;
	char *stringp;
	struct termlist *head = NULL;

	*termlist = NULL;

	while ((stringp = strsep(&termstring, ", \t")) != NULL) {
		if (*stringp != '\0') {
			struct termlist *tl;
			dev_t term;
			int bad = 0;
			struct stat statbuf;

			if (*stringp != '/') {
				size_t len;
				char *temps;

				len = strlen(stringp);
				len += 6; /* 5 for "/dev/" and 1 for '\0' */
				temps = calloc(len, sizeof(char));
				snprintf(temps, len, "/dev/%s", stringp);
				stringp = temps;
			}
			if (stat(stringp, &statbuf) == 0)
				if (statbuf.st_mode | S_IFCHR)
					term = statbuf.st_rdev;
				else {
					bad++;
					warn("%s not a character device", stringp);
				}
			else {
				bad++;
				warn("can't stat %s", stringp);
			}
			if (bad == 0) {
				tl = calloc(1, sizeof(struct termlist));
				tl->term = term;
				tl->next = NULL;
				if (*termlist == NULL) {
					*termlist = tl;
					head = *termlist;
				} else {
					(*termlist)->next = tl;
					*termlist = (*termlist)->next;
				}
			} else
				invalid++;
		}
	}

	*termlist = head;
	return(invalid);
}

int
matchUidList(uidlist, uid)
	struct uidlist *uidlist;
	uid_t uid;
{
	struct uidlist *tempul;

	if (uidlist == NULL)
		return(TRUE);

	for (tempul = uidlist; tempul != NULL; tempul = tempul->next)
		if (tempul->uid == uid)
			return(TRUE);
	return(FALSE);
}

int
matchGroupList(grouplist, gid)
	struct grouplist *grouplist;
	gid_t gid;
{
	struct grouplist *tempgl;

	if (grouplist == NULL)
		return(TRUE);

	for (tempgl = grouplist; tempgl != NULL; tempgl = tempgl->next)
		if (tempgl->group == gid)
			return(TRUE);
	return(FALSE);
}

int
matchPidList(pidlist, pid)
	struct pidlist *pidlist;
	pid_t pid;
{
	struct pidlist *temppl;

	if (pidlist == NULL)
		return(TRUE);

	for (temppl = pidlist; temppl != NULL; temppl = temppl->next)
		if (temppl->pid == pid)
			return(TRUE);
	return(FALSE);
}

int
matchTermList(termlist, term)
	struct termlist *termlist;
	dev_t term;
{
	struct termlist *temptl;

	if (termlist == NULL)
		return(TRUE);

	for (temptl = termlist; temptl != NULL; temptl = temptl->next)
		if (temptl->term == term)
			return(TRUE);
	return(FALSE);
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
	struct kinfo_proc *kp, kpi;
	int nentries, i;
	char errbuf[_POSIX2_LINE_MAX];
	kvm_t *kd;
	int fflag, lflag, nflag, vflag, xflag;
	char *delim = "\n";
	int ch;
	struct grouplist *gidl;
	struct pidlist *pgroupl, *ppidl, *sidl;
	struct uidlist *euidl, *uidl;
	struct termlist *terml;
	regex_t regex;
	int first = TRUE;
	char *name;
	char **kvm_argv;
	int match, extmatch;
	struct pstats pstats;
	struct {
		struct timeval time;
		char *name;
		pid_t pid;
		int valid;
	} latest;

	fflag = lflag = xflag = 0;
	nflag = vflag = FALSE;
	gidl = NULL;
	pgroupl = ppidl = sidl = NULL;
	euidl = uidl = NULL;
	terml = NULL;

	while ((ch = getopt(argc, argv,
	    "d:fg:G:lnP:s:t:u:U:vxi")) != -1)
		switch ((char)ch) {
		case 'd':
			delim = strdup(optarg);
			break;
		case 'f':
			fflag++;
			break;
		case 'g':
			(void)parsePidList(optarg, &pgroupl);
			break;
		case 'G':
			(void)parseGroupList(optarg, &gidl);
			break;
		case 'l':
			lflag++;
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
			xflag++;
			break;
		}
	argc -= optind;
	argv += optind;

	if (argc > 1)
		err(1, "too many arguments");

	kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);
	if (kd == 0)
		errx(1, "%s", errbuf);

	setegid(getgid());
	setgid(getgid());

	if ((kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nentries)) == 0)
		errx(1, "%s", kvm_geterr(kd));

	if (!xflag && (argc > 0))
		if (regcomp(&regex, argv[0], REG_EXTENDED) != 0)
			err(1, "Unable to compile regular expression");

	if (nflag)
		latest.valid = FALSE;

	for (i = nentries; --i >= 0; ++kp) {
		kpi = *kp;
		match = (matchPidList(pgroupl, kpi.kp_eproc.e_pgid) &&
		    matchGroupList(gidl, kpi.kp_eproc.e_ucred.cr_gid) &&
		    matchPidList(ppidl, kpi.kp_eproc.e_ppid) &&
/*
		    matchPidList(sidl, kpi.kp_eproc.e_sess->s_leader->p_pid) &&
*/
		    matchTermList(terml, kpi.kp_eproc.e_tdev) &&
		    matchUidList(euidl, kpi.kp_eproc.e_pcred.p_svuid) &&
		    matchUidList(uidl, kpi.kp_eproc.e_pcred.p_ruid));
		extmatch = pgroupl || gidl || ppidl || terml || euidl || uidl;
		if (match && !vflag) {
			if (fflag) {
				kvm_argv = kvm_getargv(kd, kp, 0);
				name = strdup(kvm_argv[0]);
			} else
				name = strdup(kpi.kp_proc.p_comm);
			if (nflag) {
				if (kvm_read(kd, (u_long)&kpi.kp_proc.p_addr->u_stats,
				    &pstats, sizeof(pstats)) != sizeof(pstats))
					err(1, "Unable to get process start time");
				if (!latest.valid) {
					latest.valid = TRUE;
					latest.time.tv_sec = pstats.p_start.tv_sec;
					latest.time.tv_usec = pstats.p_start.tv_usec;
					latest.name = strdup(kpi.kp_proc.p_comm);
					latest.pid = kpi.kp_proc.p_pid;
				} else if ((pstats.p_start.tv_sec > latest.time.tv_sec) &&
				    (pstats.p_start.tv_usec > latest.time.tv_usec)) {
					latest.time.tv_sec = pstats.p_start.tv_sec;
					latest.time.tv_usec = pstats.p_start.tv_usec;
					free(latest.name);
					latest.name = strdup(kpi.kp_proc.p_comm);
					latest.pid = kpi.kp_proc.p_pid;
				}
			} else if (argc > 0) {
				if (xflag) {
					if (!strcmp(name, argv[0]))
						printf("%s%d%s%s",
						    (first?(first = FALSE, ""):delim),
						    (int)kpi.kp_proc.p_pid,
						    (lflag?" ":""),
						    (lflag?kpi.kp_proc.p_comm:""));
				} else
					if (regexec(&regex, name, 0, NULL, NULL) == 0)
						printf("%s%d%s%s",
						    (first?(first = FALSE, ""):delim),
						    (int)kpi.kp_proc.p_pid,
						    (lflag?" ":""),
						    (lflag?kpi.kp_proc.p_comm:""));
			} else
				printf("%s%d%s%s",
				    (first?(first = FALSE, ""):delim),
				    (int)kpi.kp_proc.p_pid,
				    (lflag?" ":""),
				    (lflag?kpi.kp_proc.p_comm:""));
		} else if ((!match && vflag) || (match && !extmatch && vflag)) {
			if (fflag) {
				kvm_argv = kvm_getargv(kd, kp, 0);
				name = strdup(kvm_argv[0]);
			} else
				name = strdup(kpi.kp_proc.p_comm);
			if (nflag) {
				if (kvm_read(kd, (u_long)&kpi.kp_proc.p_addr->u_stats,
				    &pstats, sizeof(pstats)) != sizeof(pstats))
					errx(1, "Unable to get process start time");
				if (!latest.valid) {
					latest.valid = TRUE;
					latest.time.tv_sec = pstats.p_start.tv_sec;
					latest.time.tv_usec = pstats.p_start.tv_usec;
					latest.name = strdup(kpi.kp_proc.p_comm);
					latest.pid = kpi.kp_proc.p_pid;
				} else if ((pstats.p_start.tv_sec > latest.time.tv_sec) &&
				    (pstats.p_start.tv_usec > latest.time.tv_usec)) {
					latest.time.tv_sec = pstats.p_start.tv_sec;
					latest.time.tv_usec = pstats.p_start.tv_usec;
					free(latest.name);
					latest.name = strdup(kpi.kp_proc.p_comm);
					latest.pid = kpi.kp_proc.p_pid;
				}
			} else if (argc > 0) {
				if (xflag) {
					if (strcmp(name, argv[0]))
						printf("%s%d%s%s",
						    (first?(first = FALSE, ""):delim),
						    (int)kpi.kp_proc.p_pid,
						    (lflag?" ":""),
						    (lflag?kpi.kp_proc.p_comm:""));
				} else
					if (regexec(&regex, name, 0, NULL, NULL) == REG_NOMATCH)
						printf("%s%d%s%s",
						    (first?(first = FALSE, ""):delim),
						    (int)kpi.kp_proc.p_pid,
						    (lflag?" ":""),
						    (lflag?kpi.kp_proc.p_comm:""));
			} else
				printf("%s%d%s%s",
				    (first?(first = FALSE, ""):delim),
				    (int)kpi.kp_proc.p_pid,
				    (lflag?" ":""),
				    (lflag?kpi.kp_proc.p_comm:""));
		}
	}
	kpi = *kp;

	if (nflag)
		printf("%d%s%s\n",
		    (int)latest.pid,
		    (lflag?" ":""),
		    (lflag?latest.name:""));
	else if (!first)
		printf("\n");

	return(1);
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
 *
 *
 * Portions of this code taken from:
 *   $OpenBSD: ps.c,v 1.19 2001/04/17 21:12:07 millert Exp $
 *   $NetBSD: ps.c,v 1.15 1995/05/18 20:33:25 mycroft Exp $
 * which has the following license:
 *
 * Copyright (c) 1990, 1993, 1994
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
