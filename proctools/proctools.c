#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <err.h>
#include <fcntl.h>
#include <grp.h>
#include <kvm.h>
#include <limits.h>
#include <pwd.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include "proctools.h"

/*
 * Takes a comma/whitespace separated list of pids and places
 * them in a linked list in an unspecified order.
 */
int
parsePidList(pidstring, pidlist)
	char *pidstring;
	struct pidlist **pidlist;
{
	struct pidlist *head, *pl;
	int bad, invalid;
	pid_t pid;
	char *stringp;
	char *endptr;

	*pidlist = head = NULL;
	invalid = 0;

	while ((stringp = strsep(&pidstring, ", \t")) != NULL) {
		if (*stringp != '\0') {
			bad = 0;
			pid = (pid_t)strtol(stringp, &endptr, 10);
			if (*endptr != '\0') {
				warn("Unable to parse pid %s", stringp);
				bad++;
			}
			if (bad == 0) {
				if ((pl = calloc(1, sizeof(struct pidlist))) == NULL)
					err(EX_OSERR, NULL);
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
	return (invalid);
}

/*
 * Takes a comma/whitespace separated list of usernames and uids
 * and places them in a linked list in an unspecified order.
 */
int
parseUidList(uidstring, uidlist)
	char *uidstring;
	struct uidlist **uidlist;
{
	struct passwd *tempu;
	struct uidlist *head, *ul;
	int bad, invalid;
	uid_t uid;
	char *stringp;
	char *endptr;

	*uidlist = head = NULL;
	invalid = 0;

	while ((stringp = strsep(&uidstring, ", \t")) != NULL) {
		if (*stringp != '\0') {
			bad = 0;
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
				if ((ul = calloc(1, sizeof(struct uidlist))) == NULL)
					err(EX_OSERR, NULL);
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
	return (invalid);
}

/*
 * Takes a comma/whitespace separated list of groups and gids
 * and places them in a linked list in an unspecified order.
 */
int
parseGroupList(groupstring, grouplist)
	char *groupstring;
	struct grouplist **grouplist;
{
	struct group *tempg;
	struct grouplist *gl, *head;
	gid_t group;
	int bad, invalid;
	char *endptr;
	char *stringp;

	*grouplist = head = NULL;
	invalid = 0;

	while ((stringp = strsep(&groupstring, ", \t")) != NULL) {
		if (*stringp != '\0') {
			bad = 0;
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
				if ((gl = calloc(1, sizeof(struct grouplist))) == NULL)
					err(EX_OSERR, NULL);
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
	return (invalid);
}

/*
 * Takes a comma/whitespace separated list of filenames, translates
 * them to device numbers if possible and places them in a linked list
 * in an unspecified order.  If the filename does not begin with a '/',
 * it assumes that the file lies within the /dev directory.
 */
int
parseTermList(termstring, termlist)
	char *termstring;
	struct termlist **termlist;
{
	struct stat statbuf;
	struct termlist *head, *tl;
	dev_t term;
	int bad, invalid;
	size_t len;
	char *stringp;
	char *temps;

	*termlist = head = NULL;
	invalid = 0;

	while ((stringp = strsep(&termstring, ", \t")) != NULL) {
		if (*stringp != '\0') {
			bad = 0;
			if (*stringp != '/') {
				len = strlen(stringp);
				len += 6; /* for "/dev/" */
				if ((temps = calloc(len, sizeof(char))) == NULL)
					err(EX_OSERR, NULL);
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
				if ((tl = calloc(1, sizeof(struct termlist))) == NULL)
					err(EX_OSERR, NULL);
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
	return (invalid);
}

/*
 * Takes a uid and a linked list of uids and checks to see
 * if the uid exists within the linked list.
 */
int
matchUidList(uidlist, uid)
	struct uidlist *uidlist;
	uid_t uid;
{
	struct uidlist *tempul;

	if (uidlist == NULL)
		return (TRUE);

	for (tempul = uidlist; tempul != NULL; tempul = tempul->next)
		if (tempul->uid == uid)
			return (TRUE);
	return (FALSE);
}

/*
 * Takes a gid and a linked list of gids and checks to see
 * if the gid exists within the linked list.
 */
int
matchGroupList(grouplist, gid)
	struct grouplist *grouplist;
	gid_t gid;
{
	struct grouplist *tempgl;

	if (grouplist == NULL)
		return (TRUE);

	for (tempgl = grouplist; tempgl != NULL; tempgl = tempgl->next)
		if (tempgl->group == gid)
			return (TRUE);
	return (FALSE);
}

/*
 * Takes a pid and a linked list of pids and checks to see
 * if the pid exists within the linked list.
 */
int
matchPidList(pidlist, pid)
	struct pidlist *pidlist;
	pid_t pid;
{
	struct pidlist *temppl;

	if (pidlist == NULL)
		return (TRUE);

	for (temppl = pidlist; temppl != NULL; temppl = temppl->next)
		if (temppl->pid == pid)
			return (TRUE);
	return (FALSE);
}

/*
 * Takes a device number and a linked list of device numbers and
 * checks to see if the device number exists within the linked list.
 */
int
matchTermList(termlist, term)
	struct termlist *termlist;
	dev_t term;
{
	struct termlist *temptl;

	if (termlist == NULL)
		return (TRUE);

	for (temptl = termlist; temptl != NULL; temptl = temptl->next)
		if (temptl->term == term)
			return (TRUE);
	return (FALSE);
}

/*
 * Pushes a new process and its executable name into a linked
 * list of processes, creating the linked list if necessary.
 */
int
pushProcList(proclist, pid, name)
	struct proclist **proclist;
	pid_t pid;
	char *name;
{
	struct proclist *temppl;

	if ((temppl = calloc(1, sizeof(struct proclist))) == NULL)
		err(EX_OSERR, NULL);
	if ((temppl->name = strdup(name)) == NULL)
		err(EX_OSERR, NULL);
	temppl->pid = pid;
	temppl->next = *proclist;

	*proclist = temppl;
	return (1);
}

/*
 * Parses the kernel structures containing process information searching
 * for processes that match the information stored in the linked lists
 * and flags supplied.
 */
int
getProcList(proclist, euidlist, uidlist, gidlist, ppidlist, pgrouplist, termlist, fullmatch, lastonly, invert, exact, pattern)
	struct proclist **proclist;
	struct uidlist *euidlist;
	struct uidlist *uidlist;
	struct grouplist *gidlist;
	struct pidlist *ppidlist;
	struct pidlist *pgrouplist;
	struct termlist *termlist;
	int fullmatch;
	int lastonly;
	int invert;
	int exact;
	char *pattern;
{
	char errbuf[_POSIX2_LINE_MAX];
	kvm_t *kd;
	struct kinfo_proc *kp, kpi;
	struct pstats pstats;
	struct {
		struct	timeval time;
		char	*name;
		pid_t	pid;
		int	valid;
	} latest;
	regex_t regex;
	int i, nentries;
	int extmatch, match;
	char **kvm_argv;
	char *name;

	kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);
	if (kd == 0)
		errx(EX_UNAVAILABLE, "%s", errbuf);

	setegid(getgid());
	setgid(getgid());

	if ((kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nentries)) == 0)
		errx(EX_UNAVAILABLE, "%s", kvm_geterr(kd));

	if (!exact && (pattern != NULL))
		if (regcomp(&regex, pattern, REG_EXTENDED) != 0)
			err(EX_UNAVAILABLE, "Unable to compile regular expression");

	if (lastonly)
		latest.valid = FALSE;

	for (i = nentries; --i >= 0; ++kp) {
		kpi = *kp;
		match = (matchPidList(pgrouplist, kpi.kp_eproc.e_pgid) &&
		    matchGroupList(gidlist, kpi.kp_eproc.e_ucred.cr_gid) &&
		    matchPidList(ppidlist, kpi.kp_eproc.e_ppid) &&
		    matchTermList(termlist, kpi.kp_eproc.e_tdev) &&
		    matchUidList(euidlist, kpi.kp_eproc.e_pcred.p_svuid) &&
		    matchUidList(uidlist, kpi.kp_eproc.e_pcred.p_ruid));
		extmatch = pgrouplist || gidlist || ppidlist || termlist || euidlist || uidlist;
		if (match && !invert) {
			if (fullmatch) {
				kvm_argv = kvm_getargv(kd, kp, 0);
				if ((name = strdup(kvm_argv[0])) == NULL)
					err(EX_OSERR, NULL);
			} else
				if ((name = strdup(kpi.kp_proc.p_comm)) == NULL)
					err(EX_OSERR, NULL);
			if (lastonly) {
				if (kvm_read(kd, (u_long)&kpi.kp_proc.p_addr->u_stats, &pstats, sizeof(pstats)) != sizeof(pstats))
					err(EX_UNAVAILABLE, "Unable to get process start time");
				if (exact) {
					if (!strcmp(name, pattern)) {
						if (!latest.valid) {
							latest.valid = TRUE;
							latest.time.tv_sec = pstats.p_start.tv_sec;
							latest.time.tv_usec = pstats.p_start.tv_usec;
							if ((latest.name = strdup(kpi.kp_proc.p_comm)) == NULL)
								err(EX_OSERR, NULL);
							latest.pid = kpi.kp_proc.p_pid;
						} else if ((pstats.p_start.tv_sec > latest.time.tv_sec) && (pstats.p_start.tv_usec > latest.time.tv_usec)) {
							latest.time.tv_sec = pstats.p_start.tv_sec;
							latest.time.tv_usec = pstats.p_start.tv_usec;
							free(latest.name);
							if ((latest.name = strdup(kpi.kp_proc.p_comm)) == NULL)
								err(EX_OSERR, NULL);
							latest.pid = kpi.kp_proc.p_pid;
						}
					}
				} else {
					if (regexec(&regex, name, 0, NULL, NULL) == 0) {
						if (!latest.valid) {
							latest.valid = TRUE;
							latest.time.tv_sec = pstats.p_start.tv_sec;
							latest.time.tv_usec = pstats.p_start.tv_usec;
							if ((latest.name = strdup(kpi.kp_proc.p_comm)) == NULL)
								err(EX_OSERR, NULL);
							latest.pid = kpi.kp_proc.p_pid;
						} else if ((pstats.p_start.tv_sec > latest.time.tv_sec) && (pstats.p_start.tv_usec > latest.time.tv_usec)) {
							latest.time.tv_sec = pstats.p_start.tv_sec;
							latest.time.tv_usec = pstats.p_start.tv_usec;
							free(latest.name);
							if ((latest.name = strdup(kpi.kp_proc.p_comm)) == NULL)
								err(EX_OSERR, NULL);
							latest.pid = kpi.kp_proc.p_pid;
						}
					}
				}
			} else if (pattern != NULL) {
				if (exact) {
					if (strcmp(name, pattern) == 0)
						pushProcList(proclist, kpi.kp_proc.p_pid, kpi.kp_proc.p_comm);
				} else
					if (regexec(&regex, name, 0, NULL, NULL) == 0)
						pushProcList(proclist, kpi.kp_proc.p_pid, kpi.kp_proc.p_comm);
			} else
				pushProcList(proclist, kpi.kp_proc.p_pid, kpi.kp_proc.p_comm);
			free(name);
		} else if ((!match && invert) || (match && !extmatch && invert)) {
			if (fullmatch) {
				kvm_argv = kvm_getargv(kd, kp, 0);
				if ((name = strdup(kvm_argv[0])) == NULL)
					err(EX_OSERR, NULL);
			} else
				if ((name = strdup(kpi.kp_proc.p_comm)) == NULL)
					err(EX_OSERR, NULL);
			if (lastonly) {
				if (kvm_read(kd, (u_long)&kpi.kp_proc.p_addr->u_stats, &pstats, sizeof(pstats)) != sizeof(pstats))
					errx(EX_UNAVAILABLE, "Unable to get process start time");
				if (!latest.valid) {
					latest.valid = TRUE;
					latest.time.tv_sec = pstats.p_start.tv_sec;
					latest.time.tv_usec = pstats.p_start.tv_usec;
					if ((latest.name = strdup(kpi.kp_proc.p_comm)) == NULL)
						err(EX_OSERR, NULL);
					latest.pid = kpi.kp_proc.p_pid;
				} else if ((pstats.p_start.tv_sec > latest.time.tv_sec) && (pstats.p_start.tv_usec > latest.time.tv_usec)) {
					latest.time.tv_sec = pstats.p_start.tv_sec;
					latest.time.tv_usec = pstats.p_start.tv_usec;
					free(latest.name);
					if ((latest.name = strdup(kpi.kp_proc.p_comm)) == NULL)
						err(EX_OSERR, NULL);
					latest.pid = kpi.kp_proc.p_pid;
				}
			} else if (pattern != NULL) {
				if (exact) {
					if (strcmp(name, pattern) != 0)
						pushProcList(proclist, kpi.kp_proc.p_pid, kpi.kp_proc.p_comm);
				} else
					if (regexec(&regex, name, 0, NULL, NULL) == REG_NOMATCH)
						pushProcList(proclist, kpi.kp_proc.p_pid, kpi.kp_proc.p_comm);
			} else
				pushProcList(proclist, kpi.kp_proc.p_pid, kpi.kp_proc.p_comm);
			free(name);
		}
	}
	kpi = *kp;

	if (lastonly && latest.valid)
		pushProcList(proclist, latest.pid, latest.name);

	return (1);
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
 */
