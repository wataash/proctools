#ifndef _PROCTOOLS_H_
#define _PROCTOOLS_H_

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif


struct proclist {
        struct	proclist *next;
        char	*name;
        pid_t	pid;
};

struct uidlist {
	struct	uidlist *next;
	uid_t	uid;
};

struct pidlist {
	struct	pidlist *next;
	pid_t	pid;
};

struct grouplist {
	struct	grouplist *next;
	gid_t	group;
};

struct termlist {
	struct	termlist *next;
	dev_t	term;
};

__BEGIN_DECLS
int parsePidList __P((char *, struct pidlist **));
int parseUidList __P((char *, struct uidlist **));
int parseGroupList __P((char *, struct grouplist **));
int parseTermList __P((char *, struct termlist **));
int matchUidList __P((struct uidlist *, uid_t));
int matchGroupList __P((struct grouplist *, gid_t));
int matchPidList __P((struct pidlist *, pid_t));
int matchTermList __P((struct termlist *, dev_t));
int pushProcList __P((struct proclist **, pid_t, char*));
int getProcList __P((struct proclist **, struct uidlist *, struct uidlist *, struct grouplist *, struct pidlist *, struct pidlist *, struct termlist *, int, int, int, int, char *));
__END_DECLS

#endif /* !_PROCTOOLS_H_ */
