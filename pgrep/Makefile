PROG= pgrep
DPADD+= ../proctools/libproctools.a
LDADD= -L${MAKEOBJDIR} -lproctools
CLEANFILES+= pgrep.cat1

.if defined(OLDKVM)
BINGRP= kmem
BINMODE= 2555
.endif

.include <bsd.prog.mk>
