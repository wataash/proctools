PROG=   pkill
DPADD+=	${LIBPROCTOOLS} ${LIBKVM}
LDADD=	-lkvm -L${.CURDIR}/../proctools -lproctools
BINGRP=	kmem
BINMODE=	2555

.include <bsd.prog.mk>
