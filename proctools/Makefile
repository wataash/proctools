LIB=	proctools
SRCS= fmt.c proctools.c
NOPROFILE=	yes
NOPIC=	yes
NOLINT=	yes

.if defined(OLDKVM)
CFLAGS= -DUSE_KVM
.endif

install:

.include <bsd.lib.mk>
