SUBDIR= proctools pgrep pkill
DPADD+= proctools/libproctools.a pgrep/pgrep pkill/pkill

beforeinstall: all

.include <bsd.subdir.mk>
