SUBDIR=	proctools pgrep pkill pfind
DOCS=	LICENSE README
DIR=	proctools

.include "Makefile.inc"

beforeinstall: ${DESTDIR}${BINDIR} ${DESTDIR}${MANDIR}1

${DESTDIR}${BINDIR}:
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m ${BINMODE} ${DESTDIR}${BINDIR}

${DESTDIR}${MANDIR}1:
	${INSTALL} -d -o ${MANOWN} -g ${MANGRP} -m ${MANMODE} ${DESTDIR}${MANDIR}1

afterinstall:
	${INSTALL} -d -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${DESTDIR}${DOCDIR}/${DIR}
	${INSTALL} ${INSTALL_COPY} -o ${DOCOWN} -g ${DOCGRP} -m ${DOCMODE} \
		${DOCS} ${DESTDIR}${DOCDIR}/${DIR}

.include <bsd.subdir.mk>
