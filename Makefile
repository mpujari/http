PROG=   http
MAN=    http.1

DEBUG=	-g
SRCS=   main.c http.c ftp.c file.c io.c progressmeter.c util.c

LDADD+=	-lutil -ltls -lssl -lcrypto
DPADD+=	${LIBUTIL} ${LIBTLS} ${LIBSSL} ${LIBCRYPTO}

.include <bsd.prog.mk>
