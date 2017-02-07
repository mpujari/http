PROG=   http
MAN=    http.1

SRCS=   main.c http.c ftp.c io.c progressmeter.c util.c

LDADD+= -lcurses -ledit -ltls -lssl -lcrypto -lutil
DPADD+= ${LIBTLS} ${LIBSSL} ${LIBCRYPTO} ${LIBUTIL}

.include <bsd.prog.mk>
