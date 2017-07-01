PROG=   http
MAN=    http.1

CFLAGS=	-D'pledge(pr, pa)=0' -D'getdtablecount()=0'
CFLAGS+= -I${.CURDIR} -I/usr/pkg/libressl/include
LDFLAGS= -L /usr/pkg/libressl/lib

SRCS=   main.c http.c ftp.c file.c progressmeter.c util.c
SRCS+=	openbsd_compat.c imsg.c imsg-buffer.c

LDADD+=	-lutil -ltls -lssl -lcrypto
DPADD+=	${LIBUTIL} ${LIBTLS} ${LIBSSL} ${LIBCRYPTO}

.include <bsd.prog.mk>
