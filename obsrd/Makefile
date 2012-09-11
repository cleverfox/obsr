#

PROG=	obsrd
MAN=	obsrd.8

LIBCLI=	${.CURDIR}/../libcli
WARNS?= 2

SRCS=   obsrd.c ippool.c session.c cliconfig.c cli.c clicmd.c obsr_commands.c libcli.c log.c ipfw.c

DPADD=  ${LIBNETGRAPH} ${LIBCLI} ${LIBUTIL}
LDADD=  -lnetgraph -g -lradius -lcrypt -pthread -lutil
CFLAGS+=-g -I${LIBCLI}


.PATH: ${LIBCLI}

.include <bsd.prog.mk>
