#	@(#)Makefile	8.3 (Berkeley) 3/27/94
# $FreeBSD: releng/10.3/sbin/mount_cryptofs/Makefile 198236 2009-10-19 16:00:24Z ru $

PROG=	mount_cryptofs
SRCS=	mount_cryptofs.c getmntopts.c
MAN=	mount_cryptofs.8

MOUNT=	${.CURDIR}/../mount
CFLAGS+=-I${MOUNT}

.PATH:	${MOUNT}

.include <bsd.prog.mk>
