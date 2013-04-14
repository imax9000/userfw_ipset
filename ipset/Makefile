SRCS=	ipset.c \
		pfxlen.c \
		ip_set_bitmap_ip.c
KMOD=	userfw_ipset
KMODDIR?=	/boot/modules
CFLAGS+=	-I/usr/local/include

.if defined(SKIP_OPCODE_VERIFICATION)
CFLAGS+=	-DSKIP_OPCODE_VERIFICATION
.endif

afterinstall:
	${INSTALL} -d "${PREFIX}/include/userfw/modules"
	${INSTALL} ipset.h "${PREFIX}/include/userfw/modules"

.include <bsd.kmod.mk>
