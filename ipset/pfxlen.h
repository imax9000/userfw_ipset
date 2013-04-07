#ifndef _PFXLEN_H
#define _PFXLEN_H

#include <sys/types.h>
#include <netinet/in.h>

union nf_inet_addr {
	uint32_t	all[4];
	uint32_t	ip;
	uint32_t	ip6[4];
	struct in_addr	in;
	struct in6_addr	in6;
};

/* Prefixlen maps, by Jan Engelhardt  */
extern const union nf_inet_addr ip_set_netmask_map[];
extern const union nf_inet_addr ip_set_hostmask_map[];

static inline uint32_t
ip_set_netmask(uint8_t pfxlen)
{
	return ip_set_netmask_map[pfxlen].ip;
}

static inline const uint32_t *
ip_set_netmask6(uint8_t pfxlen)
{
	return &ip_set_netmask_map[pfxlen].ip6[0];
}

static inline uint32_t
ip_set_hostmask(uint8_t pfxlen)
{
	return (uint32_t) ip_set_hostmask_map[pfxlen].ip;
}

static inline const uint32_t *
ip_set_hostmask6(uint8_t pfxlen)
{
	return &ip_set_hostmask_map[pfxlen].ip6[0];
}

extern uint32_t ip_set_range_to_cidr(uint32_t from, uint32_t to, uint8_t *cidr);

#define ip_set_mask_from_to(from, to, cidr)	\
do {						\
	from &= ip_set_hostmask(cidr);		\
	to = from | ~ip_set_hostmask(cidr);	\
} while (0)

#endif /*_PFXLEN_H */
