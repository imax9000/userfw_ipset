/* Copyright (C) 2013 Maxim Ignatenko <gelraen.ua@gmail.com>
 *
 * Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 * Copyright (C) 2003-2011 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/limits.h>
#include <sys/mbuf.h>
#include <machine/atomic.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <userfw/module.h>
#include <userfw/io.h>
#include "ipset.h"
#include "ip_set_bitmap_ip.h"
#include "pfxlen.h"
#include "bitops.h"

/* Type structure */
struct bitmap_ip {
	void *members;		/* the set members */
	uint32_t first_ip;		/* host byte order, included in range */
	uint32_t last_ip;		/* host byte order, included in range */
	uint32_t elements;		/* number of max elements in the set */
	uint32_t hosts;		/* number of hosts in a subnet */
	size_t memsize;		/* members size */
	uint8_t netmask;		/* subnet netmask */
	uint32_t timeout;		/* timeout parameter */
/*	struct timer_list gc;*/	/* garbage collection */
};

#define	NMAPS	(0x10000)

struct bitmap_ip *maps[NMAPS];

static inline uint32_t
ip_to_id(const struct bitmap_ip *m, uint32_t ip)
{
	return ((ip & ip_set_hostmask(m->netmask)) - m->first_ip)/m->hosts;
}

static inline int
bitmap_ip_test(struct bitmap_ip *map, void *value)
{
	uint16_t id = *(uint16_t *)value;

	return !!test_bit(id, map->members);
}

static inline int
bitmap_ip_add(struct bitmap_ip *map, void *value)
{
	uint16_t id = *(uint16_t *)value;

	if (test_and_set_bit(id, map->members))
		return -EEXIST;

	return 0;
}

static inline int
bitmap_ip_del(struct bitmap_ip *map, void *value)
{
	uint16_t id = *(uint16_t *)value;

	if (!test_and_clear_bit(id, map->members))
		return -ENOENT;

	return 0;
}

static inline void
bitmap_ip_destroy(struct bitmap_ip *map)
{
	/* TODO: check refcount */
	free(map->members, M_USERFW_IPSET);
}

static inline struct bitmap_ip*
get_instance(uint16_t id)
{
	/* Warning: race condition possible when another thread removes instance
	   just after this function returned a pointer */
	return (struct bitmap_ip *)atomic_load_acq_ptr(&maps[id]);
}

static void
bitmap_ip_flush(struct bitmap_ip *map)
{
	bzero(map->members, map->memsize);
}

static int
action_add_delete_ip(struct mbuf **mb, userfw_chk_args *args, userfw_action *a, userfw_cache *cache, int *continue_, uint32_t flags)
{
	struct bitmap_ip *map = NULL;
	struct ip *ip = mtod(*mb, struct ip *);
	uint32_t addr;
	uint16_t id;

	*continue_ = 1;

	if (flags & USERFW_ACTION_FLAG_SECOND_PASS)
		return 0;

	if (ip->ip_v != 4)
		return 0;

	switch (a->op)
	{
	case A_ADD_SRC:
	case A_DELETE_SRC:
		addr = ntohl(ip->ip_src.s_addr);
		break;
	case A_ADD_DST:
	case A_DELETE_DST:
		addr = ntohl(ip->ip_dst.s_addr);
		break;
	default:
		printf("userfw_ipset_bitmap_ip: unknown opcode %d called used with action_add_delete_ip()\n", a->op);
		return 0;
	}

	map = get_instance(a->args[0].uint16.value);
	if (map == NULL)
		return 0;

	if (addr < map->first_ip || addr > map->last_ip)
		return 0;

	id = ip_to_id(map, addr);

	switch (a->op)
	{
	case A_ADD_SRC:
	case A_ADD_DST:
		bitmap_ip_add(map, &id);
		break;
	case A_DELETE_SRC:
	case A_DELETE_DST:
		bitmap_ip_del(map, &id);
		break;
	}

	return 0;
}

static userfw_action_descr bitmap_ip_actions[] = {
	{A_ADD_SRC,	1,	{T_UINT16},	"add-src", action_add_delete_ip}
	,{A_ADD_DST,	1,	{T_UINT16},	"add-dst", action_add_delete_ip}
	,{A_DELETE_SRC,	1,	{T_UINT16},	"delete-src", action_add_delete_ip}
	,{A_DELETE_DST,	1,	{T_UINT16},	"delete-dst", action_add_delete_ip}
};

static int
match_bitmap_ip(struct mbuf **mb, userfw_chk_args *args, userfw_match *m, userfw_cache *cache, userfw_arg *marg)
{
	struct bitmap_ip *map = NULL;
	uint32_t addr;
	uint16_t id;
	struct ip *ip = mtod(*mb, struct ip *);

	VERIFY_OPCODE2(m, USERFW_IPSET_BITMAP_IP_MOD, M_LOOKUP_SRC, M_LOOKUP_DST, 0);

	if (ip->ip_v != 4)
		return 0;

	if (m->op == M_LOOKUP_DST) {
		addr = ntohl(ip->ip_dst.s_addr);
	}
	else
	{
		addr = ntohl(ip->ip_src.s_addr);
	}

	map = get_instance(m->args[0].uint16.value);
	if (map != NULL)
	{
		if (addr >= map->first_ip && addr <= map->last_ip)
		{
			id = ip_to_id(map, addr);
			return bitmap_ip_test(map, &id);
		}
	}
	return 0;
}

static userfw_match_descr bitmap_ip_matches[] = {
	{M_LOOKUP_DST,	1,	{T_UINT16},	"lookup-dst",	match_bitmap_ip}
	,{M_LOOKUP_SRC,	1,	{T_UINT16},	"lookup-src",	match_bitmap_ip}	
};

static int
cmd_add_delete_test(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	uint32_t ip;
	uint16_t id;
	int ret = EOPNOTSUPP;
	struct bitmap_ip *map;

	map = get_instance(args[0].uint16.value);
	ip = ntohl(args[1].ipv4.addr);
	/* XXX: Only one address at a time for now */

	if (map != NULL)
	{
		if (ip >= map->first_ip && ip <= map->last_ip)
		{
			id = ip_to_id(map, ip);
			switch (op)
			{
			case CMD_ADD:
				ret = -(bitmap_ip_add(map, &id));
				break;
			case CMD_DELETE:
				ret = -(bitmap_ip_del(map, &id));
				break;
			case CMD_TEST:
				ret = bitmap_ip_test(map, &id) ? 0 : ENOENT;
				break;
			}
		}
		else
		{
			ret = EOPNOTSUPP;
		}
	}
	else
	{
		ret = ENOENT;
	}

	userfw_msg_reply_error(so, cookie, ret);

	return ret;
}

static int
cmd_clear(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	int ret = 0;
	struct bitmap_ip *map;

	map = get_instance(args[0].uint16.value);

	if (map != NULL)
	{
		bitmap_ip_flush(map);
	}
	else
	{
		ret = ENOENT;
	}
	userfw_msg_reply_error(so, cookie, ret);

	return ret;
}

static int
cmd_list(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	int ret = 0, len;
	struct bitmap_ip *map;
	unsigned char *data = NULL, *buf = NULL;
	uint32_t entries, n;
	size_t i;
	struct userfw_io_block *msg, *list;

	map = get_instance(args[0].uint16.value);

	if (map != NULL)
	{
		/* Warning: this function can return large amount of objects
		    and thus not compatible with userfw 0.1, which allows only
		    upto 255 subblocks */
		/* 
		  1) make a copy
		  2) count set bits
		  3) allocate structure for answer
		  4) run over copy again and fill answer
		  5) reply
		*/
		data = malloc(map->memsize, M_USERFW_IPSET, M_WAITOK);
		bcopy(map->members, data, map->memsize);

		entries = 0;
		for(i = 0; i < map->memsize; i++)
		{
			n = data[i];
			while(n > 0)
			{
				entries += (n & 1);
				n >>= 1;
			}
		}

		msg = userfw_msg_alloc_container(T_CONTAINER, ST_MESSAGE, 2, M_USERFW_IPSET);
		userfw_msg_insert_uint32(msg, ST_COOKIE, cookie, 0, M_USERFW_IPSET);

		list = userfw_msg_alloc_container(T_CONTAINER, ST_RESULT, entries, M_USERFW_IPSET);

		for(n = 0, i = 0; i < map->elements && n < entries; i++)
		{
			if (test_bit(i, data))
			{
				userfw_msg_insert_ipv4(list, ST_UNSPEC,
					htonl(map->first_ip + (i << (32 - map->netmask))),
					ip_set_netmask(map->netmask),
					n, M_USERFW_IPSET);
				n++;
			}
		}

		userfw_msg_set_arg(msg, list, 1);

		len = userfw_msg_calc_size(msg);
		buf = malloc(len, M_USERFW_IPSET, M_WAITOK);
		if (userfw_msg_serialize(msg, buf, len) > 0)
			userfw_domain_send_to_socket(so, buf, len);

		free(buf, M_USERFW_IPSET);
		userfw_msg_free(msg, M_USERFW_IPSET);
		free(data, M_USERFW_IPSET);
	}
	else
	{
		ret = ENOENT;
		userfw_msg_reply_error(so, cookie, ret);
	}

	return ret;
}

static inline int
is_mask_contiguous(uint32_t mask)
{
	int one_seen = 0;

	while(mask > 0)
	{
		if (mask & 1) one_seen = 1;
		else if (one_seen) return 0;
		mask >>= 1;
	}
	return 1;
}

static inline int
mask_to_cidr(uint32_t mask)
{
	int result = 32;

	while((mask & 1) == 0)
	{
		result--;
		mask >>= 1;
	}
	return result;
}

static inline size_t
bitmap_bytes(size_t nbits)
{
	if (nbits / (sizeof(long) * CHAR_BIT) * sizeof(long) * CHAR_BIT == nbits)
		return nbits / CHAR_BIT;
	else
		return (nbits / (sizeof(long) * CHAR_BIT) + 1) * sizeof(long);
}

static int
cmd_create(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	int ret = 0;
	struct bitmap_ip *map = NULL;
	uint32_t ip, mask, masklen;

	if (get_instance(args[0].uint16.value) != NULL)
	{
		userfw_msg_reply_error(so, cookie, EEXIST);
		return EEXIST;
	}

	/* Only bitmap with IPs (not subnets) allowed for now */
	ip = ntohl(args[1].ipv4.addr);
	mask = ntohl(args[1].ipv4.mask);
	if (is_mask_contiguous(mask) && (masklen = mask_to_cidr(mask)) >= 16)
	{
		map = malloc(sizeof(*map), M_USERFW_IPSET, M_WAITOK | M_ZERO);
		map->first_ip = ip & mask;
		map->last_ip = ip | (~mask);
		map->elements = map->last_ip - map->first_ip + 1;
		map->hosts = 1;
		map->netmask = 32;
		map->timeout = 0;
		map->memsize = bitmap_bytes(map->elements);
		map->members = malloc(map->memsize, M_USERFW_IPSET, M_WAITOK | M_ZERO);
	}
	else
	{
		ret = EINVAL;
	}

	if (!atomic_cmpset_ptr(&(maps[args[0].uint16.value]), NULL, map))
	{
		ret = EEXIST;
		bitmap_ip_destroy(map);
		free(map, M_USERFW_IPSET);
	}

	userfw_msg_reply_error(so, cookie, ret);
	return ret;
}

static int
cmd_destroy(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	int ret = 0;
	struct bitmap_ip *map = NULL;

	map = get_instance(args[0].uint16.value);
	if (map != NULL)
	{
		if (atomic_cmpset_ptr(&(map[args[0].uint16.value]), map, NULL))
		{
			bitmap_ip_destroy(map);
			free(map, M_USERFW_IPSET);
		}
		else
		{
			ret = EEXIST; /* XXX: what else? */
		}
	}
	else
	{
		ret = ENOENT;
	}

	userfw_msg_reply_error(so, cookie, ret);
	return ret;
}

static userfw_cmd_descr bitmap_ip_cmds[] =
{
	{CMD_ADD,	2,	{T_UINT16, T_IPv4},	"add",	cmd_add_delete_test}
	,{CMD_DELETE,	2,	{T_UINT16, T_IPv4},	"delete",	cmd_add_delete_test}
	,{CMD_TEST,	2,	{T_UINT16, T_IPv4},	"test",	cmd_add_delete_test}
	,{CMD_CLEAR,	1,	{T_UINT16},	"clear",	cmd_clear}
	,{CMD_LIST,	1,	{T_UINT16},	"list",	cmd_list}
	,{CMD_CREATE,	2,	{T_UINT16, T_IPv4},	"create",	cmd_create}
	,{CMD_DESTROY,	2,	{T_UINT16, T_IPv4},	"destroy",	cmd_destroy}
};

static userfw_modinfo ipset_bitmap_ip_modinfo =
{
	.id = USERFW_IPSET_BITMAP_IP_MOD,
	.name = "ipset_bitmap_ip",
	.nactions = sizeof(bitmap_ip_actions)/sizeof(bitmap_ip_actions[0]),
	.nmatches = sizeof(bitmap_ip_matches)/sizeof(bitmap_ip_matches[0]),
	.ncmds = sizeof(bitmap_ip_cmds)/sizeof(bitmap_ip_cmds[0]),
	.actions = bitmap_ip_actions,
	.matches = bitmap_ip_matches,
	.cmds = bitmap_ip_cmds
};

static int
ipset_bitmap_ip_modevent(module_t mod, int type, void *p)
{
	int err = 0;
	switch(type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&ipset_bitmap_ip_modinfo);
		if (err == 0)
		{
			bzero(maps, sizeof(maps));
		}
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_IPSET_BITMAP_IP_MOD);
		if (err == 0)
		{
			int i;
			for(i = 0; i < NMAPS; i++)
			{
				if (maps[i] != NULL)
				{
					bitmap_ip_destroy(maps[i]);
					free(maps[i], M_USERFW_IPSET);
				}
			}
		}
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t ipset_bitmap_ip_mod =
{
	"userfw_ipset_bitmap_ip",
	ipset_bitmap_ip_modevent,
	0
};

MODULE_VERSION(userfw_ipset_bitmap_ip, 1);
DEPEND_ON_USERFW_CORE(userfw_ipset_bitmap_ip);
#if USERFW_KABI_VERSION < 2
#error "This module will not work correctly with userfw 0.1.*. If you sure that you can deal with that - remove this line."
#endif

DECLARE_MODULE(userfw_ipset_bitmap_ip, ipset_bitmap_ip_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD + 1);
