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
#include <userfw/module.h>
#include <userfw/io.h>
#include "ipset.h"
#include "ip_set_bitmap_ip.h"
#include "pfxlen.h"
#include <linux/bitops.h> /* XXX: from sys/ofed, */

/* Kernel module implementing an IP set type: the bitmap:ip type */

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

/* Base variant */

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
		return -EEXIST;

	return 0;
}

static inline void
bitmap_ip_destroy(struct bitmap_ip *map)
{
	free(map->members, M_USERFW_IPSET);
}

static inline struct bitmap_ip*
get_instance(uint16_t id)
{
	return maps[id];
}

/*
static int
bitmap_ip_list(const struct ip_set *set,
	       struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct bitmap_ip *map = set->data;
	struct nlattr *atd, *nested;
	uint32_t id, first = cb->args[2];

	atd = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!atd)
		return -EMSGSIZE;
	for (; cb->args[2] < map->elements; cb->args[2]++) {
		id = cb->args[2];
		if (!test_bit(id, map->members))
			continue;
		nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
		if (!nested) {
			if (id == first) {
				nla_nest_cancel(skb, atd);
				return -EMSGSIZE;
			} else
				goto nla_put_failure;
		}
		if (nla_put_ipaddr4(skb, IPSET_ATTR_IP,
				    htonl(map->first_ip + id * map->hosts)))
			goto nla_put_failure;
		ipset_nest_end(skb, nested);
	}
	ipset_nest_end(skb, atd);
	cb->args[2] = 0;
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nested);
	ipset_nest_end(skb, atd);
	if (unlikely(id == first)) {
		cb->args[2] = 0;
		return -EMSGSIZE;
	}
	return 0;
}
*/
/* Timeout variant */
/*
static int
bitmap_ip_ttest(struct ip_set *set, void *value, uint32_t timeout, uint32_t flags)
{
	const struct bitmap_ip *map = set->data;
	const unsigned long *members = map->members;
	uint16_t id = *(uint16_t *)value;

	return ip_set_timeout_test(members[id]);
}

static int
bitmap_ip_tadd(struct ip_set *set, void *value, uint32_t timeout, uint32_t flags)
{
	struct bitmap_ip *map = set->data;
	unsigned long *members = map->members;
	uint16_t id = *(uint16_t *)value;

	if (ip_set_timeout_test(members[id]) && !(flags & IPSET_FLAG_EXIST))
		return -IPSET_ERR_EXIST;

	members[id] = ip_set_timeout_set(timeout);

	return 0;
}

static int
bitmap_ip_tdel(struct ip_set *set, void *value, uint32_t timeout, uint32_t flags)
{
	struct bitmap_ip *map = set->data;
	unsigned long *members = map->members;
	uint16_t id = *(uint16_t *)value;
	int ret = -IPSET_ERR_EXIST;

	if (ip_set_timeout_test(members[id]))
		ret = 0;

	members[id] = IPSET_ELEM_UNSET;
	return ret;
}

static int
bitmap_ip_tlist(const struct ip_set *set,
		struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct bitmap_ip *map = set->data;
	struct nlattr *adt, *nested;
	uint32_t id, first = cb->args[2];
	const unsigned long *members = map->members;

	adt = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!adt)
		return -EMSGSIZE;
	for (; cb->args[2] < map->elements; cb->args[2]++) {
		id = cb->args[2];
		if (!ip_set_timeout_test(members[id]))
			continue;
		nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
		if (!nested) {
			if (id == first) {
				nla_nest_cancel(skb, adt);
				return -EMSGSIZE;
			} else
				goto nla_put_failure;
		}
		if (nla_put_ipaddr4(skb, IPSET_ATTR_IP,
				    htonl(map->first_ip + id * map->hosts)) ||
		    nla_put_net32(skb, IPSET_ATTR_TIMEOUT,
				  htonl(ip_set_timeout_get(members[id]))))
			goto nla_put_failure;
		ipset_nest_end(skb, nested);
	}
	ipset_nest_end(skb, adt);

	// Set listing finished
	cb->args[2] = 0;

	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nested);
	ipset_nest_end(skb, adt);
	if (unlikely(id == first)) {
		cb->args[2] = 0;
		return -EMSGSIZE;
	}
	return 0;
}
*/
/*
static int
bitmap_ip_kadt(struct ip_set *set, const struct sk_buff *skb,
	       const struct xt_action_param *par,
	       enum ipset_adt adt, const struct ip_set_adt_opt *opt)
{
	struct bitmap_ip *map = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	uint32_t ip;

	ip = ntohl(ip4addr(skb, opt->flags & IPSET_DIM_ONE_SRC));
	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	ip = ip_to_id(map, ip);

	return adtfn(set, &ip, opt_timeout(opt, map), opt->cmdflags);
}

static int
bitmap_ip_uadt(struct ip_set *set, struct nlattr *tb[],
	       enum ipset_adt adt, uint32_t *lineno, uint32_t flags, bool retried)
{
	struct bitmap_ip *map = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	uint32_t timeout = map->timeout;
	uint32_t ip, ip_to, id;
	int ret = 0;

	if (unlikely(!tb[IPSET_ATTR_IP] ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT)))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_uint32_t(tb[IPSET_ATTR_LINENO]);

	ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP], &ip);
	if (ret)
		return ret;

	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	if (tb[IPSET_ATTR_TIMEOUT]) {
		if (!with_timeout(map->timeout))
			return -IPSET_ERR_TIMEOUT;
		timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
	}

	if (adt == IPSET_TEST) {
		id = ip_to_id(map, ip);
		return adtfn(set, &id, timeout, flags);
	}

	if (tb[IPSET_ATTR_IP_TO]) {
		ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP_TO], &ip_to);
		if (ret)
			return ret;
		if (ip > ip_to) {
			swap(ip, ip_to);
			if (ip < map->first_ip)
				return -IPSET_ERR_BITMAP_RANGE;
		}
	} else if (tb[IPSET_ATTR_CIDR]) {
		uint8_t cidr = nla_get_uint8_t(tb[IPSET_ATTR_CIDR]);

		if (!cidr || cidr > 32)
			return -IPSET_ERR_INVALID_CIDR;
		ip_set_mask_from_to(ip, ip_to, cidr);
	} else
		ip_to = ip;

	if (ip_to > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	for (; !before(ip_to, ip); ip += map->hosts) {
		id = ip_to_id(map, ip);
		ret = adtfn(set, &id, timeout, flags);

		if (ret && !ip_set_eexist(ret, flags))
			return ret;
		else
			ret = 0;
	}
	return ret;
}

static void
bitmap_ip_destroy(struct ip_set *set)
{
	struct bitmap_ip *map = set->data;

	if (with_timeout(map->timeout))
		del_timer_sync(&map->gc);

	ip_set_free(map->members);
	kfree(map);

	set->data = NULL;
}
*/

static void
bitmap_ip_flush(struct bitmap_ip *map)
{
	bzero(map->members, map->memsize);
}
/*
static int
bitmap_ip_head(struct ip_set *set, struct sk_buff *skb)
{
	const struct bitmap_ip *map = set->data;
	struct nlattr *nested;

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	if (nla_put_ipaddr4(skb, IPSET_ATTR_IP, htonl(map->first_ip)) ||
	    nla_put_ipaddr4(skb, IPSET_ATTR_IP_TO, htonl(map->last_ip)) ||
	    (map->netmask != 32 &&
	     nla_put_uint8_t(skb, IPSET_ATTR_NETMASK, map->netmask)) ||
	    nla_put_net32(skb, IPSET_ATTR_REFERENCES, htonl(set->ref - 1)) ||
	    nla_put_net32(skb, IPSET_ATTR_MEMSIZE,
			  htonl(sizeof(*map) + map->memsize)) ||
	    (with_timeout(map->timeout) &&
	     nla_put_net32(skb, IPSET_ATTR_TIMEOUT, htonl(map->timeout))))
		goto nla_put_failure;
	ipset_nest_end(skb, nested);

	return 0;
nla_put_failure:
	return -EMSGSIZE;
}
*/
/*
static void
bitmap_ip_gc(unsigned long ul_set)
{
	struct ip_set *set = (struct ip_set *) ul_set;
	struct bitmap_ip *map = set->data;
	unsigned long *table = map->members;
	uint32_t id;

	/ * We run parallel with other readers (test element)
	 * but adding/deleting new entries is locked out * /
	read_lock_bh(&set->lock);
	for (id = 0; id < map->elements; id++)
		if (ip_set_timeout_expired(table[id]))
			table[id] = IPSET_ELEM_UNSET;
	read_unlock_bh(&set->lock);

	map->gc.expires = jiffies + IPSET_GC_PERIOD(map->timeout) * HZ;
	add_timer(&map->gc);
}

static void
bitmap_ip_gc_init(struct ip_set *set)
{
	struct bitmap_ip *map = set->data;

	init_timer(&map->gc);
	map->gc.data = (unsigned long) set;
	map->gc.function = bitmap_ip_gc;
	map->gc.expires = jiffies + IPSET_GC_PERIOD(map->timeout) * HZ;
	add_timer(&map->gc);
}
*/

/* Create bitmap:ip type of sets */
/*
static bool
init_map_ip(struct ip_set *set, struct bitmap_ip *map,
	    uint32_t first_ip, uint32_t last_ip,
	    uint32_t elements, uint32_t hosts, uint8_t netmask)
{
	map->members = ip_set_alloc(map->memsize);
	if (!map->members)
		return false;
	map->first_ip = first_ip;
	map->last_ip = last_ip;
	map->elements = elements;
	map->hosts = hosts;
	map->netmask = netmask;
	map->timeout = IPSET_NO_TIMEOUT;

	set->data = map;
	set->family = NFPROTO_IPV4;

	return true;
}

static int
bitmap_ip_create(struct ip_set *set, struct nlattr *tb[], uint32_t flags)
{
	struct bitmap_ip *map;
	uint32_t first_ip, last_ip, hosts;
	u64 elements;
	uint8_t netmask = 32;
	int ret;

	if (unlikely(!tb[IPSET_ATTR_IP] ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT)))
		return -IPSET_ERR_PROTOCOL;

	ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP], &first_ip);
	if (ret)
		return ret;

	if (tb[IPSET_ATTR_IP_TO]) {
		ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP_TO], &last_ip);
		if (ret)
			return ret;
		if (first_ip > last_ip) {
			uint32_t tmp = first_ip;

			first_ip = last_ip;
			last_ip = tmp;
		}
	} else if (tb[IPSET_ATTR_CIDR]) {
		uint8_t cidr = nla_get_uint8_t(tb[IPSET_ATTR_CIDR]);

		if (cidr >= 32)
			return -IPSET_ERR_INVALID_CIDR;
		ip_set_mask_from_to(first_ip, last_ip, cidr);
	} else
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_NETMASK]) {
		netmask = nla_get_uint8_t(tb[IPSET_ATTR_NETMASK]);

		if (netmask > 32)
			return -IPSET_ERR_INVALID_NETMASK;

		first_ip &= ip_set_hostmask(netmask);
		last_ip |= ~ip_set_hostmask(netmask);
	}

	if (netmask == 32) {
		hosts = 1;
		elements = (u64)last_ip - first_ip + 1;
	} else {
		uint8_t mask_bits;
		uint32_t mask;

		mask = range_to_mask(first_ip, last_ip, &mask_bits);

		if ((!mask && (first_ip || last_ip != 0xFFFFFFFF)) ||
		    netmask <= mask_bits)
			return -IPSET_ERR_BITMAP_RANGE;

		pr_debug("mask_bits %u, netmask %u\n", mask_bits, netmask);
		hosts = 2 << (32 - netmask - 1);
		elements = 2 << (netmask - mask_bits - 1);
	}
	if (elements > IPSET_BITMAP_MAX_RANGE + 1)
		return -IPSET_ERR_BITMAP_RANGE_SIZE;

	pr_debug("hosts %u, elements %llu\n",
		 hosts, (unsigned long long)elements);

	map = kzalloc(sizeof(*map), GFP_KERNEL);
	if (!map)
		return -ENOMEM;

	if (tb[IPSET_ATTR_TIMEOUT]) {
		map->memsize = elements * sizeof(unsigned long);

		if (!init_map_ip(set, map, first_ip, last_ip,
				 elements, hosts, netmask)) {
			kfree(map);
			return -ENOMEM;
		}

		map->timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
		set->variant = &bitmap_tip;

		bitmap_ip_gc_init(set);
	} else {
		map->memsize = bitmap_bytes(0, elements - 1);

		if (!init_map_ip(set, map, first_ip, last_ip,
				 elements, hosts, netmask)) {
			kfree(map);
			return -ENOMEM;
		}

		set->variant = &bitmap_ip;
	}
	return 0;
}
*/

static int
cmd_add(opcode_t op, uint32_t cookie, userfw_arg *args, struct socket *so, struct thread *th)
{
	uint32_t ip, id;
	int ret;
	struct bitmap_ip *map;

	map = get_instance(args[0].uint16.value);
	ip = ntohl(args[1].ipv4.addr);
	/* XXX: Only one address at a time for now */

	if (map != NULL)
	{
		if (ip >= map->first_ip && ip <= map->last_ip)
		{
			id = ip_to_id(map, ip);
			ret = -(bitmap_ip_add(map, &id));
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

static userfw_cmd_descr bitmap_ip_cmds[] =
{
	{CMD_ADD,	2,	{T_UINT16, T_IPv4},	"add",	cmd_add}
	,{CMD_CLEAR,	1,	{T_UINT16},	"clear",	cmd_clear}
};

static userfw_modinfo ipset_bitmap_ip_modinfo =
{
	.id = USERFW_IPSET_BITMAP_IP_MOD,
	.name = "ipset_bitmap_ip",
	.nactions = 0,
	.nmatches = 0,
	.ncmds = sizeof(bitmap_ip_cmds)/sizeof(bitmap_ip_cmds[0]),
	.actions = NULL,
	.matches = NULL,
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
MODULE_DEPEND(userfw_ipset_bitmap_ip, userfw_core, 1, 1, 1);

DECLARE_MODULE(userfw_ipset_bitmap_ip, ipset_bitmap_ip_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD + 1);
