#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <userfw/module.h>
#include <userfw/io.h>
#include "ipset.h"

MALLOC_DEFINE(M_USERFW_IPSET, "userfw_ipset", "Memory used by userfw_ipset modules");

/*
static userfw_modinfo ipset_modinfo =
{
	.id = USERFW_IPSET_MOD,
	.name = "ipset",
	.nactions = 0,
	.nmatches = 0,
	.ncmds = 0,
	.actions = NULL,
	.matches = NULL,
	.cmds = NULL
};

static int
ipset_modevent(module_t mod, int type, void *p)
{
	int err = 0;
	switch(type)
	{
	case MOD_LOAD:
		err = userfw_mod_register(&ipset_modinfo);
		break;
	case MOD_UNLOAD:
		err = userfw_mod_unregister(USERFW_IPSET_MOD);
		break;
	default:
		err = EOPNOTSUPP;
		break;
	}
	return err;
}

static moduledata_t ipset_mod =
{
	"userfw_ipset",
	ipset_modevent,
	0
};

MODULE_VERSION(userfw_ipset, 1);
MODULE_DEPEND(userfw_ipset, userfw_core, 1, 1, 1);

DECLARE_MODULE(userfw_ipset, ipset_mod, SI_SUB_USERFW, SI_ORDER_USERFW_MOD);
*/
