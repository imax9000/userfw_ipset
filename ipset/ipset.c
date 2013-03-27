#include <sys/param.h>
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <userfw/module.h>
#include <userfw/io.h>
#include "ipset.h"

static userfw_action_descr ipset_actions[] =
{
};

static userfw_match_descr ipset_matches[] =
{
};

static userfw_cmd_descr ipset_cmds[] =
{
};

static userfw_modinfo ipset_modinfo =
{
	.id = USERFW_IPSET_MOD,
	.name = "ipset",
	.nactions = sizeof(ipset_actions)/sizeof(ipset_actions[0]),
	.nmatches = sizeof(ipset_matches)/sizeof(ipset_matches[0]),
	.ncmds = sizeof(ipset_cmds)/sizeof(ipset_cmds[0]),
	.actions = ipset_actions,
	.matches = ipset_matches,
	.cmds = ipset_cmds
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
