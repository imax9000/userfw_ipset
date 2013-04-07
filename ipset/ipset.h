#ifndef USERFW_IPSET_H
#define USERFW_IPSET_H

#include <sys/types.h>
#include <sys/malloc.h>

MALLOC_DECLARE(M_USERFW_IPSET);

#define USERFW_IPSET_MOD	1364411641

enum ipset_cmds
{
    CMD_NOOP
};

enum ipset_actions
{
    A_NOOP
};

enum ipset_matches
{
    M_NOOP
};

#endif /* USERFW_IPSET_H */
