#ifndef USERFW_IPSET_BITMAP_IP_H
#define USERFW_IPSET_BITMAP_IP_H

#define USERFW_IPSET_BITMAP_IP_MOD	1365195177

enum ipset_bitmap_ip_cmds
{
	CMD_ADD
	,CMD_DELETE
	,CMD_TEST
	,CMD_CLEAR
	,CMD_LIST
	,CMD_CREATE
	,CMD_DESTROY
};

enum ipset_bitmap_ip_actions
{
	A_ADD_SRC
	,A_ADD_DST
	,A_DELETE_SRC
	,A_DELETE_DST
};

enum ipset_bitmap_ip_matches
{
	M_LOOKUP_DST
	,M_LOOKUP_SRC
};

#endif /* USERFW_IPSET_BITMAP_IP_H */
