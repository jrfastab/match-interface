

#include "if_match.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))
#endif /* ARRAY_SIZE */

static char empty[] = "";

enum action_ids {
	ACTION_UNSPEC = 0,
	ACTION_MODIFY_VID,
	ACTION_DROPNCOUNT,
	ACTION_COUNT,
	ACTION_DROP,
};
static char src_modify_vid_str[] = "src";
static struct net_mat_action_arg modify_vid_args[] = {
	{
		.name = src_modify_vid_str,
		.type = NET_MAT_ACTION_ARG_TYPE_U16,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,
	},
};

static char modify_vid_str[] = "modify_vid";

static struct net_mat_action modify_vid = {
	.name = modify_vid_str,
	.uid = ACTION_MODIFY_VID,
	.args = modify_vid_args,
};

static char c_dropncount_str[] = "c";
static char index_dropncount_str[] = "index";
static struct net_mat_action_arg dropncount_args[] = {
	{
		.name = c_dropncount_str,
		.type = NET_MAT_ACTION_ARG_TYPE_U32,
	},
	{
		.name = index_dropncount_str,
		.type = NET_MAT_ACTION_ARG_TYPE_U32,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,
	},
};

static char dropncount_str[] = "dropncount";

static struct net_mat_action dropncount = {
	.name = dropncount_str,
	.uid = ACTION_DROPNCOUNT,
	.args = dropncount_args,
};

static char c_count_str[] = "c";
static char index_count_str[] = "index";
static struct net_mat_action_arg count_args[] = {
	{
		.name = c_count_str,
		.type = NET_MAT_ACTION_ARG_TYPE_U32,
	},
	{
		.name = index_count_str,
		.type = NET_MAT_ACTION_ARG_TYPE_U32,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,
	},
};

static char count_str[] = "count";

static struct net_mat_action count = {
	.name = count_str,
	.uid = ACTION_COUNT,
	.args = count_args,
};

static char drop_str[] = "drop";

static struct net_mat_action drop = {
	.name = drop_str,
	.uid = ACTION_DROP,
	.args = NULL
};

static struct net_mat_action *bpf_action_list[] = {
	&modify_vid,
	&dropncount,
	&count,
	&drop,
	NULL,
};

enum bpf_header_ids {
	HEADER_UNSPEC,
	HEADER_ETHERNETT,
	HEADER_VLANT,
};

static char ethernett_str[] = "ethernett";

enum ies_header_ethernett_ids {
	HEADER_ETHERNETT_UNSPEC = 0,
	HEADER_ETHERNETT_ETHERTYPE,
	HEADER_ETHERNETT_SRCMAC,
	HEADER_ETHERNETT_DSTMAC,
};

static char ethertype_ethernett_str[] = "ethertype";
static char srcmac_ethernett_str[] = "srcmac";
static char dstmac_ethernett_str[] = "dstmac";
static struct net_mat_field ethernett_fields[] = {
	{ .name = ethertype_ethernett_str,
	  .uid = HEADER_ETHERNETT_ETHERTYPE,
	  .bitwidth = 16,},
	{ .name = srcmac_ethernett_str,
	  .uid = HEADER_ETHERNETT_SRCMAC,
	  .bitwidth = 48,},
	{ .name = dstmac_ethernett_str,
	  .uid = HEADER_ETHERNETT_DSTMAC,
	  .bitwidth = 48,},
};

static struct net_mat_hdr ethernett = {
	.name = ethernett_str,
	.uid = HEADER_ETHERNETT,
	.field_sz = ARRAY_SIZE(ethernett_fields),
	.fields = ethernett_fields,
};
static char vlant_str[] = "vlant";

enum ies_header_vlant_ids {
	HEADER_VLANT_UNSPEC = 0,
	HEADER_VLANT_ETHERTYPE,
	HEADER_VLANT_VID,
	HEADER_VLANT_CFI,
	HEADER_VLANT_PCP,
};

static char ethertype_vlant_str[] = "ethertype";
static char vid_vlant_str[] = "vid";
static char cfi_vlant_str[] = "cfi";
static char pcp_vlant_str[] = "pcp";
static struct net_mat_field vlant_fields[] = {
	{ .name = ethertype_vlant_str,
	  .uid = HEADER_VLANT_ETHERTYPE,
	  .bitwidth = 16,},
	{ .name = vid_vlant_str,
	  .uid = HEADER_VLANT_VID,
	  .bitwidth = 12,},
	{ .name = cfi_vlant_str,
	  .uid = HEADER_VLANT_CFI,
	  .bitwidth = 1,},
	{ .name = pcp_vlant_str,
	  .uid = HEADER_VLANT_PCP,
	  .bitwidth = 3,},
};

static struct net_mat_hdr vlant = {
	.name = vlant_str,
	.uid = HEADER_VLANT,
	.field_sz = ARRAY_SIZE(vlant_fields),
	.fields = vlant_fields,
};
static struct net_mat_hdr *bpf_header_list[] = {
	&ethernett,
	&vlant,
	NULL,
};

enum bpf_header_instance {
	HEADER_INSTANCE_UNSPEC,
	HEADER_INSTANCE_LINUXETHERNET,
	HEADER_INSTANCE_LINUXVLAN,
};

enum bpf_table_id {
	TABLE_UNSPEC = 0,
	TABLE_A,
	TABLE_B,
	TABLE_C,
	TABLE_D,
	TABLE_E,
	__TABLE_MAX,
};
#define BPF_MAX_TABLES (__TABLE_MAX - 1)


static char e_str[] = "e";
static __u32 actions_e[] = {ACTION_DROP, 0};
#define TABLE_E_SIZE 4096

static struct net_mat_field_ref matches_e[] = {
	{ .instance = HEADER_INSTANCE_LINUXVLAN,
	  .header = HEADER_VLANT,
	  .field = HEADER_VLANT_VID,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

static struct net_mat_tbl bpf_table_e = {
	.name = e_str,
	.uid = TABLE_E,
	.apply_action = TABLE_E,
	.size = TABLE_E_SIZE,
	.matches = matches_e,
	.actions = actions_e,
};
static char d_str[] = "d";
static __u32 actions_d[] = {ACTION_DROP, 0};
#define TABLE_D_SIZE 2048

static struct net_mat_field_ref matches_d[] = {
	{ .instance = HEADER_INSTANCE_LINUXETHERNET,
	  .header = HEADER_ETHERNETT,
	  .field = HEADER_ETHERNETT_DSTMAC,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = HEADER_INSTANCE_LINUXVLAN,
	  .header = HEADER_VLANT,
	  .field = HEADER_VLANT_VID,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = HEADER_INSTANCE_LINUXVLAN,
	  .header = HEADER_VLANT,
	  .field = HEADER_VLANT_CFI,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

static struct net_mat_tbl bpf_table_d = {
	.name = d_str,
	.uid = TABLE_D,
	.apply_action = TABLE_D,
	.size = TABLE_D_SIZE,
	.matches = matches_d,
	.actions = actions_d,
};
static char c_str[] = "c";
static __u32 actions_c[] = {ACTION_DROP, 0};
#define TABLE_C_SIZE 1024

static struct net_mat_field_ref matches_c[] = {
	{ .instance = HEADER_INSTANCE_LINUXVLAN,
	  .header = HEADER_VLANT,
	  .field = HEADER_VLANT_VID,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

static struct net_mat_tbl bpf_table_c = {
	.name = c_str,
	.uid = TABLE_C,
	.apply_action = TABLE_C,
	.size = TABLE_C_SIZE,
	.matches = matches_c,
	.actions = actions_c,
};
static char b_str[] = "b";
static __u32 actions_b[] = {ACTION_DROP, 0};
#define TABLE_B_SIZE 512

static struct net_mat_field_ref matches_b[] = {
	{ .instance = HEADER_INSTANCE_LINUXETHERNET,
	  .header = HEADER_ETHERNETT,
	  .field = HEADER_ETHERNETT_SRCMAC,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = HEADER_INSTANCE_LINUXVLAN,
	  .header = HEADER_VLANT,
	  .field = HEADER_VLANT_VID,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

static struct net_mat_tbl bpf_table_b = {
	.name = b_str,
	.uid = TABLE_B,
	.apply_action = TABLE_B,
	.size = TABLE_B_SIZE,
	.matches = matches_b,
	.actions = actions_b,
};
static char a_str[] = "a";
static __u32 actions_a[] = {ACTION_DROP, ACTION_COUNT, 0};
#define TABLE_A_SIZE 256

static struct net_mat_field_ref matches_a[] = {
	{ .instance = HEADER_INSTANCE_LINUXVLAN,
	  .header = HEADER_VLANT,
	  .field = HEADER_VLANT_VID,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = HEADER_INSTANCE_LINUXVLAN,
	  .header = HEADER_VLANT,
	  .field = HEADER_VLANT_PCP,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

static struct net_mat_tbl bpf_table_a = {
	.name = a_str,
	.uid = TABLE_A,
	.apply_action = TABLE_A,
	.size = TABLE_A_SIZE,
	.matches = matches_a,
	.actions = actions_a,
};
static struct net_mat_tbl *bpf_table_list[] = {
	&bpf_table_e,
	&bpf_table_d,
	&bpf_table_c,
	&bpf_table_b,
	&bpf_table_a,
	NULL,
};

static struct net_mat_jump_table linuxvlan_jump[] = {
	{ .node = 0, },
};

static struct net_mat_jump_table linuxethernet_jump[] = {
	{
		.node = HEADER_INSTANCE_LINUXVLAN,
		.field = {
			.header = HEADER_ETHERNETT,
			.field = HEADER_ETHERNETT_ETHERTYPE,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 33024,
				.mask_u16 = 0xffff
			}
		},
	},
	{ .node = 0, },
};

static char linuxethernet_str[] = "linuxethernet";
static __u32 linuxethernet_headers[] = {HEADER_ETHERNETT, 0};

static struct net_mat_hdr_node linuxethernet = {
	.name = linuxethernet_str,
	.uid = HEADER_INSTANCE_LINUXETHERNET,
	.hdrs = linuxethernet_headers,
	.jump = linuxethernet_jump,
};

static char linuxvlan_str[] = "linuxvlan";
static __u32 linuxvlan_headers[] = {HEADER_VLANT, 0};

static struct net_mat_hdr_node linuxvlan = {
	.name = linuxvlan_str,
	.uid = HEADER_INSTANCE_LINUXVLAN,
	.hdrs = linuxvlan_headers,
	.jump = linuxvlan_jump,
};

static struct net_mat_hdr_node *bpf_hdr_nodes[] = {
	&linuxvlan,
	&linuxethernet,
	NULL,
};

static struct net_mat_jump_table tbl_node_e_jump[] = {
	{ .field = {0}, .node = 0},
};

static struct net_mat_jump_table tbl_node_c_jump[] = {
	{ .field = {0}, .node = TABLE_E},
	{ .field = {0}, .node = 0},
};

static struct net_mat_jump_table tbl_node_b_jump[] = {
	{ .field = {0}, .node = TABLE_C},
	{ .field = {0}, .node = 0},
};

static struct net_mat_jump_table tbl_node_a_jump[] = {
	{ .field = {0}, .node = TABLE_B},
	{ .field = {0}, .node = 0},
};

static struct net_mat_tbl_node table_node_a = {
	.uid = TABLE_A,
	.flags = 0,
	.jump = tbl_node_a_jump
};
static struct net_mat_tbl_node table_node_b = {
	.uid = TABLE_B,
	.flags = 0,
	.jump = tbl_node_b_jump
};
static struct net_mat_tbl_node table_node_c = {
	.uid = TABLE_C,
	.flags = 0,
	.jump = tbl_node_c_jump
};
static struct net_mat_tbl_node table_node_e = {
	.uid = TABLE_E,
	.flags = 0,
	.jump = tbl_node_e_jump
};
static struct net_mat_tbl_node *bpf_tbl_nodes[] = {
	&table_node_a,
	&table_node_b,
	&table_node_c,
	&table_node_e,
	NULL,
};

