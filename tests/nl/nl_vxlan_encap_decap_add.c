#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/cli/utils.h>

#include "if_match.h"
#include "matchlib.h"
#include "matchlib_nl.h"
#include "../../models/ies_pipeline.h" /* Pipeline model */

#define PRIO 10
#define TCAM_TBL 1
#define TE_TBL_A 2
#define TBL_SIZE 64
#define HOST1_OUTER_IP 0x0100003c
#define HOST2_OUTER_IP 0x0200003c
#define MULTICAST_IP 0x010101ef
#define U24_MASK 0x00ffffff
#define U32_MASK 0xffffffff
#define U64_MASK 0xffffffffffff
#define INNER_DST_MAC 0x2e2fda4f0289
#define INNER_SRC_MAC 0x9a1be527f24d
#define VXLAN_VNI 100

extern struct net_mat_hdr *my_header_list[] __attribute__((unused));
extern struct net_mat_action *my_action_list[] __attribute__((unused));
extern struct net_mat_tbl *my_table_list[] __attribute__((unused));
extern struct net_mat_hdr_node *my_hdr_nodes[] __attribute__((unused));
extern struct net_mat_tbl_node *my_tbl_nodes[] __attribute__((unused));

int main(void)
{
	struct nl_sock *nsd;
	uint32_t pid;
	unsigned int ifindex = 0;
	int family;
	struct net_mat_hdr_node *hdr_gph_node;
	struct net_mat_hdr *headers;
	struct net_mat_action *actions;
	struct net_mat_tbl *tables, tcam_to_te, te_vxlan_encap, te_vxlan_decap;
	struct net_mat_rule te_vxlan_decap_r, tcam_to_te_decap_a, tcam_to_te_decap_b,
			    te_vxlan_encap_a, te_vxlan_encap_b, tcam_to_te_encap_a, tcam_to_te_encap_b;
	int err;


	struct net_mat_field_ref  tcam_to_te_matches[] = {
		{ .instance = HEADER_INSTANCE_ETHERNET,
		  .header = HEADER_ETHERNET,
		  .field = HEADER_ETHERNET_DST_MAC,
		  .mask_type = NET_MAT_MASK_TYPE_MASK},
		{ .instance = HEADER_INSTANCE_ETHERNET,
		  .header = HEADER_ETHERNET,
		  .field = HEADER_ETHERNET_SRC_MAC,
		  .mask_type = NET_MAT_MASK_TYPE_MASK},
		{ .instance = HEADER_INSTANCE_IPV4,
		  .header = HEADER_IPV4,
		  .field = HEADER_IPV4_DST_IP,
		  .mask_type = NET_MAT_MASK_TYPE_MASK},
		{ .instance = HEADER_INSTANCE_UDP,
		  .header = HEADER_UDP,
		  .field = HEADER_UDP_DST_PORT,
		  .mask_type = NET_MAT_MASK_TYPE_MASK},
		{0}};

	__u32 tcam_to_te_actions[] = {ACTION_COUNT,
		ACTION_FORWARD_TO_TE_A, 0};

	struct net_mat_field_ref te_vxlan_encap_matches[] = {
		{ .instance = HEADER_INSTANCE_ETHERNET,
		  .header = HEADER_ETHERNET,
		  .field = HEADER_ETHERNET_DST_MAC,
		  .mask_type = NET_MAT_MASK_TYPE_EXACT},
		{0}};

	__u32 te_vxlan_encap_actions[] = {ACTION_COUNT,
		ACTION_TUNNEL_ENCAP, 0};

	struct net_mat_field_ref te_vxlan_decap_matches[] = {
		{ .instance = HEADER_INSTANCE_VXLAN,
		  .header = HEADER_VXLAN,
		  .field = HEADER_VXLAN_VNI,
		  .mask_type = NET_MAT_MASK_TYPE_EXACT},
		{0}};

	__u32 te_vxlan_decap_actions[] = {ACTION_COUNT,
		ACTION_TUNNEL_DECAP, 0};


	struct net_mat_field_ref te_vxlan_decap_match[] = {
		{ .instance = HEADER_INSTANCE_VXLAN,
		  .header = HEADER_VXLAN,
		  .field = HEADER_VXLAN_VNI,
		  .mask_type = NET_MAT_MASK_TYPE_EXACT,
		  .type =  NET_MAT_FIELD_REF_ATTR_TYPE_U32,
		  .v.u32.value_u32 = VXLAN_VNI,
		  te_vxlan_decap_match->v.u32.mask_u32 = U24_MASK},
		{0}};

	struct net_mat_action  te_vxlan_decap_action[] = {
		{ .name = strdup("count"),
		  .uid = ACTION_COUNT,
		  .args = NULL},
		{ .name = strdup("tunnel_decap"),
		  .uid = ACTION_TUNNEL_DECAP,
		  .args = NULL},
		{0}};

	struct net_mat_field_ref tcam_to_te_decap_match_a[] = {
		{ .instance = HEADER_INSTANCE_IPV4,
		  .header = HEADER_IPV4,
		  .field = HEADER_IPV4_DST_IP,
		  .mask_type = NET_MAT_MASK_TYPE_MASK,
		  .type =  NET_MAT_FIELD_REF_ATTR_TYPE_U32,
		  .v.u32.value_u32 =  MULTICAST_IP,
		  tcam_to_te_decap_match_a->v.u32.mask_u32 = U32_MASK},
		{0}};

	struct net_mat_field_ref tcam_to_te_decap_match_b[] = {
		{ .instance = HEADER_INSTANCE_IPV4,
		  .header = HEADER_IPV4,
		  .field = HEADER_IPV4_DST_IP,
		  .mask_type = NET_MAT_MASK_TYPE_MASK,
		  .type =  NET_MAT_FIELD_REF_ATTR_TYPE_U32,
		  .v.u32.value_u32 = HOST1_OUTER_IP,
		  tcam_to_te_decap_match_b->v.u32.mask_u32 = U32_MASK},
		{0}};

	static struct net_mat_action_arg forward_to_te_args_decap[] = {
		{ .name = forward_to_te_args_str,
		  .type = NET_MAT_ACTION_ARG_TYPE_U16,
		  .v.value_u16 = 31},
		{0}};

	struct net_mat_action tcam_to_te_decap_action[] = {
		{ .name = strdup("count"),
		  .uid = ACTION_COUNT,
		  .args = NULL},
		{ .name = strdup("forward_to_tunnel_engine_A"),
		  .uid = ACTION_FORWARD_TO_TE_A,
		  .args = forward_to_te_args_decap},
		{0}};

	struct net_mat_field_ref ethernet_dst_mac_match_a[] = {
		{ .instance = HEADER_INSTANCE_ETHERNET,
		  .header = HEADER_ETHERNET,
		  .field = HEADER_ETHERNET_DST_MAC,
		  .mask_type = NET_MAT_MASK_TYPE_EXACT,
		  .type =  NET_MAT_FIELD_REF_ATTR_TYPE_U64,
		  .v.u64.value_u64 = INNER_DST_MAC,
		  ethernet_dst_mac_match_a->v.u64.mask_u64 = U64_MASK},
		{0}};

	struct net_mat_field_ref ethernet_dst_mac_match_b[] = {
		{ .instance = HEADER_INSTANCE_ETHERNET,
		  .header = HEADER_ETHERNET,
		  .field = HEADER_ETHERNET_DST_MAC,
		  .mask_type = NET_MAT_MASK_TYPE_EXACT,
		  .type =  NET_MAT_FIELD_REF_ATTR_TYPE_U64,
		  .v.u64.value_u64 = U64_MASK,
		  ethernet_dst_mac_match_b->v.u64.mask_u64 = U64_MASK},
		{0}};
	struct net_mat_field_ref ethernet_src_dst_mac_match[] = {
		{ .instance = HEADER_INSTANCE_ETHERNET,
		  .header = HEADER_ETHERNET,
		  .field = HEADER_ETHERNET_SRC_MAC,
		  .mask_type = NET_MAT_MASK_TYPE_EXACT,
		  .type =  NET_MAT_FIELD_REF_ATTR_TYPE_U64,
		  .v.u64.value_u64 = INNER_SRC_MAC,
		  ethernet_dst_mac_match_b->v.u64.mask_u64 = U64_MASK},
		{ .instance = HEADER_INSTANCE_ETHERNET,
		  .header = HEADER_ETHERNET,
		  .field = HEADER_ETHERNET_DST_MAC,
		  .mask_type = NET_MAT_MASK_TYPE_EXACT,
		  .type =  NET_MAT_FIELD_REF_ATTR_TYPE_U64,
		  .v.u64.value_u64 = U64_MASK,
		  ethernet_src_dst_mac_match->v.u64.mask_u64 = U64_MASK},
		{0}};

	static struct net_mat_action_arg tunnel_encap_args[] = {
		{ .name = dst_ip,
		  .type = NET_MAT_ACTION_ARG_TYPE_U32,
		  .v.value_u32 = HOST2_OUTER_IP},
		{ .name = src_ip,
		  .type = NET_MAT_ACTION_ARG_TYPE_U32,
		  .v.value_u32 = HOST1_OUTER_IP},
		{ .name = vni,
		  .type = NET_MAT_ACTION_ARG_TYPE_U32,
		  .v.value_u32 = VXLAN_VNI},
		{ .name = src_port,
		  .type = NET_MAT_ACTION_ARG_TYPE_U16,
		  .v.value_u16 = 0},
		{ .name = dst_port,
		  .type = NET_MAT_ACTION_ARG_TYPE_U16,
		  .v.value_u16 = 4789},
		{0}};
	struct net_mat_action te_vxlan_encap_action[] = {
		{ .name = strdup("count"),
		  .uid = ACTION_COUNT,
		  .args = NULL},
		{ .name = strdup("tunnel_encap"),
		  .uid = ACTION_TUNNEL_ENCAP,
		  .args = tunnel_encap_args},
		{0}};

	static struct net_mat_action_arg forward_to_te_args_encap[] = {
		{ .name = forward_to_te_args_str,
		  .type = NET_MAT_ACTION_ARG_TYPE_U16,
		  .v.value_u16 = 30},
		{0}};

	struct net_mat_action tcam_to_te_encap_action[] = {
		{ .name = strdup("count"),
		  .uid = ACTION_COUNT,
		  .args = NULL},
		{ .name = strdup("forward_to_tunnel_engine_A"),
		  .uid = ACTION_FORWARD_TO_TE_A,
		  .args = forward_to_te_args_encap},
		{0}};



	nsd = match_nl_get_socket();
	if (!nsd) {
		fprintf(stderr, "Error: socket allocation failed\n");
		return -EINVAL;
	}

	pid = match_pid_lookup();
	if (pid == 0)
		return -EINVAL;

	family = NET_MAT_DFLT_FAMILY;

	headers = match_nl_get_headers(nsd, pid, ifindex, family);
	if (!headers) {
		fprintf(stderr, "Error: get_headers failed\n");
		return -EINVAL;
	}
	hdr_gph_node = match_nl_get_hdr_graph(nsd, pid, 0, family);
	if (!hdr_gph_node) {
		fprintf(stderr, "Error: get_header_graph failed\n");
		free(headers);
		return -EINVAL;
	}
	actions = match_nl_get_actions(nsd, pid, ifindex, family);
	if (!actions) {
		fprintf(stderr, "Error: get_actions failed\n");
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	match_push_actions_ary(actions);
	tables = match_nl_get_tables(nsd, pid, ifindex, family);
	if (!tables) {
		fprintf(stderr, "Error: get_tables failed\n");
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	match_push_tables_a(tables);


	printf("\n");
	printf("encap & decap tables\n");
	printf("--------------------\n");
	/* Create TCAM table */
	//tcam_to_te.name =  strndup("tcam-to-te", NET_MAT_MAXNAME);
	tcam_to_te.name =  strdup("tcam-to-te");
	tcam_to_te.uid = 20; /* API defined */
	tcam_to_te.source = TCAM_TBL;
	tcam_to_te.size = TBL_SIZE;
	tcam_to_te.attribs = NULL;
	tcam_to_te.matches = tcam_to_te_matches;
	tcam_to_te.actions = tcam_to_te_actions;
	err = match_nl_create_table(nsd, pid, ifindex, family, &tcam_to_te);
	if (err) {
		printf("Create table failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	pp_table(stdout, true, &tcam_to_te);
	printf("\n");

	/* Create encap	 table */
	te_vxlan_encap.name = strdup("te-vxlan-encap");
	te_vxlan_encap.uid = 30;
	te_vxlan_encap.source = TE_TBL_A;
	te_vxlan_encap.size = TBL_SIZE;
	te_vxlan_encap.attribs = NULL;
	te_vxlan_encap.matches = te_vxlan_encap_matches;
	te_vxlan_encap.actions = te_vxlan_encap_actions;
	err = match_nl_create_table(nsd, pid, ifindex, family, &te_vxlan_encap);
	if (err) {
		printf("Create table failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	pp_table(stdout, true, &te_vxlan_encap);
	printf("\n");

	/* Create decap table */
	te_vxlan_decap.name = strdup("te-vxlan-decap");
	te_vxlan_decap.uid = 31;
	te_vxlan_decap.source = TE_TBL_A;
	te_vxlan_decap.size = TBL_SIZE;
	te_vxlan_decap.attribs = NULL;
	te_vxlan_decap.matches = te_vxlan_decap_matches;
	te_vxlan_decap.actions = te_vxlan_decap_actions;
	err = match_nl_create_table(nsd, pid, ifindex, family, &te_vxlan_decap);
	if (err) {
		printf("Create table failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	pp_table(stdout, true, &te_vxlan_decap);
	printf("\n");


	printf("\n");
	printf("decap rules\n");
	printf("-----------\n");
	/* Set decap rules */
	te_vxlan_decap_r.table_id = 31; /* 'table' in the match-tool */
	te_vxlan_decap_r.uid = 1;         /* 'handle' in the match-tool */
	te_vxlan_decap_r.priority = PRIO;
	te_vxlan_decap_r.matches = te_vxlan_decap_match;
	te_vxlan_decap_r.actions = te_vxlan_decap_action;
	err = match_nl_set_rules(nsd, pid, ifindex, family, &te_vxlan_decap_r);
	if (err) {
		printf("Set rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");


	tcam_to_te_decap_a.table_id = 20;
	tcam_to_te_decap_a.uid = 5;
	tcam_to_te_decap_a.priority = PRIO;
	tcam_to_te_decap_a.matches = tcam_to_te_decap_match_a;
	tcam_to_te_decap_a.actions = tcam_to_te_decap_action;
	err = match_nl_set_rules(nsd, pid, ifindex, family, &tcam_to_te_decap_a);
	if (err) {
		printf("Set rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");


	tcam_to_te_decap_b.table_id = 20;
	tcam_to_te_decap_b.uid = 4;
	tcam_to_te_decap_b.priority = PRIO;
	tcam_to_te_decap_b.matches = tcam_to_te_decap_match_b;
	tcam_to_te_decap_b.actions = tcam_to_te_decap_action;
	err = match_nl_set_rules(nsd, pid, ifindex, family, &tcam_to_te_decap_b);
	if (err) {
		printf("Set rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");


	printf("\n");
	printf("encap rules\n");
	printf("-----------\n");
	/* Set encap rules */
	te_vxlan_encap_a.table_id = 30;
	te_vxlan_encap_a.uid = 1;
	te_vxlan_encap_a.priority = PRIO;
	te_vxlan_encap_a.matches = ethernet_dst_mac_match_a;
	te_vxlan_encap_a.actions = te_vxlan_encap_action;
	err = match_nl_set_rules(nsd, pid, ifindex, family, &te_vxlan_encap_a);
	if (err) {
		printf("Set rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");


	te_vxlan_encap_b.table_id = 30;
	te_vxlan_encap_b.uid = 2;
	te_vxlan_encap_b.priority = PRIO;
	te_vxlan_encap_b.matches = ethernet_dst_mac_match_b;
	te_vxlan_encap_b.actions = te_vxlan_encap_action;
	err = match_nl_set_rules(nsd, pid, ifindex, family, &te_vxlan_encap_b);
	if (err) {
		printf("Set rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");


	tcam_to_te_encap_a.table_id = 20;
	tcam_to_te_encap_a.uid = 1;
	tcam_to_te_encap_a.priority = PRIO;
	tcam_to_te_encap_a.matches = ethernet_dst_mac_match_a;
	tcam_to_te_encap_a.actions = tcam_to_te_encap_action;
	err = match_nl_set_rules(nsd, pid, ifindex, family, &tcam_to_te_encap_a);
	if (err) {
		printf("Set rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");


	tcam_to_te_encap_b.table_id = 20;
	tcam_to_te_encap_b.uid = 2;
	tcam_to_te_encap_b.priority = PRIO;
	tcam_to_te_encap_b.matches = ethernet_src_dst_mac_match;
	tcam_to_te_encap_b.actions = tcam_to_te_encap_action;
	err = match_nl_set_rules(nsd, pid, ifindex, family, &tcam_to_te_encap_b);
	if (err) {
		printf("Set rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");

	free(tables);
	free(actions);
	free(hdr_gph_node);
	free(headers);

	return 0;
}
