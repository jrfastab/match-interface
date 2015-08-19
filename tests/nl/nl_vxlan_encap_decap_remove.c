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
	printf("delete encap rules\n");
	printf("------------------\n");
	memset(&tcam_to_te_encap_b, 0, sizeof(tcam_to_te_encap_b));
	tcam_to_te_encap_b.table_id = 20;
	tcam_to_te_encap_b.uid = 2;
	tcam_to_te_encap_b.priority = PRIO;
	err = match_nl_del_rules(nsd, pid, ifindex, family, &tcam_to_te_encap_b);
	if (err) {
		printf("Delete rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");

	memset(&tcam_to_te_encap_a, 0, sizeof(tcam_to_te_encap_a));
	tcam_to_te_encap_a.table_id = 20;
	tcam_to_te_encap_a.uid = 1;
	tcam_to_te_encap_a.priority = PRIO;
	err = match_nl_del_rules(nsd, pid, ifindex, family, &tcam_to_te_encap_a);
	if (err) {
		printf("Delete rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");

	memset(&te_vxlan_encap_b, 0, sizeof(te_vxlan_encap_b));
	te_vxlan_encap_b.table_id = 30;
	te_vxlan_encap_b.uid = 2;
	te_vxlan_encap_b.priority = PRIO;
	err = match_nl_del_rules(nsd, pid, ifindex, family, &te_vxlan_encap_b);
	if (err) {
		printf("Delete rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");

	memset(&te_vxlan_encap_a, 0, sizeof(te_vxlan_encap_a));
	te_vxlan_encap_a.table_id = 30;
	te_vxlan_encap_a.uid = 1;
	te_vxlan_encap_a.priority = PRIO;
	err = match_nl_del_rules(nsd, pid, ifindex, family, &te_vxlan_encap_a);
	if (err) {
		printf("Delete rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");

	printf("delete decap rules\n");
	printf("------------------\n");
	memset(&tcam_to_te_decap_b, 0, sizeof(tcam_to_te_decap_b));
	tcam_to_te_decap_b.table_id = 20;
	tcam_to_te_decap_b.uid = 4;
	tcam_to_te_decap_b.priority = PRIO;
	err = match_nl_del_rules(nsd, pid, ifindex, family, &tcam_to_te_decap_b);
	if (err) {
		printf("Delete rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");

	memset(&tcam_to_te_decap_a, 0, sizeof(tcam_to_te_decap_a));
	tcam_to_te_decap_a.table_id = 20;
	tcam_to_te_decap_a.uid = 5;
	tcam_to_te_decap_a.priority = PRIO;
	err = match_nl_del_rules(nsd, pid, ifindex, family, &tcam_to_te_decap_a);
	if (err) {
		printf("Delete rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");

	memset(&te_vxlan_decap_r, 0, sizeof(te_vxlan_decap_r));
	te_vxlan_decap_r.table_id = 31;
	te_vxlan_decap_r.uid = 1;
	te_vxlan_decap_r.priority = PRIO;
	err = match_nl_del_rules(nsd, pid, ifindex, family, &te_vxlan_decap_r);
	if (err) {
		printf("Delete rule failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		return -EINVAL;
	}
	printf("\n");


	/* Destroy decap table */
	printf("destroy decap & encap tables\n");
	printf("----------------------------\n");
	memset(&te_vxlan_decap, 0, sizeof(te_vxlan_decap));
	te_vxlan_decap.name = strdup("te-vxlan-decap");
	te_vxlan_decap.uid = 31;
	te_vxlan_decap.source = TE_TBL_A;
	err = match_nl_destroy_table(nsd, pid, ifindex, family, &te_vxlan_decap);
	if (err) {
		printf("Destroy table failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		free(te_vxlan_decap.name);
		return -EINVAL;
	}
	pp_table(stdout, true, &te_vxlan_decap);
	free(te_vxlan_decap.name);
	printf("\n");


	/* Destroy encap table */
	memset(&te_vxlan_encap, 0, sizeof(te_vxlan_encap));
	te_vxlan_encap.name = strdup("te-vxlan-encap");
	te_vxlan_encap.uid = 30;
	te_vxlan_encap.source = TE_TBL_A;
	err = match_nl_destroy_table(nsd, pid, ifindex, family, &te_vxlan_encap);
	if (err) {
		printf("Destroy table failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		free(te_vxlan_encap.name);
		return -EINVAL;
	}
	pp_table(stdout, true, &te_vxlan_encap);
	free(te_vxlan_encap.name);
	printf("\n");

	/* Destroy TCAM table */
	memset(&tcam_to_te, 0, sizeof(tcam_to_te));
	tcam_to_te.name = strdup("tcam-to-te");
	tcam_to_te.uid = 20;
	tcam_to_te.source = TCAM_TBL;
	err = match_nl_destroy_table(nsd, pid, ifindex, family, &tcam_to_te);
	if (err) {
		printf("Destroy table failed, err = %i\n", err);
		free(tables);
		free(actions);
		free(hdr_gph_node);
		free(headers);
		free(tcam_to_te.name);
		return -EINVAL;
	}
	pp_table(stdout, true, &tcam_to_te);
	free(tcam_to_te.name);
	printf("\n");
	free(tables);
	free(actions);
	free(hdr_gph_node);
	free(headers);

	return 0;
}
