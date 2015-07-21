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

int main(void)
{
	struct nl_sock *nsd;
	uint32_t pid, min = 0, max = 5;
	int family, i;
	struct net_mat_hdr_node *hdr_gph_node;
	struct net_mat_tbl_node *tbl_gph_node;
	struct net_mat_hdr *headers;
	struct net_mat_action *actions;
	struct net_mat_tbl *tables;
	struct net_mat_port *ports;

	nsd = match_nl_get_socket();
	if (!nsd) {
		fprintf(stderr, "Error: socket allocation failed\n");
                return -EINVAL;
	}

	pid = match_pid_lookup();
	if (pid == 0)
                return -EINVAL;

	family = NET_MAT_DFLT_FAMILY;

	fprintf(stderr, "%s: pid %i family %i\n", __func__, pid, family);
	printf("----------------------------------------\n");
	printf("Header Graph:\n");
	printf("----------------------------------------\n");
	headers = match_nl_get_headers(nsd, pid, 0, family);
	if (!headers) {
		fprintf(stderr, "Error: get_headers failed\n");
                return -EINVAL;
	}
	hdr_gph_node = match_nl_get_hdr_graph(nsd, pid, 0, family);
	if (!hdr_gph_node) {
                fprintf(stderr, "Error: get_header_graph failed\n");
                return -EINVAL;
        }
	pp_header_graph(stdout, true, hdr_gph_node);
	printf("\n");

	printf("----------------------------------------\n");
	printf("Table Graph:\n");
	printf("----------------------------------------\n");
	actions = match_nl_get_actions(nsd, pid, 0, family);
	if (!actions) {
                fprintf(stderr, "Error: get_actions failed\n");
                return -EINVAL;
        }
	tables = match_nl_get_tables(nsd, pid, 0, family);
	if (!tables) {
                fprintf(stderr, "Error: get_tables failed\n");
                return -EINVAL;
        }
	match_push_tables_a(tables);
	tbl_gph_node = match_nl_get_tbl_graph(nsd, pid, 0, family);
	if (!tbl_gph_node) {
                fprintf(stderr, "Error: get_table_graph failed\n");
                return -EINVAL;
        }
	pp_table_graph(stdout, true, tbl_gph_node);
	printf("\n");

	printf("----------------------------------------\n");
	printf("Headers:\n");
	printf("----------------------------------------\n");
	headers = match_nl_get_headers(nsd, pid, 0, family);
	if (!headers) {
                fprintf(stderr, "Error: get_headers failed\n");
                return -EINVAL;
        }
	for (i = 0 ; headers[i].uid ; i++)
		pp_header(stdout, true, &headers[i]);
	printf("\n");

	printf("----------------------------------------\n");
	printf("Actions:\n");
	printf("----------------------------------------\n");
	actions = match_nl_get_actions(nsd, pid, 0, family);
	if (!actions) {
                fprintf(stderr, "Error: get_actions failed\n");
                return -EINVAL;
        }
	pp_actions(stdout, true, actions);
	printf("\n");

	printf("----------------------------------------\n");
	printf("Tables:\n");
	printf("----------------------------------------\n");
	headers = match_nl_get_headers(nsd, pid, 0, family);
	if (!headers) {
                fprintf(stderr, "Error: get_headers failed\n");
                return -EINVAL;
        }
	hdr_gph_node = match_nl_get_hdr_graph(nsd, pid, 0, family);
	if (!hdr_gph_node) {
                fprintf(stderr, "Error: get_header_graph failed\n");
                return -EINVAL;
        }
	actions = match_nl_get_actions(nsd, pid, 0, family);
	if (!actions) {
                fprintf(stderr, "Error: get_actions failed\n");
                return -EINVAL;
        }
	tables = match_nl_get_tables(nsd, pid, 0, family);
	if (!tables) {
                fprintf(stderr, "Error: get_tables failed\n");
                return -EINVAL;
        }
	for (i = 0 ; tables[i].uid ; i++)
		pp_table(stdout, true, &tables[i]);
	printf("\n");

	printf("----------------------------------------\n");
	printf("Ports:\n");
	printf("----------------------------------------\n");
	ports = match_nl_get_ports(nsd,pid, 0, family, min, max);
	if (!ports) {
                fprintf(stderr, "Error: get_ports failed\n");
                return -EINVAL;
        }
	pp_ports(stdout, true, ports);

	return 0;
}
