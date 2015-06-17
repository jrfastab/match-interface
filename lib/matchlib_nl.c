/*******************************************************************************

  Netlink wrapper routines
  Author: John Fastabend <john.r.fastabend@intel.com>
  Copyright (c) <2015>, Intel Corporation

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Intel Corporation nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

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
#include <unistd.h>
#include <inttypes.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <getopt.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/route/link.h>

#include <linux/if_ether.h>

#include "if_match.h"
#include "matchlib.h"
#include "matchlib_nl.h"

struct nl_cache *link_cache;
int verbose = 0;
static struct nla_policy match_get_tables_policy[NET_MAT_MAX+1] = {
	[NET_MAT_IDENTIFIER_TYPE] = { .type = NLA_U32 },
	[NET_MAT_IDENTIFIER]	= { .type = NLA_U32 },
	[NET_MAT_TABLES]	= { .type = NLA_NESTED },
	[NET_MAT_HEADERS]	= { .type = NLA_NESTED },
	[NET_MAT_ACTIONS] 	= { .type = NLA_NESTED },
	[NET_MAT_HEADER_GRAPH]	= { .type = NLA_NESTED },
	[NET_MAT_TABLE_GRAPH]	= { .type = NLA_NESTED },
	[NET_MAT_RULES]	= { .type = NLA_NESTED },
};

static void pfprintf(FILE *fp, bool p, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (p)
		vfprintf(fp, format, args);

	va_end(args);
}

void match_nl_free_msg(struct match_msg *msg)
{
	if(msg) {
		if (msg->nlbuf)
			nlmsg_free(msg->nlbuf);
		else
			free(msg->msg);
		free(msg);
	}
}

struct nl_sock *match_nl_get_socket(void)
{
	struct nl_sock *nsd = nl_socket_alloc();

	nl_connect(nsd, NETLINK_GENERIC);

	return nsd;
}

struct net_mat_hdr *match_nl_get_headers(struct nl_sock *nsd, uint32_t pid,
					 unsigned int ifindex, int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_HEADERS;
	struct net_mat_hdr *hdrs = NULL;
	struct match_msg *msg;

	msg = match_nl_get_msg(nsd, cmd, pid, ifindex, family);

	if (msg) {
		struct nlmsghdr *nlh = msg->msg;
		struct nlattr *tb[NET_MAT_MAX+1];
		int err;

		err = genlmsg_parse(nlh, 0, tb,
				    NET_MAT_MAX, match_get_tables_policy);
		if (err < 0) {
			fprintf(stderr, "Warning unable to parse get tables msg\n");
			goto out;
		}

		if (match_nl_table_cmd_to_type(stdout, true,
					      NET_MAT_HEADERS, tb))
			goto out;

		if (tb[NET_MAT_HEADERS])
			match_get_headers(stdout, verbose,
					 tb[NET_MAT_HEADERS], &hdrs);
	}
	match_nl_free_msg(msg);
	return hdrs;
out:
	match_nl_free_msg(msg);
	return NULL;
}

struct net_mat_action *match_nl_get_actions(struct nl_sock *nsd, uint32_t pid,
					    unsigned int ifindex, int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_ACTIONS;
	struct net_mat_action *actions = NULL;
	struct match_msg *msg;

	msg = match_nl_get_msg(nsd, cmd, pid, ifindex, family);

	if (msg) {
		struct nlmsghdr *nlh = msg->msg;
		struct nlattr *tb[NET_MAT_MAX+1];
		int err;

		err = genlmsg_parse(nlh, 0, tb,
				    NET_MAT_MAX, match_get_tables_policy);
		if (err < 0) {
			fprintf(stderr, "Warning unable to parse get tables msg\n");
			goto out;
		}

		if (match_nl_table_cmd_to_type(stdout, true,
					      NET_MAT_ACTIONS, tb))
			goto out;

		if (tb[NET_MAT_ACTIONS])
			match_get_actions(stdout, verbose,
					 tb[NET_MAT_ACTIONS], &actions);
	}
	match_nl_free_msg(msg);
	return actions;
out:
	match_nl_free_msg(msg);
	return NULL;
}

struct net_mat_tbl *match_nl_get_tables(struct nl_sock *nsd, uint32_t pid,
					unsigned int ifindex, int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_TABLES;
	struct net_mat_tbl *tables = NULL;
	struct match_msg *msg;

	msg = match_nl_get_msg(nsd, cmd, pid, ifindex, family);

	if (msg) {
		struct nlattr *tb[NET_MAT_MAX+1];
		struct nlmsghdr *nlh = msg->msg;
		int err;

		err = genlmsg_parse(nlh, 0, tb,
				    NET_MAT_MAX, match_get_tables_policy);
		if (err < 0) {
			fprintf(stderr, "Warning unable to parse get tables msg\n");
			goto out;
		}

		if (match_nl_table_cmd_to_type(stdout, true,
					      NET_MAT_TABLES, tb))
			goto out;

		if (tb[NET_MAT_TABLES])
			match_get_tables(stdout, verbose,
					tb[NET_MAT_TABLES], &tables);
	}
	match_nl_free_msg(msg);
	return tables;
out:
	match_nl_free_msg(msg);
	return NULL;
}

struct net_mat_hdr_node *match_nl_get_hdr_graph(struct nl_sock *nsd,
						uint32_t pid,
						unsigned int ifindex,
						int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_HDR_GRAPH;
	struct net_mat_hdr_node *hdr_nodes = NULL;
	struct match_msg *msg;

	msg = match_nl_get_msg(nsd, cmd, pid, ifindex, family);

	if (msg) {
		struct nlmsghdr *nlh = msg->msg;
		struct nlattr *tb[NET_MAT_MAX+1];
		int err;

		err = genlmsg_parse(nlh, 0, tb,
				    NET_MAT_MAX, match_get_tables_policy);
		if (err < 0) {
			fprintf(stderr, "Warning unable to parse get tables msg\n");
			goto out;
		}

		if (match_nl_table_cmd_to_type(stdout, true,
					      NET_MAT_HEADER_GRAPH, tb))
			goto out;

		if (tb[NET_MAT_HEADER_GRAPH])
			match_get_hdrs_graph(stdout, verbose,
					    tb[NET_MAT_HEADER_GRAPH],
					    &hdr_nodes);
	}
	match_nl_free_msg(msg);
	return hdr_nodes;
out:
	match_nl_free_msg(msg);
	return NULL;
}

struct net_mat_tbl_node *match_nl_get_tbl_graph(struct nl_sock *nsd,
						uint32_t pid,
						unsigned int ifindex,
						int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_TABLE_GRAPH;
	struct net_mat_tbl_node *nodes = NULL;
	struct match_msg *msg;

	msg = match_nl_get_msg(nsd, cmd, pid, ifindex, family);

	if (msg) {
		struct nlmsghdr *nlh = msg->msg;
		struct nlattr *tb[NET_MAT_MAX+1];
		int err;

		err = genlmsg_parse(nlh, 0, tb,
				    NET_MAT_MAX, match_get_tables_policy);
		if (err < 0) {
			fprintf(stderr, "Warning unable to parse get tables msg\n");
			goto out;
		}

		if (match_nl_table_cmd_to_type(stdout, true,
					      NET_MAT_TABLE_GRAPH, tb))
			goto out;

		if (tb[NET_MAT_TABLE_GRAPH])
			match_get_tbl_graph(stdout, verbose,
					   tb[NET_MAT_TABLE_GRAPH], &nodes);
	}
	match_nl_free_msg(msg);
	return nodes;
out:
	match_nl_free_msg(msg);
	return NULL;
}

int match_nl_set_del_rules(struct nl_sock *nsd, uint32_t pid,
		      unsigned int ifindex, int family,
		      struct net_mat_rule *rule, uint8_t cmd)
{
	struct nlattr *tb[NET_MAT_MAX+1];
	struct match_msg *msg;
	struct nlmsghdr *nlh;
	struct nlattr *rules;
	sigset_t bs;
	int err = 0;

	pp_rule(stdout, true, rule);

	msg = match_nl_alloc_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMSG;
	}

	if (nla_put_u32(msg->nlbuf,
			NET_MAT_IDENTIFIER_TYPE,
			NET_MAT_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg->nlbuf, NET_MAT_IDENTIFIER, ifindex)) {
		fprintf(stderr, "Error: Identifier put failed\n");
		match_nl_free_msg(msg);
		return -EMSGSIZE;
	}

	err = match_put_rule_error(msg->nlbuf, NET_MAT_RULES_ERROR_CONT_LOG);
	if (err) {
		match_nl_free_msg(msg);
		return err;
	}

	rules = nla_nest_start(msg->nlbuf, NET_MAT_RULES);
	if (!rules) {
		match_nl_free_msg(msg);
		return -EMSGSIZE;
	}
	match_put_rule(msg->nlbuf, rule);
	nla_nest_end(msg->nlbuf, rules);

	nl_send_auto(nsd, msg->nlbuf);
	match_nl_free_msg(msg);

	/* message sent handle recv */
	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);

	msg = match_nl_recv_msg(nsd, &err);
	sigprocmask(SIG_BLOCK, &bs, NULL);

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;
	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse set rules msg\n");
		match_nl_free_msg(msg);
		return err;
	}

	err = match_nl_table_cmd_to_type(stdout, true, 0, tb);
	if (err) {
		match_nl_free_msg(msg);
		return err;
	}

	if (tb[NET_MAT_RULES]) {
		fprintf(stderr, "Failed to set:\n");
		match_get_rules(stdout, verbose, tb[NET_MAT_RULES], NULL);
		match_nl_free_msg(msg);
		return -EINVAL;
	}
	match_nl_free_msg(msg);
	return 0;
}

struct net_mat_rule *match_nl_get_rules(struct nl_sock *nsd, uint32_t pid,
                      unsigned int ifindex, int family,
                      uint32_t tableid, uint32_t min, uint32_t max)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_RULES;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_rule *rule = NULL;
	struct match_msg *msg;
	struct nlmsghdr *nlh;
	struct nlattr *rules;
	sigset_t bs;
	int err = 0;

	msg = match_nl_alloc_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return NULL;
	}

	if (nla_put_u32(msg->nlbuf,
                        NET_MAT_IDENTIFIER_TYPE,
                        NET_MAT_IDENTIFIER_IFINDEX) ||
		nla_put_u32(msg->nlbuf, NET_MAT_IDENTIFIER, ifindex)) {
		fprintf(stderr, "Error: Identifier put failed\n");
		goto out;
	}

	err = match_put_rule_error(msg->nlbuf, NET_MAT_RULES_ERROR_CONT_LOG);
	if (err)
		goto out;

	rules = nla_nest_start(msg->nlbuf, NET_MAT_RULES);
	if (!rules) {
		fprintf(stderr, "Error: get_rules attributes failed\n");
		goto out;
	}
	err = nla_put_u32(msg->nlbuf, NET_MAT_TABLE_RULES_TABLE, tableid);
	if (err) {
		fprintf(stderr, "Error: invalid table\n");
		goto out;
	}
	if (min > 0) {
		err = nla_put_u32(msg->nlbuf, NET_MAT_TABLE_RULES_MINPRIO,
                                min);
		if (err) {
			fprintf(stderr, "Error: invalid min parameter\n");
			goto out;
		}
	}
	if (max > 0) {
		err = nla_put_u32(msg->nlbuf, NET_MAT_TABLE_RULES_MAXPRIO,
                                max);
		if (err) {
			fprintf(stderr, "Error: invalid min parameter\n");
			goto out;
		}
	}
	nla_nest_end(msg->nlbuf, rules);
	nl_send_auto(nsd, msg->nlbuf);
	match_nl_free_msg(msg);

	/* message sent handle recv */
	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);

	msg = match_nl_recv_msg(nsd, &err);
	sigprocmask(SIG_BLOCK, &bs, NULL);
	if (msg) {
		nlh = msg->msg;
		err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
		if (err < 0) {
			fprintf(stderr, "Warning unable to parse get rules msg\n");
			goto out;
		}

		if (match_nl_table_cmd_to_type(stdout, true,
                                              NET_MAT_RULES, tb))
                        goto out;

		if (tb[NET_MAT_RULES]) {
			err = match_get_rules(stdout, verbose, tb[NET_MAT_RULES], &rule);
			if (err)
				goto out;
		}
	}
	match_nl_free_msg(msg);
	return rule;
out:
	match_nl_free_msg(msg);
	return NULL;
}
struct net_mat_port *match_nl_get_ports(struct nl_sock *nsd, uint32_t pid,
                      unsigned int ifindex, int family, uint32_t min, uint32_t max)
{
	uint8_t cmd = NET_MAT_PORT_CMD_GET_PORTS;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_port *port = NULL;
	struct match_msg *msg;
	struct nlmsghdr *nlh;
	struct nlattr *ports;
	sigset_t bs;
	int err = 0;

	msg = match_nl_alloc_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return NULL;
	}

	if (nla_put_u32(msg->nlbuf,
                        NET_MAT_IDENTIFIER_TYPE,
                        NET_MAT_IDENTIFIER_IFINDEX) ||
		nla_put_u32(msg->nlbuf, NET_MAT_IDENTIFIER, ifindex)) {
		fprintf(stderr, "Error: Identifier put failed\n");
		goto out;
	}
	err = match_put_rule_error(msg->nlbuf, NET_MAT_RULES_ERROR_CONT_LOG);
	if (err)
		goto out;

	ports = nla_nest_start(msg->nlbuf, NET_MAT_PORTS);
	if (!ports) {
		fprintf(stderr, "Error: get_port attributes failed\n");
		goto out;
	}
	if (min) {
		err = nla_put_u32(msg->nlbuf, NET_MAT_PORT_MIN_INDEX,
                                min);
		if (err)
			goto out;
	}
	if (max) {
		err = nla_put_u32(msg->nlbuf, NET_MAT_PORT_MAX_INDEX,
                                max);
		if (err)
			goto out;
	}
	nla_nest_end(msg->nlbuf, ports);
	nl_send_auto(nsd, msg->nlbuf);
	match_nl_free_msg(msg);

	/* message sent handle recv */
	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);

	msg = match_nl_recv_msg(nsd, &err);
	sigprocmask(SIG_BLOCK, &bs, NULL);
	if (msg) {
		nlh = msg->msg;
		err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
		if (err < 0) {
			fprintf(stderr, "Warning unable to parse get rules msg\n");
			goto out;
		}

		if (match_nl_table_cmd_to_type(stdout, true,
                                              NET_MAT_PORTS, tb))
                        goto out;

		if (tb[NET_MAT_PORTS]) {
			err = match_get_ports(stdout, verbose, tb[NET_MAT_PORTS], &port);
			if (err)
				goto out;
		}
	}
	match_nl_free_msg(msg);
	return port;
out:
	match_nl_free_msg(msg);
	return NULL;
}

int match_nl_create_update_destroy_table(struct nl_sock *nsd, uint32_t pid,
				unsigned int ifindex, int family,
				struct net_mat_tbl *table, uint8_t cmd)
{
	struct nlattr *tb[NET_MAT_MAX+1];
	struct nlattr *nest, *nest1;
	struct nlmsghdr *nlh;
	struct match_msg *msg;
	sigset_t bs;
	int err = 0;

	msg = match_nl_alloc_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMSG;
	}

	if (nla_put_u32(msg->nlbuf,
			NET_MAT_IDENTIFIER_TYPE,
			NET_MAT_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg->nlbuf, NET_MAT_IDENTIFIER, ifindex)) {
		fprintf(stderr, "Error: Identifier put failed\n");
		match_nl_free_msg(msg);
		return -EMSGSIZE;
	}

	nest = nla_nest_start(msg->nlbuf, NET_MAT_TABLES);
	if (!nest) {
		match_nl_free_msg(msg);
		return -EMSGSIZE;
	}
	nest1 = nla_nest_start(msg->nlbuf, NET_MAT_TABLE);
	match_put_table(msg->nlbuf, table);
	nla_nest_end(msg->nlbuf, nest1);
	nla_nest_end(msg->nlbuf, nest);
	nl_send_auto(nsd, msg->nlbuf);
	match_nl_free_msg(msg);

	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);

	msg = match_nl_recv_msg(nsd, &err);
	sigprocmask(SIG_BLOCK, &bs, NULL);

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;
	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		fprintf(stderr, "Warning unable to parse create table msg\n");
		match_nl_free_msg(msg);
		return err;
	}
	match_nl_free_msg(msg);
	return 0;
}

uint32_t match_nl_find_header(struct net_mat_hdr *hdr,
			     struct net_mat_hdr *search)
{
	uint32_t i, j;

	for (i = 0; search[i].uid; i++) {
		if (hdr->field_sz != search[i].field_sz)
			continue;

		for (j = 0; j < hdr->field_sz; j++) {
			if (hdr->fields[j].bitwidth != search[i].fields[j].bitwidth)
				continue;
		}

		if (j == hdr->field_sz)
			return search[i].uid;
	}
	return 0;
}

uint32_t match_nl_find_action_by_name(char *name, struct net_mat_action *acts)
{
	uint32_t i;

	for (i = 0; acts[i].uid; i++) {
		if (strcmp(name, acts[i].name) == 0)
			return acts[i].uid;
	}

	return 0;
}

uint32_t match_nl_find_instance(struct net_mat_hdr_node *graph,
			       uint32_t uid, uint32_t next)
{
	uint32_t i, j;

	for (i = 0; graph[i].uid; i++) {
		if (graph[i].uid < next)
			continue;

		for (j = 0; graph[i].hdrs[j]; j++) {
			if (graph[i].hdrs[j] != uid)
				continue;

			return graph[i].uid;
		}
	}

	return 0;
}

uint32_t match_nl_find_table_with_action(struct net_mat_tbl *tbls,
					uint32_t action, uint32_t next)
{
	uint32_t i, j;

	for (i = 0; tbls[i].uid; i++) {
		if (i < next)
			continue;

		for (j = 0; tbls[i].actions[j]; j++) {
			if (tbls[i].actions[j] == action)
				return tbls[i].uid;
		}
	}

	return 0;
}

struct match_msg *match_nl_wrap_msg(struct nlmsghdr *buf)
{
	struct match_msg *msg;

	msg = (struct match_msg *) malloc(sizeof(struct match_msg));
	if (msg) {
		msg->msg = buf;
		msg->nlbuf = NULL;
	}

	return msg;
}

static void match_nl_handle_error(struct nlmsgerr *errmsg)
{
	fprintf(stderr, "Error processing request: %s\n",
		strerror(errmsg->error));
}

struct match_msg *match_nl_recv_msg(struct nl_sock *nsd, int *err)
{
	static unsigned char *buf;
	struct match_msg *msg;
	struct genlmsghdr *glm;
	struct sockaddr_nl nla;
	int type;
	int rc;

	*err = 0;

	do {
		rc = nl_recv(nsd, &nla, &buf, NULL);
		if (rc < 0) {
			switch (errno) {
			case EINTR:
				return NULL;
			default:
				perror("Receive operation failed:");
				return NULL;
			}
		}
	} while (rc == 0);

	msg = match_nl_wrap_msg((struct nlmsghdr *)buf);
	if (!msg) {
		fprintf(stderr, "Error: Message is empty\n");
		free(buf);
		return NULL;
	}
	type = ((struct nlmsghdr *)msg->msg)->nlmsg_type;

	/*
	 * Note the NLMSG_ERROR is overloaded
	 * Its also used to deliver ACKs
	 */
	if (type == NLMSG_ERROR) {
		struct nlmsgerr *errm = nlmsg_data(msg->msg);

		if (errm->error) {
			match_nl_handle_error(errm);
			match_nl_free_msg(msg);
			return NULL;
		}

		match_nl_free_msg(msg);
		return NULL;
	}

	glm = nlmsg_data(msg->msg);
	type = glm->cmd;

	if (type < 0 || type > NET_MAT_CMD_MAX) {
		fprintf(stderr, "Received message of unknown type %d\n", type);
		match_nl_free_msg(msg);
		return NULL;
	}

	return msg;
}

int match_nl_table_cmd_to_type(FILE *fp, bool print, int valid,
			      struct nlattr *tb[])
{
	unsigned int type, ifindex;
	int err;
	char iface[IFNAMSIZ];
	struct nl_sock *fd = NULL;

	if (!tb[NET_MAT_IDENTIFIER_TYPE]) {
		fprintf(stderr,
			"Warning: received rule msg without identifier type!\n");
		return -EINVAL;
	}
	if (!tb[NET_MAT_IDENTIFIER]) {
		fprintf(stderr,
			"Warning: received rule msg without identifier!\n");
		return -EINVAL;
	}

	if (valid > 0 && !tb[valid]) {
		fprintf(stderr, "Warning received cmd without valid attribute expected %i\n", valid);
		return -ENOMSG;
	}

	if (nla_len(tb[NET_MAT_IDENTIFIER_TYPE]) < (int)sizeof(type)) {
		fprintf(stderr, "Warning invalid identifier type len\n");
		return -EINVAL;
	}

	type = nla_get_u32(tb[NET_MAT_IDENTIFIER_TYPE]);

	switch (type) {
	case NET_MAT_IDENTIFIER_IFINDEX:
		fd = nl_socket_alloc();
		err = nl_connect(fd, NETLINK_ROUTE);
		if (err < 0) {
			fprintf(stderr,"Warning: Unable to connect socket\n");
			break;
		}
		err = rtnl_link_alloc_cache(fd, AF_UNSPEC, &link_cache);
		if (err < 0) {
			fprintf(stderr,"Warning: Unable to allocate cache\n");
			break;
		}
		ifindex = nla_get_u32(tb[NET_MAT_IDENTIFIER]);
		rtnl_link_i2name(link_cache, (int)ifindex, iface, IFNAMSIZ);
		pfprintf(fp, print, "%s (%u):\n", iface, ifindex);
		break;
	default:
		fprintf(stderr, "Warning unknown interface identifier type %i\n", type);
		break;
	}

	if (fd) {
                nl_close(fd);
                nl_socket_free(fd);
        }
	return 0;
}

struct match_msg *match_nl_alloc_msg(uint8_t type, uint32_t pid,
				   int flags, int size, int family)
{
	struct match_msg *msg;
	static uint32_t seq = 0;

	msg = (struct match_msg *) malloc(sizeof(struct match_msg));
	if (!msg)
		return NULL;

	msg->nlbuf = nlmsg_alloc();

	msg->msg = genlmsg_put(msg->nlbuf, 0, seq, family, (int)size, flags,
			       type, NET_MAT_GENL_VERSION);

	msg->seq = seq++;

	if (pid) {
		struct nl_msg *nl_msg = msg->nlbuf;
		struct sockaddr_nl nladdr = {
			.nl_family = AF_NETLINK,
			.nl_pid = pid,
			.nl_groups = 0,
		};

		nlmsg_set_dst(nl_msg, &nladdr);
	}
	return msg;
}

struct match_msg *match_nl_get_msg(struct nl_sock *nsd, uint8_t cmd, uint32_t pid,
				 unsigned int ifindex, int family)
{
	struct match_msg *msg;
	sigset_t bs;
	int err;

	msg = match_nl_alloc_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return NULL;
	}

	nla_put_u32(msg->nlbuf,
		    NET_MAT_IDENTIFIER_TYPE,
		    NET_MAT_IDENTIFIER_IFINDEX);
	nla_put_u32(msg->nlbuf, NET_MAT_IDENTIFIER, ifindex);

	nl_send_auto(nsd, msg->nlbuf);
	match_nl_free_msg(msg);

	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);

	msg = match_nl_recv_msg(nsd, &err);
	sigprocmask(SIG_BLOCK, &bs, NULL);
	return msg;
}

int match_nl_pci_lport(struct nl_sock *nsd, uint32_t pid,
		      unsigned int ifindex, int family,
		      uint8_t bus, uint8_t device, uint8_t function,
		      uint32_t *lport)
{
	struct net_mat_port port = {.pci = {0}, .port_id = 0};
	struct net_mat_port ports[2] = {{0}, {0}};
	uint8_t cmd = NET_MAT_PORT_CMD_GET_LPORT;
	struct net_mat_port *port_query = NULL;
	struct match_msg *msg;
	sigset_t bs;
	int err;

	msg = match_nl_alloc_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		fprintf(stderr, "Error: Allocation failure\n");
		return -ENOMEM;
	}

	if (nla_put_u32(msg->nlbuf,
			NET_MAT_IDENTIFIER_TYPE,
			NET_MAT_IDENTIFIER_IFINDEX) ||
	    nla_put_u32(msg->nlbuf, NET_MAT_IDENTIFIER, ifindex)) {
		match_nl_free_msg(msg);
		return -EMSGSIZE;
	}
	port.pci.bus = bus;
	port.pci.device = device;
	port.pci.function = function;
	ports[0] = port;

	err = match_put_ports(msg->nlbuf, ports);
	if (err) {
		match_nl_free_msg(msg);
		return -EMSGSIZE;
	}

	nl_send_auto(nsd, msg->nlbuf);
	match_nl_free_msg(msg);

	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);

	msg = match_nl_recv_msg(nsd, &err);

	if (msg) {
		struct nlmsghdr *nlh = msg->msg;
		struct nlattr *tb[NET_MAT_MAX+1];
		int err;

		err = genlmsg_parse(nlh, 0, tb,
				    NET_MAT_MAX, match_get_tables_policy);
		if (err < 0) {
			fprintf(stderr, "Warning unable to parse get tables msg\n");
			match_nl_free_msg(msg);
			return -EINVAL;
		}

		if (match_nl_table_cmd_to_type(stdout, true, NET_MAT_PORTS, tb)) {
			match_nl_free_msg(msg);
			return -EINVAL;
		}

		if (tb[NET_MAT_PORTS]) {
			err = match_get_ports(stdout, verbose,
					     tb[NET_MAT_PORTS], &port_query);
			if (err) {
				match_nl_free_msg(msg);
				return -EINVAL;
			}
		}

		if (!port_query) {
			match_nl_free_msg(msg);
			return -EINVAL;
		}

		*lport = port_query[0].port_id;
	}
	match_nl_free_msg(msg);
	free(port_query);
	return 0;
}
