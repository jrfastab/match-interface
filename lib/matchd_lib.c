/*******************************************************************************
  matchd_lib - library for writing backend handler for MATCH Interface 
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

#include <getopt.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/cli/utils.h>

#include <unistd.h>

#include "matlog.h"
#include "if_match.h"
#include "matchlib.h"
#ifdef DEBUG
#include "models/ies_pipeline.h" /* Pipeline model */
#include "ieslib.h" /* ies interface */
extern struct net_mat_hdr *my_header_list[] __attribute__((unused));
extern struct net_mat_action *my_action_list[] __attribute__((unused));
extern struct net_mat_tbl *my_table_list[] __attribute__((unused));
extern struct net_mat_hdr_node *my_hdr_nodes[] __attribute__((unused));
extern struct net_mat_tbl_node *my_tbl_nodes[] __attribute__((unused));
#endif
#include "matchd_lib.h"

#include "backend.h"

#define MATCHD_MOCK_SUPPORT 1

#ifdef MATCHD_MOCK_SUPPORT
/* Allocate a software cache of the match action tables so we can
 * get and set rule entries in software only mode.
 */
#define MAX_MOCK_TABLES	100
struct net_mat_rule *matchd_mock_tables[MAX_MOCK_TABLES + 1];

/* Used as a hook for software cache of match action tables */
struct net_mat_tbl my_dyn_table_list[MAX_MOCK_TABLES];
#endif

/* The family id can be learned either via a kernel query or by
 * specifying the id on the command line.
 */
static int family = -1;
static struct nl_sock *nsd;

static struct match_backend *backend = NULL;

static struct nla_policy match_get_tables_policy[NET_MAT_MAX+1] = {
	[NET_MAT_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[NET_MAT_IDENTIFIER]		= { .type = NLA_U32 },
	[NET_MAT_TABLES]		= { .type = NLA_NESTED },
	[NET_MAT_HEADERS]		= { .type = NLA_NESTED },
	[NET_MAT_ACTIONS] 		= { .type = NLA_NESTED },
	[NET_MAT_HEADER_GRAPH]		= { .type = NLA_NESTED },
	[NET_MAT_TABLE_GRAPH] 		= { .type = NLA_NESTED },
	[NET_MAT_RULES]		= { .type = NLA_NESTED },
	[NET_MAT_RULES_ERROR]		= { .type = NLA_NESTED },
	[NET_MAT_PORTS]		= { .type = NLA_NESTED },
};

static struct nl_msg *match_alloc_msg(struct nlmsghdr *nlh, uint8_t type, uint16_t flags, int size)
{
	unsigned int seq = nlh->nlmsg_seq;
	unsigned int pid = nlh->nlmsg_pid;
	struct nl_msg *nlbuf = NULL;
	struct nl_sock *fd = NULL;
	void *hdr;

	if (family < 0) {
		/* Get the family */
		fd = nl_socket_alloc();
		genl_connect(fd);
		family = genl_ctrl_resolve(fd, NET_MAT_GENL_NAME);
		if (family < 0) {
			MAT_LOG(ERR,
				"Can not resolve family NET_MAT_TABLE\n");
			nl_close(fd);
			nl_socket_free(fd);
			goto done;
		}
		nl_close(fd);
		nl_socket_free(fd);
	}

	nlbuf = nlmsg_alloc();
	if (!nlbuf)
		goto done;

	hdr = genlmsg_put(nlbuf, 0, seq, family, size, flags, type,
			  NET_MAT_GENL_VERSION);
	if (!hdr) {
		nlmsg_free(nlbuf);
		goto done;
	}

	if (pid) {
		struct sockaddr_nl nladdr = {
			.nl_family = AF_NETLINK,
			.nl_pid = nlh->nlmsg_pid,
			.nl_groups = 0,
		};

		nlmsg_set_dst(nlbuf, &nladdr);
	}
done:
	return nlbuf;
}

/*
 * @struct multipart_head
 * @brief defines the head of a multipart tailq
 */
TAILQ_HEAD(multipart_head, multipart_node);

/*
 * @struct multipart_node
 * @brief defines a node of a multipart tailq
 *
 * @nlbuf the netlink message buffer
 * @entries reference to other entries in the tailq
 */
struct multipart_node {
	struct nl_msg *nlbuf;
	TAILQ_ENTRY(multipart_node) entries;
};

/*
 * free_multipart_msg() - free nlbufs and nodes in a multipart tailq
 * @head: the tailq containing netlink message buffers
 */
static inline void free_multipart_msg(struct multipart_head *head)
{
	struct multipart_node *node;

	TAILQ_FOREACH(node, head, entries) {
		if (node->nlbuf)
			nlmsg_free(node->nlbuf);
		TAILQ_REMOVE(head, node, entries);
		free(node);
	}
}

/*
 * send_done() - send a netlink done message
 * @nlh: netlink message header from request message
 *
 * A NLMSG_DONE message is sent after multipart netlink messages to
 * indicate to the receiver that the multipart message is completed.
 *
 * Return: number of bytes sent on success, or a negative error code
 *         on failure
 */
static int send_done(struct nlmsghdr *nlh)
{
	struct nl_msg *nlbuf = NULL;
	struct sockaddr_nl nladdr;
	uint32_t pid;
	int ret;

	if (nlh == NULL)
		return -EINVAL;

	nlbuf = nlmsg_alloc();
	if (nlbuf == NULL)
		return -ENOMEM;

	pid = nlh->nlmsg_pid;
	if (!nlmsg_put(nlbuf, pid, nlh->nlmsg_seq, NLMSG_DONE, 0, 0)) {
		nlmsg_free(nlbuf);
		return -EMSGSIZE;
	}

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = pid;
	nladdr.nl_groups = 0;

	nlmsg_set_dst(nlbuf, &nladdr);

	ret = nl_send_auto(nsd, nlbuf);
	nlmsg_free(nlbuf);

	return ret;
}

/*
 * send_match_msg() - send a match message stored in a multipart tailq
 * @nlh: the original netlink message request
 * @head: the tailq containing netlink message buffers
 * @multipart: when set, an NLMSG_DONE message will be sent
 *
 * Return: the number of bytes sent on success, or a negative error code
 */
static int
send_multipart_msg(struct nlmsghdr *nlh, struct multipart_head *head,
	bool multipart)
{
	struct multipart_node *node;
	int err;
	int ret = 0;

	TAILQ_FOREACH(node, head, entries) {
		err = nl_send_auto(nsd, node->nlbuf);
		if (err < 0) {
			free_multipart_msg(head);
			return err;
		}
		ret += err;
	}

	if (multipart) {
		err = send_done(nlh);
		ret = (err < 0) ? err : ret + err;
	}

	free_multipart_msg(head);
	return ret;
}

static int match_cmd_get_tables(struct nlmsghdr *nlh)
{
	struct nlattr *nest, *t, *tb[NET_MAT_MAX+1];
	struct multipart_head head;
	struct multipart_node *node;
	struct nlmsghdr *nlh_multi;
	unsigned int ifindex = 0;
	struct nl_msg *nlbuf = NULL;
	int i, err = -ENOMSG;
	bool multipart = false;

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX,
				match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
		err = -EINVAL; /* TBD need to reply with ERROR */
		goto nla_put_failure;
	}

#ifdef MATCHD_MOCK_SUPPORT
	TAILQ_INIT(&head);
	for (i = 0; i < MAX_MOCK_TABLES;) {
		/* allocate storage for nlbuf node */
		node = malloc(sizeof(*node));
		if (!node) {
			MAT_LOG(ERR, "Error: Cannot allocate node\n");
			free_multipart_msg(&head);
			return -ENOMEM;
		}

		nlbuf = match_alloc_msg(nlh, NET_MAT_TABLE_CMD_GET_TABLES,
				NLM_F_REQUEST|NLM_F_ACK, 0);
		if (!nlbuf) {
			MAT_LOG(ERR, "Error: Cannot allocate message\n");
			/* special case: free the previously allocated node
			 * since it has not yet been added to the tailq */
			free(node);
			free_multipart_msg(&head);
			return -ENOMEM;
		}

		node->nlbuf = nlbuf;
		TAILQ_INSERT_TAIL(&head, node, entries);

		if (multipart) {
			nlh_multi = nlmsg_hdr(nlbuf);
			nlh_multi->nlmsg_flags |= NLM_F_MULTI;
		}

		err = nla_put_u32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
				  NET_MAT_IDENTIFIER_IFINDEX);
		if (err) {
			MAT_LOG(ERR, "Error: Cannot put identifier\n");
			free_multipart_msg(&head);
			goto nla_put_failure;
		}

		err = nla_put_u32(nlbuf, NET_MAT_IDENTIFIER, ifindex);
		if (err) {
			MAT_LOG(ERR, "Error: Cannot put ifindex\n");
			free_multipart_msg(&head);
			return  -EMSGSIZE;
		}

		nest = nla_nest_start(nlbuf, NET_MAT_TABLES);
		if (!nest) {
			err = -EMSGSIZE;
			goto nla_put_failure;
		}

		for (; i < MAX_MOCK_TABLES; i++) {
			if (my_dyn_table_list[i].uid < 1)
				continue;

			t = nla_nest_start(nlbuf, NET_MAT_TABLE);
			err = match_put_table(nlbuf, &my_dyn_table_list[i]);
			if (err) {
				nlh_multi = nlmsg_hdr(nlbuf);
				nlh_multi->nlmsg_flags |= NLM_F_MULTI;
				multipart = true;
				MAT_LOG(ERR, "Warning nla_put error, abort\n");
				free_multipart_msg(&head);
				goto nla_put_failure;
			}
			nla_nest_end(nlbuf, t);
		}

		nla_nest_end(nlbuf, nest);
	}
#endif /* MATCHD_MOCK_SUPPORT */

	return send_multipart_msg(nlh, &head, multipart);

nla_put_failure:
	if (nlbuf)
		nlmsg_free(nlbuf);
	return err;
}

static int match_cmd_get_headers(struct nlmsghdr *nlh)
{
	struct nlattr *tb[NET_MAT_MAX+1];
	unsigned int ifindex = 0;
	struct nl_msg *nlbuf = NULL;
	int err = -ENOMSG;

	nlbuf = match_alloc_msg(nlh, NET_MAT_TABLE_CMD_GET_HEADERS,
				NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!nlbuf) {
		MAT_LOG(ERR, "Message allocation failed.\n");
		err = -ENOMEM;
		goto nla_put_failure;
	}

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
		err = -EINVAL; /* TBD need to reply with ERROR */
		goto nla_put_failure;
	}

	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
			NET_MAT_IDENTIFIER_IFINDEX);
	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER, ifindex);

	err = match_put_headers(nlbuf, backend->hdrs);
	if (err) {
		MAT_LOG(ERR, "Warning failed to pack headers.\n");
		goto nla_put_failure;
	}
	return nl_send_auto(nsd, nlbuf);

nla_put_failure:
	if (nlbuf)
		nlmsg_free(nlbuf);
	return err;
}

static int match_cmd_get_actions(struct nlmsghdr *nlh)
{
	struct nlattr *actions, *tb[NET_MAT_MAX+1];
	unsigned int ifindex = 0;
	struct nl_msg *nlbuf = NULL;
	int i, err = -ENOMSG;

	nlbuf = match_alloc_msg(nlh, NET_MAT_TABLE_CMD_GET_ACTIONS,
				NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!nlbuf) {
		MAT_LOG(ERR, "Message allocation failed.\n");
		err = -ENOMEM;
		goto nla_put_failure;
	}

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
		err = -EINVAL; /* TBD need to reply with ERROR */
		goto nla_put_failure;
	}

	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
			NET_MAT_IDENTIFIER_IFINDEX);
	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER, ifindex);

	actions = nla_nest_start(nlbuf, NET_MAT_ACTIONS);
	if (!actions) {
		err = -EMSGSIZE;
		goto nla_put_failure;
	}
		
	for (i = 0; backend->actions[i] && backend->actions[i]->uid; i++) {
		err = match_put_action(nlbuf, backend->actions[i]);
		if (err) {
			MAT_LOG(ERR, "Warning nla_put error, abort\n");
			goto nla_put_failure;
		}
	}
	nla_nest_end(nlbuf, actions);
	return nl_send_auto(nsd, nlbuf);

nla_put_failure:
	if (nlbuf)
		nlmsg_free(nlbuf);
	return err;
}

static int match_cmd_get_header_graph(struct nlmsghdr *nlh)
{
	struct nlattr *tb[NET_MAT_MAX+1];
	unsigned int ifindex = 0;
	struct nl_msg *nlbuf = NULL;
	int err = -ENOMSG;

	nlbuf = match_alloc_msg(nlh, NET_MAT_TABLE_CMD_GET_HDR_GRAPH,
		NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!nlbuf) {
		MAT_LOG(ERR, "Message allocation failed.\n");
		err = -ENOMEM;
		goto nla_put_failure;
	}

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
		err = -EINVAL; /* TBD need to reply with ERROR */
		goto nla_put_failure;
	}

	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
			NET_MAT_IDENTIFIER_IFINDEX);
	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER, ifindex);

	match_put_header_graph(nlbuf, backend->hdr_nodes);

	return nl_send_auto(nsd, nlbuf);

nla_put_failure:
	if (nlbuf)
		nlmsg_free(nlbuf);
	return err;
}

static int match_cmd_get_table_graph(struct nlmsghdr *nlh)
{
	struct nlattr *tb[NET_MAT_MAX+1];
	unsigned int ifindex = 0;
	struct nl_msg *nlbuf = NULL;
	int err = -ENOMSG;

	nlbuf = match_alloc_msg(nlh, NET_MAT_TABLE_CMD_GET_TABLE_GRAPH, NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!nlbuf) {
		MAT_LOG(ERR, "Message allocation failed.\n");
		err = -ENOMEM;
		goto nla_put_failure;
	}

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
		err = -EINVAL; /* TBD need to reply with ERROR */
		goto nla_put_failure;
	}

	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER_TYPE, NET_MAT_IDENTIFIER_IFINDEX);
	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER, ifindex);

	match_put_table_graph(nlbuf, backend->tbl_nodes);

	return nl_send_auto(nsd, nlbuf);

nla_put_failure:
	if (nlbuf)
		nlmsg_free(nlbuf);
	return err;
}

static struct nla_policy match_table_rules_policy[NET_MAT_TABLE_RULES_MAX + 1] = {
	[NET_MAT_TABLE_RULES_TABLE]   = { .type = NLA_U32,},
	[NET_MAT_TABLE_RULES_MINPRIO] = { .type = NLA_U32,},
	[NET_MAT_TABLE_RULES_MAXPRIO] = { .type = NLA_U32,},
	[NET_MAT_TABLE_RULES_RULES]   = { .type = NLA_NESTED,},
};

static int match_cmd_get_rules(struct nlmsghdr *nlh)
{
	struct multipart_head head;
	struct multipart_node *node;
	bool multipart = false;
	struct nlmsghdr *nlh_multi;
	unsigned int table = 0, min = 0, max = 0, ifindex = 0;
	struct nlattr *tb[NET_MAT_MAX+1];
	int err = -ENOMSG;
	struct nl_msg *nlbuf = NULL;
#ifdef MATCHD_MOCK_SUPPORT
	struct net_mat_rule *rules;
	struct nlattr *nest;
	unsigned int i;
#endif

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Error: Cannot parse get rules request\n");
		return -EINVAL;
	}

	err = nla_parse_nested(tb, NET_MAT_MAX,
			       tb[NET_MAT_RULES], match_table_rules_policy);
	if (err) {
		MAT_LOG(ERR, "Error: Cannot parse get rules request\n");
		return -EINVAL;
	}

	 /* If missing table id, return error */
	if (tb[NET_MAT_TABLE_RULES_TABLE]) {
		table = nla_get_u32(tb[NET_MAT_TABLE_RULES_TABLE]);
	} else {
		MAT_LOG(ERR, "Error: Table id is required\n");
		return -EINVAL;
	}

	/* If missing use min = 0 */
	/* TBD: prio -> should be uid */
	if (tb[NET_MAT_TABLE_RULES_MINPRIO])
		min = nla_get_u32(tb[NET_MAT_TABLE_RULES_MINPRIO]);

	/* If missing use max = table_sz */
	if (tb[NET_MAT_TABLE_RULES_MAXPRIO])
		max = nla_get_u32(tb[NET_MAT_TABLE_RULES_MAXPRIO]);

#ifdef MATCHD_MOCK_SUPPORT
	if (table > MAX_MOCK_TABLES - 1 || table < 1) {
		MAT_LOG(ERR, "Error: Table id is out of range\n");
		return -ERANGE;
	}

	if (!matchd_mock_tables[table] || !my_dyn_table_list[table].uid) {
		MAT_LOG(ERR, "Error: Table does not exist\n");
		return -ENOENT;
	}

	if (!max)
		max = my_dyn_table_list[table].size;

	if (max > my_dyn_table_list[table].size || min > max) {
		MAT_LOG(ERR, "Error: rule id min/max is out of range\n");
		return -ERANGE;
	}
#endif

	/* continue until the last rule is processed */
	TAILQ_INIT(&head);
	for (;;) {
		/* allocate storage for nlbuf node */
		node = malloc(sizeof(*node));
		if (!node) {
			MAT_LOG(ERR, "Error: Cannot allocate node\n");
			free_multipart_msg(&head);
			return -ENOMEM;
		}

		nlbuf = match_alloc_msg(nlh, NET_MAT_TABLE_CMD_GET_RULES,
				NLM_F_REQUEST|NLM_F_ACK, 0);
		if (!nlbuf) {
			MAT_LOG(ERR, "Error: Cannot allocate message\n");
			/* special case: free the previously allocated node
			 * since it has not yet been added to the tailq */
			free(node);
			free_multipart_msg(&head);
			return -ENOMEM;
		}

		node->nlbuf = nlbuf;
		TAILQ_INSERT_TAIL(&head, node, entries);

		if (multipart) {
			nlh_multi = nlmsg_hdr(nlbuf);
			nlh_multi->nlmsg_flags |= NLM_F_MULTI;
		}

		/* since a fresh buffer was just allocated, it does not
		 * make sense for nla_put_u32 to fail here, so treat it
		 * as a real error. */
		err = nla_put_u32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
			    NET_MAT_IDENTIFIER_IFINDEX);
		if (err) {
			MAT_LOG(ERR, "Error: Cannot put identifier\n");
			free_multipart_msg(&head);
			return -EMSGSIZE;
		}

		err = nla_put_u32(nlbuf, NET_MAT_IDENTIFIER, ifindex);
		if (err) {
			MAT_LOG(ERR, "Error: Cannot put ifindex\n");
			free_multipart_msg(&head);
			return -EMSGSIZE;
		}

#ifdef MATCHD_MOCK_SUPPORT
		/* it does not make sense for nla_nest_start to fail
		 * here, so treat it as a real error. */
		nest = nla_nest_start(nlbuf, NET_MAT_RULES);
		if (!nest) {
			MAT_LOG(ERR, "Error: Cannot put rules\n");
			free_multipart_msg(&head);
			return -EMSGSIZE;
		}

#ifdef DEBUG
		switch_debug(1);
		MAT_LOG(DEBUG, "get_rules: table  %d\n", table);
#endif /* DEBUG */

		rules = matchd_mock_tables[table];
		for (i = min; i < max + 1; i++) {
			if (!rules[i].uid)
				continue;

#ifdef DEBUG
			if (table >= TABLE_DYN_START) {
				__u32 switch_table_id;
				__u64 pkts, octets;

				switch_table_id = rules[i].table_id - TABLE_DYN_START + 1;

				switch_get_rule_counters(rules[i].hw_ruleid,
					switch_table_id, &pkts, &octets);
			}
#endif /* DEBUG */

			if (backend->get_rule_counters)
				(backend->get_rule_counters)(&rules[i]);
			err = match_put_rule(nlbuf, &rules[i]);
			if (err) {
				/* a multipart message is needed so set the
				 * NLM_F_MULTI flag, end this nest, and run
				 * through the outer loop again, starting
				 * with the current rule */
				nlh_multi = nlmsg_hdr(nlbuf);
				nlh_multi->nlmsg_flags |= NLM_F_MULTI;
				multipart = true;
				nla_nest_end(nlbuf, nest);
				min = i;
				break;
			}
		}

		/* break when all rules have been processed */
		if (i == max + 1) {
			nla_nest_end(nlbuf, nest);
			break;
		}

#else /* MATCHD_MOCK_SUPPORT */
		break;
#endif /* MATCHD_MOCK_SUPPORT */
	}

	return send_multipart_msg(nlh, &head, multipart);
}

/*
 * match_is_valid_action_arg() - validate an action's arguments
 * @a: the action in a table to validate against
 * @args: the arguments to validate
 *
 * The action defines how many arguments are expected and of which type each
 * argument represents. If args specifies more or less arguments than the
 * action expects, then the arguments are invalid.
 *
 * Return: 0 if the args are valid, -EINVAL if invalid.
 */
static int
match_is_valid_action_arg(struct net_mat_action *a,
			 struct net_mat_action_arg *args)
{
	int i;
	int err = -EINVAL; /* Start with -EINVAL, change as needed */	
	enum net_mat_action_arg_type fixed = NET_MAT_ACTION_ARG_TYPE_UNSPEC;

	if (!a)
		goto done;

	/* Actions might not have any arguments */
	if (!a->args && !args) {
		err = 0;
		goto done;
	}

	/* Args must be present if the action expects arguments.
	* Args must not be present if the action does not expect arguments. */
	if (!(a->args && args))
		goto done;

	/* Variadic can't be first argument so abort on this case */
	if (a->args[0].type == NET_MAT_ACTION_ARG_TYPE_VARIADIC)
		goto done;

	/* Walk argument list from client and verify it is the same type
	 * as the backend. Variadic argument lists are handled special
	 * because they allow variable number of arguments which is tracked
	 * here by 'fixed'.
	 */
	for (i = 0; args[i].type; i++) {
		if (!fixed &&
		    a->args[i].type == NET_MAT_ACTION_ARG_TYPE_VARIADIC)
			fixed = a->args[i-1].type;
		else if (!fixed && !a->args[i].type)
			goto done; /* more args than specified */

		if (fixed) {
			if (args[i].type != fixed)
				goto done;
		} else {
			if (a->args[i].type != args[i].type)
				goto done;
		}
	}

	err = 0; /* If reached here, change err code to SUCCESS */
done:
	return err;
}

/*
 * match_is_valid_action() - validate an action against a table's actions
 * @actions: the actions in a table to validate against
 * @a: the action to validate
 *
 * Return: 0 if the action is valid, -EINVAL if invalid.
 */
static int
match_is_valid_action(__u32 *actions, struct net_mat_action *a)
{
       int i;

       for (i = 0; actions[i]; i++) {
	       if (actions[i] == a->uid) {
		       return match_is_valid_action_arg(get_actions(a->uid),
						       a->args);
	       }
       }

       return -EINVAL;
}

 /*
 * Validate match value's mask.
 *
 * Exact matches must be fully masked.  Lookup the field based on the
 * header and field indices to determine the field's length in bits.
 * An exact match must have all bits set in the mask field.
 *
 * @param fref
 *   Table field ref defining the mask type
 * @param fr
 *   Rule field ref defining the mask value
 * @return 0 on success or -EINVAL on failure.
 */
static int
match_is_valid_mask(struct net_mat_field_ref *fref,
                    struct net_mat_field_ref *fr)
{
	struct net_mat_field *field;
	__u64 mask;
	int err = 0;

	if (fref->mask_type == NET_MAT_MASK_TYPE_EXACT) {
		field = get_fields(fr->header, fr->field);
		if (!field) {
			MAT_LOG(ERR, "Error: invalid header/field\n");
			return -EINVAL;
		}

		mask = (1ULL << field->bitwidth) - 1;

		switch(fr->type) {
		case NET_MAT_FIELD_REF_ATTR_TYPE_U8:
			err = (fr->v.u8.mask_u8 == mask) ? 0 : -EINVAL;
			break;
		case NET_MAT_FIELD_REF_ATTR_TYPE_U16:
			err = (fr->v.u16.mask_u16 == mask) ? 0 : -EINVAL;
			break;
		case NET_MAT_FIELD_REF_ATTR_TYPE_U32:
			err = (fr->v.u32.mask_u32 == mask) ? 0 : -EINVAL;
			break;
		case NET_MAT_FIELD_REF_ATTR_TYPE_U64:
			err = (fr->v.u64.mask_u64 == mask) ? 0 : -EINVAL;
			break;
		default:
			err = -EINVAL;
		}

		if (err) {
			MAT_LOG(ERR, "Error: Exact match requires full mask\n");
		}
	}

	return err;
}

/*
 * match_is_valid_match() - validate a match against a table's matches
 * @fields: the fields in a table to validate against
 * @f: the match to validate
 *
 * Return: 0 if the match is valid, -EINVAL if invalid.
 */
static int
match_is_valid_match(struct net_mat_field_ref *fields,
		    struct net_mat_field_ref *f)
{
       int i;

       for (i = 0; fields[i].header; i++) {
	       if (f->header == fields[i].header &&
		   f->field == fields[i].field &&
		   !match_is_valid_mask(&fields[i], f))
		       return 0;
       }

       return -EINVAL;
}

/*
 * match_is_valid_rule() - validate a rule against a table spec
 * @table: the table to validate against
 * @rule: the rule to validate
 *
 * Return: 0 if the rule is valid, -EINVAL if invalid.
 */
static int
match_is_valid_rule(struct net_mat_tbl *table, struct net_mat_rule *rule)
{
	struct net_mat_field_ref *fields;
	__u32 *actions;
	int i;
	int err = -EINVAL; /* Start with -EINVAL, change as needed */	

	/* Only accept rules with matches AND actions it does not seem
	* correct to allow a match without actions or action chains
	* that will never be hit
	*/
	if(!table)
		goto done;
	if (!rule->actions || !rule->matches)
		goto done;

	actions = table->actions;
	for (i = 0; rule->actions[i].uid; i++) {
		err = match_is_valid_action(actions, &rule->actions[i]);
		if (err)
			goto done;
	}

	fields = table->matches;
	for (i = 0; rule->matches[i].header; i++) {
		err = match_is_valid_match(fields, &rule->matches[i]);
		if (err)
			goto done;
	}

	err = 0; /* If reached here, change err code to SUCCESS */
done:
	return err;
}

static int match_cmd_resolve_rules(struct net_mat_rule *rule, int cmd,
				  unsigned int error_method,
				  struct nl_msg *nlbuf)
{
	int i, err = 0;

	for (i = 0; rule[i].uid; i++) {
#ifdef MATCHD_MOCK_SUPPORT
		unsigned int table = rule[i].table_id;
		struct net_mat_rule *rules;

		if (table >= MAX_MOCK_TABLES) {
			MAT_LOG(ERR, "Invalid table %i\n", table);
			err = -EINVAL;
			goto skip_add;
		}

		if (!matchd_mock_tables[table]) {
			MAT_LOG(ERR, "Warning, invalid rule table %i\n",
				table);
			err = -EINVAL;
			goto skip_add;
		}

		if (!my_dyn_table_list[table].uid) {
			MAT_LOG(ERR, "Warning, invalid dynamic table %i\n",
				table);
			err = -EINVAL;
			goto skip_add;
		}

		if (rule[i].uid > my_dyn_table_list[table].size) {
			MAT_LOG(ERR, "Warning, table overrun\n");
			err = -ENOMEM;
			goto skip_add;
		}
		rules = matchd_mock_tables[table];
#endif /* MATCHD_MOCK_SUPPORT*/

		switch (cmd) {
		case NET_MAT_TABLE_CMD_SET_RULES:
			if (rules[rule[i].uid].uid) {
				MAT_LOG(ERR, "rule %d already exists\n",
					rule[i].uid);
				err = -EEXIST;
				goto skip_add;
			}

			err = match_is_valid_rule(get_tables(table), rule);
			if (err) {
				MAT_LOG(ERR, "Warning, rule invalid\n");
				goto skip_add;
			}

			err = (backend->set_rules)(&rule[i]);
			if(err) {
				goto skip_add;
			}
#ifdef MATCHD_MOCK_SUPPORT
			rules[rule[i].uid] = rule[i];
#endif /* MATCHD_MOCK_SUPPORT */
			break;
		case NET_MAT_TABLE_CMD_DEL_RULES:
			err = (backend->del_rules)(&rules[rule[i].uid]);
			if(err) {
				goto skip_add;
			}
#ifdef MATCHD_MOCK_SUPPORT
			rules[rule[i].uid].uid = 0;
			rules[rule[i].uid].hw_ruleid = 0;
#endif /* MATCHD_MOCK_SUPPORT */
			break;
		default:
			err = -EINVAL;
			goto done;
		}
skip_add:
		if (err) {
			switch (error_method) {
			case NET_MAT_RULES_ERROR_ABORT:
				return err;
			case NET_MAT_RULES_ERROR_CONTINUE:
				err = 0;
				break;
			case NET_MAT_RULES_ERROR_ABORT_LOG:
				match_put_rule(nlbuf, &rule[i]);
				goto done;
			case NET_MAT_RULES_ERROR_CONT_LOG:
				err = 0;
				match_put_rule(nlbuf, &rule[i]);
				break;
			default:
				return err;
			}
		}
	}

done:
	return err;
}

static int match_cmd_rules(struct nlmsghdr *nlh)
{
	unsigned int error_method = NET_MAT_RULES_ERROR_ABORT;
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_rule *rule = NULL;
	unsigned int ifindex = 0;
	struct nl_msg *nlbuf = NULL;
	int err = -ENOMSG;

	if (glh->cmd > NET_MAT_CMD_MAX) {
		err = -EOPNOTSUPP;
		goto nla_put_failure;
	}

	nlbuf = match_alloc_msg(nlh, NET_MAT_TABLE_CMD_SET_RULES,
				NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!nlbuf) {
		MAT_LOG(ERR, "Message allocation failed.\n");
		err = -ENOMEM;
		goto nla_put_failure;
	}

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
		err = -EINVAL; /* TBD need to reply with ERROR */
		goto nla_put_failure;
	}

	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
				NET_MAT_IDENTIFIER_IFINDEX);
	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER, ifindex);

	if (tb[NET_MAT_RULES_ERROR])
		error_method = nla_get_u32(tb[NET_MAT_RULES_ERROR]);

	/* Generates a null terminated list of rules for processing */
	err = match_get_rules(stdout, true, tb[NET_MAT_RULES], &rule);
	if (err) {
		MAT_LOG(ERR, "Warning received an invalid set_rule oper\n");
		goto nla_put_failure;
	} 

	err = match_cmd_resolve_rules(rule, glh->cmd, error_method, nlbuf);
	if (err && (error_method < NET_MAT_RULES_ERROR_CONTINUE + 1)) {
		MAT_LOG(ERR, "%s: return err %i\n", __func__, err);
		goto nla_put_failure;
	}

	err = nl_send_auto(nsd, nlbuf);
	if (err < 0) {
		MAT_LOG(ERR, "%s: nl_send_suto returned err %d\n",
			__func__, err);
		goto nla_put_failure;
	}
	return err;

nla_put_failure:
	if (rule)
		free(rule);
	if (nlbuf)
		nlmsg_free(nlbuf);
	return err;
}

static int match_cmd_update_rules(struct nlmsghdr *nlh __unused)
{
	return -EOPNOTSUPP;
}

static bool match_is_dynamic_table(unsigned int uid)
{
	int i;

	for (i = 0; backend->tbl_nodes[i] && backend->tbl_nodes[i]->uid; i++) {
		if (backend->tbl_nodes[i]->uid == uid &&
		    backend->tbl_nodes[i]->flags & NET_MAT_TABLE_DYNAMIC)
			return true;
	}

	return false;
}

/*
 * match_set_dyn_tbl_matches() - set or inherit source table matches
 * @table: the source table for the new dynamic table
 * @new_table: the new table being created
 *
 * If no matches are specified for the sub-table, the matches should
 * be inherited from the parent.
 *
 * If some matches are specified for the sub-table, they should be
 * a sub-set of the parent table.
 *
 * Return: 0 if the matches are set
 * 	   -EINVAL if new table specifies matches which are not supported by
 * 		   the source table.
 */
static int
match_set_dyn_tbl_matches(struct net_mat_tbl *table,
			 struct net_mat_tbl *new_table)
{
	size_t size;
	size_t count;
	int i;
	int j;
	bool found;

	/* inherit matches from parent table when no matches are
	 * provided in the sub-table */
	if (!new_table->matches || new_table->matches[0].instance == 0) {
		if (new_table->matches)
			free(new_table->matches);

		/* count matches */
		for (count = 0; table->matches[count].instance; ++count);

		/* duplicate matches, plus one for NULL terminator */
		size = (count + 1) * sizeof(table->matches[0]);

		new_table->matches = malloc(size);
		if (!new_table->matches)
			return -ENOMEM;

		memcpy(new_table->matches, table->matches, size);

		return 0;
	}

	/* sub-table matches must be a subset of the parent table's matches */
	for (i = 0; new_table->matches[i].instance; ++i) {
		found = false;
		for (j = 0; table->matches[j].instance; ++j) {
			if ((new_table->matches[i].instance ==
			     table->matches[j].instance) &&
			    (new_table->matches[i].field ==
			     table->matches[j].field)) {
				found = true;
				break;
			}
		}

		if (!found)
			return -EINVAL;
	}

	return 0;
}

/*
 * match_set_dyn_tbl_actions() - set or inherit source table actions
 * @table: the source table for the new dynamic table
 * @new_table: the new table being created
 *
 * If no actions are specified for the sub-table, the actions should
 * be inherited from the parent.
 *
 * If some actions are specified for the sub-table, they should be
 * a sub-set of the parent table.
 *
 * Return: 0 if the actions are set
 * 	   -EINVAL if new table specifies actions which are not supported by
 * 		   the source table.
 */
static int
match_set_dyn_tbl_actions(struct net_mat_tbl *table,
			 struct net_mat_tbl *new_table)
{
	size_t size;
	size_t count;
	int i;
	int j;
	bool found;

	/* inherit actions from parent table when no actions are
	 * provided in the sub-table */
	if (!new_table->actions || new_table->actions[0] == 0) {
		if (new_table->actions)
			free(new_table->actions);

		/* count actions */
		for (count = 0; table->actions[count]; ++count);

		/* duplicate actions, plus one for NULL terminator */
		size = (count + 1) * sizeof(table->actions[0]);

		new_table->actions = malloc(size);
		if (!new_table->actions)
			return -ENOMEM;

		memcpy(new_table->actions, table->actions, size);

		return 0;
	}

	/* sub-table actions must be a subset of the parent table's actions */
	for (i = 0; new_table->actions[i]; ++i) {
		found = false;
		for (j = 0; table->actions[j]; ++j) {
			if (new_table->actions[i] == table->actions[j]) {
				found = true;
				break;
			}
		}

		if (!found)
			return -EINVAL;
	}

	return 0;
}

/*
 * Verify the requested mask type is valid
 *
 * A field supporting the NET_MAT_MASK_TYPE_MASK type can also take
 * the NET_MAT_MASK_TYPE_EXACT type. All other mask types need to match
 * the expected type.
 *
 * @param exp
 *   The expected mask type.
 * @param req
 *   The requested mask type.
 *
 * @return 0 on success or -EINVAL if the requested mask type is invalid.
 */
static int match_check_field_mask(__u32 exp, __u32 req)
{
	switch (exp) {
	case NET_MAT_MASK_TYPE_MASK:
		if (req == NET_MAT_MASK_TYPE_EXACT ||
		    req == NET_MAT_MASK_TYPE_MASK)
			return 0;
		else
			return -EINVAL;
	case NET_MAT_MASK_TYPE_LPM:
		return (req == NET_MAT_MASK_TYPE_LPM) ? 0 : -EINVAL;
	case NET_MAT_MASK_TYPE_EXACT:
		return (req == NET_MAT_MASK_TYPE_EXACT) ? 0 : -EINVAL;
	case NET_MAT_MASK_TYPE_UNSPEC:
	default:
		return -EINVAL;
	}
}

/* verify that new table specifies valid match masks */
static int match_check_field_masks(struct net_mat_tbl *table,
                                   struct net_mat_tbl *new_table)
{
	int i;
	int j;

	for (i = 0; new_table->matches[i].instance; ++i) {
		for (j = 0; table->matches[j].instance; ++j) {
			if (new_table->matches[i].instance ==
			    table->matches[j].instance) {
				return match_check_field_mask(
				          table->matches[j].mask_type,
				          new_table->matches[i].mask_type);
			}
		}
	}

	return 0;
}

static int match_cmd_table(struct nlmsghdr *nlh)
{
	struct genlmsghdr *glh = nlmsg_data(nlh);
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_tbl *tables = NULL;
	unsigned int ifindex = 0;
	int i, err = -ENOMSG;
	struct nl_msg *nlbuf = NULL;

	nlbuf = match_alloc_msg(nlh, NET_MAT_TABLE_CMD_CREATE_TABLE,
			       NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!nlbuf) {
		MAT_LOG(ERR, "Message allocation failed.\n");
		err = -ENOMEM;
		goto nla_put_failure;
	}

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
		err = -EINVAL; /* TBD need to reply with ERROR */
		goto nla_put_failure;
	}

	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
		NET_MAT_IDENTIFIER_IFINDEX);
	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER, ifindex);

	if (!tb[NET_MAT_TABLES]) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	/* Generates a null terminated list of rules for processing */
	err = match_get_tables(stdout, false, tb[NET_MAT_TABLES], &tables);
	if (err)
		goto nla_put_failure;

	/*
		(* valid fields *)
		table->uid (* unique id of the table to create *)
		table->source (* where to place it *)
		table->size   (* how many rule entries *)
		table->matches (* null terminated matches it needs to support *)
		table->actions (* num terminated list of action ids *) 

	*/

	for (i = 0; tables[i].uid; i++) {
		struct net_mat_tbl *src = get_tables(tables[i].source);

		switch (glh->cmd) {
		case NET_MAT_TABLE_CMD_DESTROY_TABLE:
			if(!src) {
				err = -EINVAL;
				goto nla_put_failure;
			}
			pp_table(stdout, true, &tables[i]);

			MAT_LOG(ERR, "%s: destroy table %d\n",
					__func__, tables[i].uid);

#ifdef MATCHD_MOCK_SUPPORT
			if (my_dyn_table_list[tables[i].uid].uid < 1) {
				err = -EINVAL;
				goto nla_put_failure;
			}
			if (tables[i].uid > MAX_MOCK_TABLES - 1) {
				err = -EINVAL;
				goto nla_put_failure;
			}
#endif /* MATCHD_MOCK_SUPPORT */

			err = (backend->destroy_table)(&tables[i]);
			if(err < 0) {
				MAT_LOG(ERR, "delete table %d error %d\n", i, err);
				goto nla_put_failure;
			}

#ifdef MATCHD_MOCK_SUPPORT
			my_dyn_table_list[tables[i].uid].uid = 0;
			free(matchd_mock_tables[tables[i].uid]);
			matchd_mock_tables[tables[i].uid] = NULL;
#endif /* MATCHD_MOCK_SUPPORT */
			break;

		case NET_MAT_TABLE_CMD_CREATE_TABLE:
#ifdef MATCHD_MOCK_SUPPORT
			if(!src) {
				err = -EINVAL;
				goto nla_put_failure;
			}
			pp_table(stdout, true, &tables[i]);

			if (tables[i].uid > MAX_MOCK_TABLES - 1) {
				MAT_LOG(ERR, "create table request greater "
						"than max tables abort!\n");
				err =  -EINVAL;
				goto nla_put_failure;
			}

			if (matchd_mock_tables[tables[i].uid]) {
				MAT_LOG(ERR, "create table request exists "
					"in mock tables abort!\n");
				err = -EEXIST;
				goto nla_put_failure;
			}

			if (my_dyn_table_list[tables[i].uid].uid) {
				MAT_LOG(ERR, "create table request exists "
					"in dyn tables abort!\n");
				err = -EEXIST;
				goto nla_put_failure;
			}
#endif /* MATCHD_MOCK_SUPPORT */

			if (match_is_dynamic_table(tables[i].source) == false) {
				MAT_LOG(ERR, "create table requests require"
						" dynamic bit\n");
				err = -EINVAL;
				goto nla_put_failure;
			}

			if (src->size < tables[i].size) {
				MAT_LOG(ERR, "Dynamic table's size must be less than or equal to source table's size\n");
				err = -EINVAL;
				goto nla_put_failure;
			}

			if (match_set_dyn_tbl_matches(src, &tables[i])) {
				MAT_LOG(ERR, "Dynamic table's matches must be a subset of the source table's matches\n");
				err = -EINVAL;
				goto nla_put_failure;
			}

			if (match_check_field_masks(src, &tables[i])) {
				MAT_LOG(ERR, "Match mask(s) invalid\n");
				err = -EINVAL;
				goto nla_put_failure;
			}

			if (match_set_dyn_tbl_actions(src, &tables[i])) {
				MAT_LOG(ERR, "Dynamic table's actions must be a subset of the source table's actions\n");
				err = -EINVAL;
				goto nla_put_failure;
			}

#ifdef MATCHD_MOCK_SUPPORT
			/* In ENOMEM case leave my_dyn_table_list allocated
			 * anticipating a retry from agent.
			 */
			matchd_mock_tables[tables[i].uid] = calloc(1 +
				tables[i].size, sizeof(struct net_mat_rule));
			if (!matchd_mock_tables[tables[i].uid]) {
				MAT_LOG(ERR, "rule table alloc failed!\n");
				err = -ENOMEM;
				goto nla_put_failure;
			}
#endif /* MATCHD_MOCK_SUPPORT */

			err = (backend->create_table)(&tables[i]);
			if(err < 0) {
				MAT_LOG(ERR, "create table failed err=%d\n", err);
				free(matchd_mock_tables[tables[i].uid]);
				matchd_mock_tables[tables[i].uid] = NULL;
				goto nla_put_failure;
			}

#ifdef MATCHD_MOCK_SUPPORT
			my_dyn_table_list[tables[i].uid] = tables[i];
#endif /* MATCHD_MOCK_SUPPORT */
			break;
		case NET_MAT_TABLE_CMD_UPDATE_TABLE:
			err = (backend->update_table)(&tables[i]);
			if (err < 0) {
				MAT_LOG(ERR, "update table failed err=%d\n", err);
				goto nla_put_failure;
			}
			break;
		default:
			MAT_LOG(ERR, "table cmd error\n");
			break;
		}
	}

	if (glh->cmd == NET_MAT_TABLE_CMD_DESTROY_TABLE)
		match_pop_tables(&tables);
	else if (glh->cmd == NET_MAT_TABLE_CMD_CREATE_TABLE)
		match_push_tables_a(tables);

	err = nl_send_auto(nsd, nlbuf);

	if (err < 0) {
		MAT_LOG(ERR, "nl_send_auto returned error %d\n", err);
		goto nla_put_failure;
	}

	return err;

nla_put_failure:
	if (tables)
		free(tables);
	if (nlbuf)
		nlmsg_free(nlbuf);
	return err;
}

static struct nla_policy match_table_ports_policy[NET_MAT_PORT_MAX + 1] = {
	[NET_MAT_PORT]			= { .type = NLA_NESTED,},
	[NET_MAT_PORT_MIN_INDEX]	= { .type = NLA_U32,},
	[NET_MAT_PORT_MAX_INDEX]	= { .type = NLA_U32,},
};

static int match_cmd_get_ports(struct nlmsghdr *nlh)
{
	struct nlattr *p[NET_MAT_PORT_MAX+1];
	struct multipart_head head;
	struct multipart_node *node;
	struct net_mat_port *ports;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct nlattr *pnest, *port;
	struct nl_msg *nlbuf = NULL;
	struct nlmsghdr *nlh_multi;
	uint32_t i, min, max, bmax;
	unsigned int ifindex = 0;
	bool multipart = false;
	int err = -ENOMSG;

	if (!backend->get_ports) {
		MAT_LOG(ERR, "get_ports not supported by backend.\n");
		return -EOPNOTSUPP;
	}

	err = backend->get_ports(&ports);
	if (err) {
		MAT_LOG(ERR, "get_ports failed in backend.\n");
		return -EOPNOTSUPP;
	}

	for (bmax = 0, i = 0; ports[i].port_id != NET_MAT_PORT_ID_UNSPEC; i++)
		if (ports[i].port_id > bmax)
			bmax = ports[i].port_id;

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
		return -EINVAL;
	}

	min = 0;
	max = bmax;

	if (tb[NET_MAT_PORTS]) {
		err = nla_parse_nested(p, NET_MAT_PORT_MAX,
				       tb[NET_MAT_PORTS],
				       match_table_ports_policy);
		if (err) {
			MAT_LOG(ERR, "Error: Cannot parse get ports request\n");
			return -EINVAL;
		}

		if (p[NET_MAT_PORT_MIN_INDEX])
			min = nla_get_u32(p[NET_MAT_PORT_MIN_INDEX]);

		if (p[NET_MAT_PORT_MAX_INDEX])
			max = nla_get_u32(p[NET_MAT_PORT_MAX_INDEX]);
	}

	/* continue until the last port is processed */
	TAILQ_INIT(&head);
	for (i = 0; ports[i].port_id != NET_MAT_PORT_ID_UNSPEC; i++) {
		/* allocate storage for nlbuf node */
		node = malloc(sizeof(*node));
		if (!node) {
			MAT_LOG(ERR, "Error: Cannot allocate node\n");
			err = -ENOMEM;
			goto nla_failure;
		}

		nlbuf = match_alloc_msg(nlh, NET_MAT_PORT_CMD_GET_PORTS,
					NLM_F_REQUEST|NLM_F_ACK, 0);
		if (!nlbuf) {
			MAT_LOG(ERR, "Message allocation failed.\n");
			err = -ENOMEM;
			goto nla_failure;
		}

		node->nlbuf = nlbuf;
		TAILQ_INSERT_TAIL(&head, node, entries);

		if (multipart) {
			nlh_multi = nlmsg_hdr(nlbuf);
			nlh_multi->nlmsg_flags |= NLM_F_MULTI;
		}

		err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
		if (err) {
			MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
			goto nla_failure;
		}

		err = nla_put_u32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
				  NET_MAT_IDENTIFIER_IFINDEX);
		if (err) {
			MAT_LOG(ERR, "Error: Cannot put identifier\n");
			goto nla_failure;
		}

		err = nla_put_u32(nlbuf, NET_MAT_IDENTIFIER, ifindex);
		if (err) {
			MAT_LOG(ERR, "Error: Cannot put identifier\n");
			goto nla_failure;
		}

		pnest = nla_nest_start(nlbuf, NET_MAT_PORTS);
		if (!pnest)
			return -EMSGSIZE;

		for (; ports[i].port_id != NET_MAT_PORT_ID_UNSPEC; i++) {
			if (ports[i].port_id > max ||
			    ports[i].port_id < min)
				continue;
			port = nla_nest_start(nlbuf, NET_MAT_PORT);
			if (!port) {
				err = -EMSGSIZE;
				goto nla_failure;
			}

			err = match_put_port(nlbuf, &ports[i]);
			if (err) {
				/* a multipart message is needed so set the
				 * NLM_F_MULTI flag, end this nest, and run
				 * through the outer loop again, starting
				 * with the current port */
				nlh_multi = nlmsg_hdr(nlbuf);
				nlh_multi->nlmsg_flags |= NLM_F_MULTI;
				multipart = true;
				min = i;
				nla_nest_end(nlbuf, port);
				break;
			}
			nla_nest_end(nlbuf, port);
		}
		nla_nest_end(nlbuf, pnest);

		if (ports[i].port_id == NET_MAT_PORT_ID_UNSPEC)
			break;
	}

	return send_multipart_msg(nlh, &head, multipart);
nla_failure:
	free(node);
	free_multipart_msg(&head);
	nlmsg_free(nlbuf);
	return err;
}

static int match_cmd_set_ports(struct nlmsghdr *nlh)
{
	struct nlattr *tb[NET_MAT_MAX+1];
	struct nl_msg *nlbuf = NULL;
	struct net_mat_port *p;
	unsigned int ifindex = 0;
	int err;

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Warnings genlmsg_parse failed\n");
		return -EINVAL;
	}

	if (!tb[NET_MAT_PORTS])
		return -EINVAL;

	err = match_get_ports(stderr, true, tb[NET_MAT_PORTS], &p);
	if (err) {
		MAT_LOG(ERR, "get_ports failed.\n");
		return err;
	}

	if (!backend->set_ports) {
		MAT_LOG(ERR, "set_ports not supported by backend.\n");
		free(p);
		return -EOPNOTSUPP;
	}

	err = backend->set_ports(p);
	if (err) {
		MAT_LOG(ERR, "set_ports failed in backend.\n");
		free(p);
		return err;
	}

	nlbuf = match_alloc_msg(nlh, NET_MAT_PORT_CMD_SET_PORTS,
				NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!nlbuf) {
		err = -ENOMEM;
		MAT_LOG(ERR, "Message allocation failed.\n");
		goto nla_put_failure;
	}

	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
			NET_MAT_IDENTIFIER_IFINDEX);
	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER, ifindex);

	err = nl_send_auto(nsd, nlbuf);
nla_put_failure:
	free(p);
	nlmsg_free(nlbuf);

	return err;
}

static int match_cmd_get_port(struct nlmsghdr *nlh, uint8_t cmd)
{
	struct nlattr *i, *tb[NET_MAT_MAX+1];
	struct net_mat_port *ports;
	unsigned int ifindex = 0;
	struct nl_msg *nlbuf = NULL;
	int rem, err = -ENOMSG;
	unsigned int count = 0;

	if ((cmd == NET_MAT_PORT_CMD_GET_LPORT && !backend->get_lport) ||
	    (cmd == NET_MAT_PORT_CMD_GET_PHYS_PORT && !backend->get_phys_port)) {
		MAT_LOG(ERR, "get port not supported by backend.\n");
		return -EOPNOTSUPP;
	}

	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err) {
		MAT_LOG(ERR, "Error: Cannot parse get port request\n");
		return -EINVAL;
	}

	if (!tb[NET_MAT_PORTS]) {
		MAT_LOG(ERR, "Error: Missing port port request\n");
		return -EINVAL;
	}

	rem = nla_len(tb[NET_MAT_PORTS]);
	for (i = nla_data(tb[NET_MAT_PORTS]);
	     nla_ok(i, rem);
	     i = nla_next(i, &rem))
		count++;

	ports = (struct net_mat_port *)calloc(count + 1, sizeof(*ports));

	if(!ports)
		return -ENOMEM;

	/* terminate ports array */
	ports[count].port_id = NET_MAT_PORT_ID_UNSPEC;

	rem = nla_len(tb[NET_MAT_PORTS]);
	for (i = nla_data(tb[NET_MAT_PORTS]), count = 0;
	     nla_ok(i, rem);
	     i = nla_next(i, &rem), count++) {

		if (nla_type(i) != NET_MAT_PORT) {
			MAT_LOG(ERR, "Warning: not a port!\n");
			continue;
		}

		err = match_get_port(stdout, true, i, &ports[count]);
		if (err) {
			MAT_LOG(ERR, "Error: invalid port message\n");
			free(ports);
			return -EINVAL;
		}

		if (cmd == NET_MAT_PORT_CMD_GET_LPORT)
			err = backend->get_lport(&ports[count],
			                         &ports[count].port_id,
			                         &ports[count].glort);
		else if (cmd == NET_MAT_PORT_CMD_GET_PHYS_PORT)
			err = backend->get_phys_port(&ports[count],
						&ports[count].port_phys_id,
						&ports[count].glort);

		if (err) {
			MAT_LOG(ERR, "get port failed in backend.\n");
			free(ports);
			return err;
		}
	}

	nlbuf = match_alloc_msg(nlh, cmd, NLM_F_REQUEST|NLM_F_ACK, 0);
	if (!nlbuf) {
		MAT_LOG(ERR, "Message allocation failed.\n");
		goto nla_put_failure;
	}

	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER_TYPE,
			NET_MAT_IDENTIFIER_IFINDEX);
	NLA_PUT_U32(nlbuf, NET_MAT_IDENTIFIER, ifindex);

	err = match_put_ports(nlbuf, ports);
	if (err) {
		MAT_LOG(ERR, "Warning failed to pack ports.\n");
		goto nla_put_failure;
	}
	err = nl_send_auto(nsd, nlbuf);
nla_put_failure:
	free(ports);
	nlmsg_free(nlbuf);

	return err;
}


static int match_cmd_get_lport(struct nlmsghdr *nlh)
{
	return match_cmd_get_port(nlh, NET_MAT_PORT_CMD_GET_LPORT);
}

static int match_cmd_get_phys_port(struct nlmsghdr *nlh)
{
	return match_cmd_get_port(nlh, NET_MAT_PORT_CMD_GET_PHYS_PORT);
}

/*
 * send_error() - send a netlink error message
 * @orighdr: original netlink message header which produced the error
 *
 * @err: the non-negative error code to send
 *
 * Return: number of bytes sent on success, or a negative error code
 *         on failure
 */
static int send_error(struct nlmsghdr *orighdr, int err)
{
	struct nl_msg *nlbuf = NULL;
	struct nlmsghdr *newhdr;
	struct nlmsgerr *errmsg;
	struct sockaddr_nl nladdr;
	uint32_t payload_len;
	int ret = -EINVAL;

	if (orighdr == NULL)
		goto done;

	nlbuf = nlmsg_alloc();
	if (nlbuf == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	payload_len = orighdr->nlmsg_len;

	newhdr = nlmsg_put(nlbuf, NL_AUTO_PID, orighdr->nlmsg_seq, NLMSG_ERROR,
	                   (int)payload_len, 0);
	if (newhdr == NULL)
		goto done;

	errmsg = nlmsg_data(newhdr);
	errmsg->error = err;
	memcpy(&errmsg->msg, orighdr, payload_len);

	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = orighdr->nlmsg_pid;
	nladdr.nl_groups = 0;

	nlmsg_set_dst(nlbuf, &nladdr);

	return nl_send_auto(nsd, nlbuf);
done:
	if (nlbuf)
		nlmsg_free(nlbuf);
	return ret;
}

static int(*type_cb[NET_MAT_CMD_MAX+1])(struct nlmsghdr *nlh) = {
	match_cmd_get_tables,
	match_cmd_get_headers,
	match_cmd_get_actions,
	match_cmd_get_header_graph,
	match_cmd_get_table_graph,
	match_cmd_get_rules,
	match_cmd_rules,
	match_cmd_rules,
	match_cmd_update_rules,
	match_cmd_table,
	match_cmd_table,
	match_cmd_table,
	match_cmd_get_ports,
	match_cmd_get_lport,
	match_cmd_get_phys_port,
	match_cmd_set_ports,
};

int matchd_rx_process(struct nlmsghdr *nlh)
{
	struct genlmsghdr *glh = nlmsg_data(nlh);
	int err;

	if (nlh->nlmsg_type != family) {
		err = -EINVAL;
		goto out;
	}

	if (glh->cmd > NET_MAT_CMD_MAX) {
		err = -EOPNOTSUPP;
		goto out;
	}

	if (type_cb[glh->cmd] == NULL) {
		err = -EOPNOTSUPP;
		goto out;
	}

	err = type_cb[glh->cmd](nlh);
out:
	return (err < 0) ? send_error(nlh, -err) : err;
}

int matchd_uninit(void)
{
	/* Free up memory which was allocated using calloc, malloc, etc.. */

	if (backend != NULL)
		match_backend_close(backend);

	return 0;
}

int matchd_init(struct nl_sock *sock, int family_id,
	       const char *backend_name, void *init_arg)
{
	int rc = 0;

#ifdef MATCHD_MOCK_SUPPORT
	int i;
#endif
	nsd = sock;
	family = family_id;

	if (family < NLMSG_MIN_TYPE) {
		MAT_LOG(ERR, "Error: invalid netlink family id\n");
		return -EINVAL;
	}

	backend = match_backend_open(backend_name, init_arg);
	if (!backend) {
		MAT_LOG(ERR, "Error: cannot open backend\n");
		return -EINVAL;
	}

#ifdef MATCHD_MOCK_SUPPORT
	for (i = 0; backend->tbls[i]; i++)
		matchd_mock_tables[i+1] = calloc(1 + backend->tbls[i]->size,
						sizeof(struct net_mat_rule));
	for (i = 0; backend->tbls[i]; i++)
		my_dyn_table_list[backend->tbls[i]->uid] = *backend->tbls[i];
#endif

	return rc;
}
