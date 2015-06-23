/*******************************************************************************
  MATCH Library - Helpers for working on match action tables API
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

#ifndef _MATCHLIB_H
#define _MATCHLIB_H

#include <linux/netlink.h>

#define PRINT_GRAPHVIZ 2

#define __unused __attribute__((__unused__))

struct nl_msg;

int match_get_field(FILE *fp, int print, struct nlattr *nl,
		struct net_mat_field_ref *ref);

int match_get_matches(FILE *fp, int print, struct nlattr *nl,
		struct net_mat_field_ref **ref);

int match_get_action(FILE *fp, int p, struct nlattr *nl,
		struct net_mat_action *a);

int match_get_actions(FILE  *fp, int print, struct nlattr *nl,
		struct net_mat_action **actions);

int match_get_headers(FILE *fp, int print, struct nlattr *nl,
		struct net_mat_hdr **headers);

int match_get_rules(FILE *fp, int print, struct nlattr *attr,
		struct net_mat_rule **f);

int match_get_table(FILE *fp, int print, struct nlattr *nl,
		struct net_mat_tbl *t);

int match_get_tables(FILE *fp, int print, struct nlattr *nl,
		struct net_mat_tbl **t);

int match_get_table_field(FILE *fp, int print, struct nlattr *nl,
		struct net_mat_hdr *hdr);

int match_get_tbl_graph(FILE *fp, int p, struct nlattr *nl,
		struct net_mat_tbl_node **ref);

int match_get_hdrs_graph(FILE *fp, int p, struct nlattr *nl,
		struct net_mat_hdr_node **ref);
int match_get_ports(FILE *fp, int p, struct nlattr *nl,
		struct net_mat_port **ports);
int match_get_port(FILE *fp, int p, struct nlattr *nl,
		  struct net_mat_port *ports);

unsigned int match_get_rule_errors(struct nlattr *nl);

int match_put_field_ref(struct nl_msg *nlbuf, struct net_mat_field_ref *ref);

int match_put_matches(struct nl_msg *nlbuf,
		struct net_mat_field_ref *ref, int type);

int match_put_action(struct nl_msg *nlbuf, struct net_mat_action *ref);
int match_put_actions(struct nl_msg *nlbuf, struct net_mat_action **actions);
int match_put_headers(struct nl_msg *nlbuf, struct net_mat_hdr **header);
int match_put_rules(struct nl_msg *nlbuf, struct net_mat_rule *rule);
int match_put_rule(struct nl_msg *nlbuf, struct net_mat_rule *ref);
int match_put_rule_error(struct nl_msg *nlbuf, __u32 err);
int match_put_table(struct nl_msg *nlbuf, struct net_mat_tbl *t);
int match_put_tables(struct nl_msg *nlbuf, struct net_mat_tbl *t);
int match_put_table_graph(struct nl_msg *nlbuf, struct net_mat_tbl_node **ref);
int match_put_header_graph(struct nl_msg *nlbuf, struct net_mat_hdr_node **g);
int match_put_ports(struct nl_msg *nlbuf, struct net_mat_port *ports);
int match_put_port(struct nl_msg *nlbuf, struct net_mat_port *p);

void match_push_headers(struct net_mat_hdr **h);
void match_push_actions(struct net_mat_action **a);
void match_push_tables(struct net_mat_tbl **t);
void match_push_tables_a(struct net_mat_tbl *t);
void match_push_header_fields(struct net_mat_hdr **h);
void match_push_graph_nodes(struct net_mat_hdr_node **n);

void match_pop_tables(struct net_mat_tbl **t);

int find_match(char *header, char *field, unsigned int *hi, unsigned int *li);
unsigned int find_action(char *name);
unsigned int find_table(char *name);
unsigned int find_header_node(char *name);
unsigned int find_field(char *name, unsigned int hdr);

void pp_action(FILE *fp, int p, struct net_mat_action *ref,
	       bool print_values);
void pp_actions(FILE *fp, int print, struct net_mat_action *actions);
void pp_table(FILE *fp, int p, struct net_mat_tbl *ref);
void pp_header(FILE *fp, int p, struct net_mat_hdr *ref);
void pp_rules(FILE *fp, int p, struct net_mat_rule *ref);
void pp_rule(FILE *fp, int p, struct net_mat_rule *ref);
void pp_table_graph(FILE *fp, int p, struct net_mat_tbl_node *nodes);
void pp_ports(FILE *fp, int p, struct net_mat_port *port);
void pp_port(FILE *fp, int p, struct net_mat_port *port);
void pp_header_graph(FILE *fp, int print,
                struct net_mat_hdr_node *nodes);

struct net_mat_hdr *get_headers(unsigned int uid);
struct net_mat_field *get_fields(unsigned int huid, unsigned int uid);
struct net_mat_tbl *get_tables(unsigned int uid);
struct net_mat_action *get_actions(unsigned int uid);
struct net_mat_hdr_node *get_graph_node(unsigned int uid);

char *headers_names(unsigned int uid);
char *fields_names(unsigned int hid, unsigned int uid);
char *table_names(unsigned int uid);
char *action_names(unsigned int uid);

unsigned int gen_table_id(void);
unsigned int get_table_id(char *name);

#endif /* _MATCHLIB_H */
