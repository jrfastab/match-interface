/*******************************************************************************
  IES Library - Functions to program the switch using IES API
  Author: Hao Zheng <hao.zheng@intel.com>
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

#ifndef _IESLIB_H
#define _IESLIB_H

#define __unused __attribute__((__unused__))

struct switch_args {
	bool single_vlan;
	bool disable_switch_init;
	bool disable_switch_router_init;
	bool disable_switch_tunnel_engine_a_init;
	bool disable_switch_tunnel_engine_b_init;
};

struct my_ecmp_group {
	int hw_group_id;
	int num_nhs;
};

#ifdef VXLAN_MCAST
typedef enum {
	FLOW_MCAST_LISTENER_PORT_VLAN = 0,
	FLOW_MCAST_LISTENER_FLOW_TUNNEL,
	FLOW_MCAST_LISTENER_MAX,
} my_mcast_listener_type;

struct my_mcast_listener {
	union {
		struct {
			int vlan;
			int port;
		} p;
		struct {
			int table;
			int flow;
		} f;
	} l;

	my_mcast_listener_type t;
};
#endif /* VXLAN_MCAST */

int switch_init(bool one_vlan);

void switch_close(void);

int switch_router_init(__u64 router_mac, int update_dmac, int update_smac,
		       int update_vlan, int update_ttl, int curr_sw);

int switch_configure_tunnel_engine(int te, __u64 smac, __u64 dmac, __u16 l4dst, __u16 parser_vxlan_port,
                                   __u16 l4dst_nsh, __u16 parser_nsh_port);

int switch_tunnel_engine_set_default_nge_port(int te, __u16 port);

int switch_tunnel_engine_set_default_smac(int te, __u64 smac);

int switch_tunnel_engine_set_default_dmac(int te, __u64 dmac);

void switch_debug(int on);

int switch_get_rule_counters(__u32 ruleid, __u32 switch_table_id,
		__u64 *pkts, __u64 *octets);

int switch_add_nh_entry(struct net_mat_field_ref *matches,
			struct net_mat_action *actions);

int switch_del_nh_entry(struct net_mat_field_ref *matches,
			struct net_mat_action *actions);

int switch_add_mac_entry(struct net_mat_field_ref *matches,
		struct net_mat_action *actions);

int switch_del_mac_entry(int vlan, __u64 mac);

int switch_create_TCAM_table(__u32 table_id, struct net_mat_field_ref *matches,
			     __u32 *actions, __u32 size, int max_actions);

int switch_del_TCAM_table(__u32 table_id);

int switch_add_TCAM_rule_entry(__u32 *hw_ruleid, __u32 table_id, __u32 priority,
		struct net_mat_field_ref *matches,
		struct net_mat_action *actions);

int switch_del_TCAM_rule_entry(__u32 ruleid, __u32 switch_table_id);

int switch_create_TE_table(int te, __u32 table_id, struct net_mat_field_ref *matches, 
			   __u32 *actions, __u32 size, int max_actions);

int switch_del_TE_table(__u32 table_id);

int switch_add_TE_rule_entry(__u32 *ruleid, __u32 table_id, __u32 priority,
			     struct net_mat_field_ref *matches,
			     struct net_mat_action *actions);

int switch_del_TE_rule_entry(__u32 ruleid, __u32 switch_table_id);

int switch_add_L2MP_rule_entry(struct net_mat_field_ref *matches,
			       struct net_mat_action *actions);

int switch_del_L2MP_rule_entry(struct net_mat_field_ref *matches);

#endif /* _IESLIB_H */
