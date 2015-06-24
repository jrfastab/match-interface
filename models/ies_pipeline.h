/*******************************************************************************
  IES Pipeline - A pipeline model for IES
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

#ifndef _IES_PIPELINE_H
#define _IES_PIPELINE_H

#include "if_match.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array)/sizeof(array[0]))
#endif /* ARRAY_SIZE */

/********************************************************************
 * HEADER DEFINITIONS
 *******************************************************************/
static char src_mac[] =  "src_mac";
static char dst_mac[] =  "dst_mac";
static char ethertype[] =  "ethertype";
static char ether_str[] =  "ethernet";
static char ether_inner_str[] =  "ethernet_inner";
static char pcp[] = "pcp";
static char cfi[] = "cfi";
static char vid[] = "vid";
static char vlan_str[] = "vlan";
static char vlan_inner_str[] = "vlan_inner";
static char reserved1[] = "reserved1";
static char vni[] = "vni";
static char reserved2[] = "reserved2";
static char vxlan_str[] = "vxlan";
static char vxlan_src_port_str[] = "vxlan_src_port";
static char vxlan_dst_port_str[] = "vxlan_dst_port";
static char vxlan_src_mac_str[] = "vxlan_src_mac";
static char vxlan_dst_mac_str[] = "vxlan_dst_mac";
static char te_miss_dflt_port_str[] = "miss_default_port";
static char version[] = "version";
static char ihl[] = "ihl";
static char dscp[] = "dscp";
static char ecn[] = "ecn";
static char length[] = "length";
static char ident[] = "identification";
static char flags[] = "flags";
static char frag_off[] = "fragment_offset";
static char ttl[] = "ttl";
static char protocol[] = "protocol";
static char csum_str[] = "csum";
static char src_ip[] = "src_ip";
static char dst_ip[] = "dst_ip";
static char options[] = "options";
static char ipv4_str[] = "ipv4";
static char ipv4_inner_str[] = "ipv4_inner";
static char src_port[] = "src_port";
static char dst_port[] = "dst_port";
static char seq_str[] = "seq";
static char ack[] = "ack";
static char offset[] = "offset";
static char reserved[] = "reserved";
static char window[] = "window";
static char urgent[] = "urgent";
static char tcp_str[] = "tcp";
static char tcp_inner_str[] = "tcp_inner";
static char udp_str[] = "udp";
static char udp_inner_str[] = "udp_inner";
static char ingress_port[] = "ingress_port";
static char metadata_t_str[] = "metadata_t";
static char egress_port[] = "egress_port";
static char empty[] = "";
static char set_egress_port_str[] = "set_egress_port";
static char drop_str[] = "drop_packet";
static char ecmp_group_id[] = "ecmp_group_id";
static char route_via_ecmp_str[] = "route_via_ecmp";
static char newDMAC[] = "newDMAC";
static char newVLAN[] = "newVLAN";
static char route_str[] = "route";
static char mac_address[] = "mac_address";
static char set_dst_mac_str[] = "set_dst_mac";
static char set_src_mac_str[] = "set_src_mac";
static char set_ip_addr_args[] = "ip_address";
static char set_port_args_str[] = "port";
static char set_ipv4_dst_ip_str[] = "set_ipv4_dst_ip";
static char set_ipv4_src_ip_str[] = "set_ipv4_src_ip";
static char set_udp_port_src_port_str[] = "set_udp_src_port";
static char set_udp_port_dst_port_str[] = "set_udp_dst_port";
static char set_tcp_port_src_port_str[] = "set_tcp_src_port";
static char set_tcp_port_dst_port_str[] = "set_tcp_dst_port";
static char count_str[] = "count";
static char set_vlan_str[] = "set_vlan";
static char normal_str[] = "normal";
static char trap_str[] = "trap";
static char forward_to_te_a_str[] = "forward_to_tunnel_engine_A";
static char forward_to_te_b_str[] = "forward_to_tunnel_engine_B";
static char forward_direct_to_te_a_str[] = "forward_direct_to_tunnel_engine_A";
static char forward_direct_to_te_b_str[] = "forward_direct_to_tunnel_engine_B";
static char forward_to_l2_mp_args_str[] = "sub-table";
static char forward_to_l2_mp_str[] = "forward_to_l2_mp";
static char forward_to_te_args_str[] = "sub-table";
static char direct_index_to_te_str[] = "index";
static char direct_index[] = "direct_index";
static char direct_index_metadata[] = "direct_index_metadata";
static char goto_l2_mp[] = "goto_l2_multipath";
static char goto_te_a[] = "goto_te_a";
static char goto_te_b[] = "goto_te_b";
static char nexthop[] = "nexthop";
static char mac[] = "mac";
static char tcam[] = "tcam";
static char tunnel_engine_a[] = "tunnel_engineA";
static char tunnel_engine_b[] = "tunnel_engineB";
static char routing_metadata[] = "routing_metadata";
static char ig_port_metadata[] = "ig_port_metadata";
static char te_metadata_a[] = "goto_tunnel_endpoint_a_metadata";
static char te_metadata_b[] = "goto_tunnel_endpoint_b_metadata";
static char l2mp_metadata[] = "goto_l2_multipath_metadata";
static char tunnel_encap_str[] = "tunnel_encap";
static char tunnel_decap_str[] = "tunnel_decap";
#ifdef PORT_TO_VNI
static char port_to_vni[] = "port_to_vni";
static char forward_to_port_to_vni_str[] = "forward_to_port_to_vni";
#endif
static char l2_mp_str[] = "L2 load_balancer_groups";
static char pci_bus_str[] = "pci_bus";
static char pci_device_str[] = "pci_device";
static char pci_function_str[] = "pci_function";
static char forward_vsi_str[] = "forward_vsi";
static char egress_set_str[] = "egress_set";
static char egress_ports_str[] = "port";
static char service_path_id[] = "service_path_id";
static char service_index[] = "service_index";
static char tunnel_encap_nsh_str[] = "tunnel_encap_nsh";
static char tunnel_decap_nsh_str[] = "tunnel_decap_nsh";

enum ies_header_ids {
	HEADER_ETHERNET = 1,
	HEADER_VLAN,
	HEADER_VXLAN,
	HEADER_IPV4,
	HEADER_TCP,
	HEADER_UDP,
	HEADER_METADATA,
};

enum ies_header_ethernet_ids {
	HEADER_ETHERNET_SRC_MAC = 1,
	HEADER_ETHERNET_DST_MAC,
	HEADER_ETHERNET_ETHERTYPE,
};

static struct net_mat_field ethernet_fields[3] = {
	{ .name = src_mac, .uid = HEADER_ETHERNET_SRC_MAC, .bitwidth = 48},
	{ .name = dst_mac, .uid = HEADER_ETHERNET_DST_MAC, .bitwidth = 48},
	{ .name = ethertype, .uid = HEADER_ETHERNET_ETHERTYPE, .bitwidth = 16},
};

static struct net_mat_hdr ethernet = {
	.name = ether_str,
	.uid = HEADER_ETHERNET,
	.field_sz = ARRAY_SIZE(ethernet_fields),
	.fields = ethernet_fields,
};

enum ies_header_vlan_ids {
	HEADER_VLAN_PCP = 1,
	HEADER_VLAN_CFI,
	HEADER_VLAN_VID,
	HEADER_VLAN_ETHERTYPE,
};

static struct net_mat_field vlan_fields[4] = {
	{ .name = pcp, .uid = HEADER_VLAN_PCP, .bitwidth = 3,},
	{ .name = cfi, .uid = HEADER_VLAN_CFI, .bitwidth = 1,},
	{ .name = vid, .uid = HEADER_VLAN_VID, .bitwidth = 12,},
	{ .name = ethertype, .uid = HEADER_VLAN_ETHERTYPE, .bitwidth = 16,},
};

static struct net_mat_hdr vlan = {
	.name = vlan_str,
	.uid = HEADER_VLAN,
	.field_sz = ARRAY_SIZE(vlan_fields),
	.fields = vlan_fields,
};

enum ies_header_vxlan_ids {
	HEADER_VXLAN_FLAGS = 1,
	HEADER_VXLAN_RESERVED1,
	HEADER_VXLAN_VNI,
	HEADER_VXLAN_RESERVED2,
};

static struct net_mat_field vxlan_fields[] = {
	{ .name = flags, .uid = HEADER_VXLAN_FLAGS, .bitwidth = 8,},
	{ .name = reserved1, .uid = HEADER_VXLAN_RESERVED1, .bitwidth = 24,},
	{ .name = vni, .uid = HEADER_VXLAN_VNI, .bitwidth = 24,},
	{ .name = reserved2, .uid = HEADER_VXLAN_RESERVED2, .bitwidth = 8,},
};

static struct net_mat_hdr vxlan = {
	.name = vxlan_str,
	.uid = HEADER_VXLAN,
	.field_sz = ARRAY_SIZE(vxlan_fields),
	.fields = vxlan_fields,
};

enum ies_header_ipv4_ids {
	HEADER_IPV4_VERSION = 1,
	HEADER_IPV4_IHL,
	HEADER_IPV4_DSCP,
	HEADER_IPV4_ECN,
	HEADER_IPV4_LENGTH,
	HEADER_IPV4_IDENTIFICATION,
	HEADER_IPV4_FLAGS,
	HEADER_IPV4_FRAGMENT_OFFSET,
	HEADER_IPV4_TTL,
	HEADER_IPV4_PROTOCOL,
	HEADER_IPV4_CSUM,
	HEADER_IPV4_SRC_IP,
	HEADER_IPV4_DST_IP,
	HEADER_IPV4_OPTIONS,
};

static struct net_mat_field ipv4_fields[14] = {
	{ .name = version,
	  .uid = HEADER_IPV4_VERSION,
	  .bitwidth = 4,},
	{ .name = ihl,
	  .uid = HEADER_IPV4_IHL,
	  .bitwidth = 4,},
	{ .name = dscp,
	  .uid = HEADER_IPV4_DSCP,
	  .bitwidth = 6,},
	{ .name = ecn,
	  .uid = HEADER_IPV4_ECN,
	  .bitwidth = 2,},
	{ .name = length,
	  .uid = HEADER_IPV4_LENGTH,
	  .bitwidth = 8,},
	{ .name = ident,
	  .uid = HEADER_IPV4_IDENTIFICATION,
	  .bitwidth = 8,},
	{ .name = flags,
	  .uid = HEADER_IPV4_FLAGS,
	  .bitwidth = 3,},
	{ .name = frag_off,
	  .uid = HEADER_IPV4_FRAGMENT_OFFSET,
	  .bitwidth = 13,},
	{ .name = ttl,
	  .uid = HEADER_IPV4_TTL,
	  .bitwidth = 1,},
	{ .name = protocol,
	  .uid = HEADER_IPV4_PROTOCOL,
	  .bitwidth = 8,},
	{ .name = csum_str,
	  .uid = HEADER_IPV4_CSUM,
	  .bitwidth = 8,},
	{ .name = src_ip,
	  .uid = HEADER_IPV4_SRC_IP,
	  .bitwidth = 32,},
	{ .name = dst_ip,
	  .uid = HEADER_IPV4_DST_IP,
	  .bitwidth = 32,},
	{ .name = options,
	  .uid = HEADER_IPV4_OPTIONS,
	  .bitwidth = 0,},
	/* TBD options */
};

static struct net_mat_hdr ipv4 = {
	.name = ipv4_str,
	.uid = HEADER_IPV4,
	.field_sz = ARRAY_SIZE(ipv4_fields),
	.fields = ipv4_fields,
};

enum ies_header_tcp_ids {
	HEADER_TCP_SRC_PORT = 1,
	HEADER_TCP_DST_PORT,
	HEADER_TCP_SEQ,
	HEADER_TCP_ACK,
	HEADER_TCP_OFFSET,
	HEADER_TCP_RESERVED,
	HEADER_TCP_FLAGS,
	HEADER_TCP_WINDOW,
	HEADER_TCP_CSUM,
	HEADER_TCP_URGENT,
};

static struct net_mat_field tcp_fields[10] = {
	{ .name = src_port,
	  .uid = HEADER_TCP_SRC_PORT,
	  .bitwidth = 16,
	},
	{ .name = dst_port,
	  .uid = HEADER_TCP_DST_PORT,
	  .bitwidth = 16,
	},
	{ .name = seq_str,
	  .uid = HEADER_TCP_SEQ,
	  .bitwidth = 32,
	},
	{ .name = ack,
	  .uid = HEADER_TCP_ACK,
	  .bitwidth = 32,
	},
	{ .name = offset,
	  .uid = HEADER_TCP_OFFSET,
	  .bitwidth = 4,
	},
	{ .name = reserved,
	  .uid = HEADER_TCP_RESERVED,
	  .bitwidth = 3},
	{ .name = flags,
	  .uid = HEADER_TCP_FLAGS,
	  .bitwidth = 9},
	{ .name = window,
	  .uid = HEADER_TCP_WINDOW,
	  .bitwidth = 8,},
	{ .name = csum_str,
	  .uid = HEADER_TCP_CSUM,
	  .bitwidth = 16,},
	{ .name = urgent,
	  .uid = HEADER_TCP_URGENT,
	  .bitwidth = 16},
	/* TBD options */
};

static struct net_mat_hdr tcp = {
	.name = tcp_str,
	.uid = HEADER_TCP,
	.field_sz = ARRAY_SIZE(tcp_fields),
	.fields = tcp_fields,
};

enum ies_header_udp_ids {
	HEADER_UDP_SRC_PORT = 1,
	HEADER_UDP_DST_PORT,
	HEADER_UDP_LENGTH,
	HEADER_UDP_CSUM,
};

static struct net_mat_field udp_fields[4] = {
	{ .name = src_port,
	  .uid = HEADER_UDP_SRC_PORT,
	  .bitwidth = 16},
	{ .name = dst_port,
	  .uid = HEADER_UDP_DST_PORT,
	  .bitwidth = 16},
	{ .name = length,
	  .uid = HEADER_UDP_LENGTH,
	  .bitwidth = 16},
	{ .name = csum_str,
	  .uid = HEADER_UDP_CSUM,
	  .bitwidth = 16},
};

static struct net_mat_hdr udp = {
	.name = udp_str,
	.uid = HEADER_UDP,
	.field_sz = ARRAY_SIZE(udp_fields),
	.fields = udp_fields,
};

enum ies_header_metadata_ids {
	HEADER_METADATA_INGRESS_PORT = 1,
	HEADER_METADATA_ECMP_GROUP_ID,
	HEADER_METADATA_TE_A,
	HEADER_METADATA_TE_B,
	HEADER_METADATA_DIRECT_INDEX,
	HEADER_METADATA_L2_MP,
};

static struct net_mat_field metadata_fields[] = {
	{ .name = ingress_port,
	  .uid = HEADER_METADATA_INGRESS_PORT,
	  .bitwidth = 32,},
	{ .name = ecmp_group_id,
	  .uid = HEADER_METADATA_ECMP_GROUP_ID,
	  .bitwidth = 32,},
	{ .name = goto_te_a,
	  .uid = HEADER_METADATA_TE_A,
	  .bitwidth = 16,},
	{ .name = goto_te_b,
	  .uid = HEADER_METADATA_TE_B,
	  .bitwidth = 16,},
	{ .name = direct_index,
	  .uid = HEADER_METADATA_DIRECT_INDEX,
	  .bitwidth = 16,},
	{ .name = goto_l2_mp,
	  .uid = HEADER_METADATA_L2_MP,
	  .bitwidth = 32,},
};

static struct net_mat_hdr metadata_t = {
	.name = metadata_t_str,
	.uid = HEADER_METADATA,
	.field_sz = ARRAY_SIZE(metadata_fields),
	.fields = metadata_fields,
};

static struct net_mat_hdr *my_header_list[] = {
	&ethernet,
	&vlan,
	&ipv4,
	&tcp,
	&udp,
	&vxlan,
	&metadata_t,
	NULL,
};

/********************************************************************
 * ACTION DEFINITIONS
 *******************************************************************/

enum ies_pipeline_action_ids {
	ACTION_SET_EGRESS_PORT = 1,
	ACTION_SET_SRC_MAC,
	ACTION_SET_DST_MAC,
	ACTION_SET_VLAN,
	ACTION_SET_IPV4_DST_IP,
	ACTION_SET_IPV4_SRC_IP,
	ACTION_SET_TCP_DST_PORT,
	ACTION_SET_TCP_SRC_PORT,
	ACTION_SET_UDP_DST_PORT,
	ACTION_SET_UDP_SRC_PORT,
	ACTION_NORMAL,
	ACTION_TRAP,
	ACTION_DROP_PACKET,
	ACTION_ROUTE_VIA_ECMP,
	ACTION_ROUTE,
	ACTION_COUNT,
	ACTION_TUNNEL_ENCAP,
	ACTION_TUNNEL_DECAP,
	ACTION_FORWARD_TO_TE_A,
	ACTION_FORWARD_TO_TE_B,
	ACTION_FORWARD_DIRECT_TO_TE_A,
	ACTION_FORWARD_DIRECT_TO_TE_B,
	ACTION_FORWARD_TO_L2MPATH,
	ACTION_FORWARD_VSI,
	ACTION_SET_EGRESS_SET_V,
	ACTION_TUNNEL_ENCAP_NSH,
	ACTION_TUNNEL_DECAP_NSH,
};

static struct net_mat_action_arg set_egress_port_args[] = {
	{
		.name = egress_port,
		.type = NET_MAT_ACTION_ARG_TYPE_U32,
		.v.value_u32 = 0,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,
	},
};

static struct net_mat_action set_egress_port = {
	.name = set_egress_port_str,
	.uid = ACTION_SET_EGRESS_PORT,
	.args = set_egress_port_args,
};

static struct net_mat_action drop_packet = {
	.name = drop_str,
	.uid = ACTION_DROP_PACKET,
	.args = NULL,
};

static struct net_mat_action_arg route_via_ecmp_args[] = {
	{ .name = ecmp_group_id,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action route_via_ecmp = {
	.name = route_via_ecmp_str,
	.uid = ACTION_ROUTE_VIA_ECMP,
	.args = route_via_ecmp_args,
};

static struct net_mat_action_arg route_args[] = {
	{ .name = newDMAC,
	  .type = NET_MAT_ACTION_ARG_TYPE_U64,},
	{ .name = newVLAN,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action route = {
	.name = route_str,
	.uid = ACTION_ROUTE,
	.args = route_args,
};

static struct net_mat_action_arg set_mac_args[] = {
	{ .name = mac_address,
	  .type = NET_MAT_ACTION_ARG_TYPE_U64,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action set_dst_mac = {
	.name = set_dst_mac_str,
	.uid = ACTION_SET_DST_MAC,
	.args = set_mac_args,
};

static struct net_mat_action set_src_mac = {
	.name = set_src_mac_str,
	.uid = ACTION_SET_SRC_MAC,
	.args = set_mac_args,
};

static struct net_mat_action_arg set_ip_args[] = {
	{ .name = set_ip_addr_args,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action set_ipv4_dst_ip = {
	.name = set_ipv4_dst_ip_str,
	.uid = ACTION_SET_IPV4_DST_IP,
	.args = set_ip_args,
};

static struct net_mat_action set_ipv4_src_ip = {
	.name = set_ipv4_src_ip_str,
	.uid = ACTION_SET_IPV4_SRC_IP,
	.args = set_ip_args,
};

static struct net_mat_action_arg set_port_args[] = {
	{ .name = set_port_args_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action set_udp_src_port = {
	.name = set_udp_port_src_port_str,
	.uid = ACTION_SET_UDP_SRC_PORT,
	.args = set_port_args,
};

static struct net_mat_action set_udp_dst_port = {
	.name = set_udp_port_dst_port_str,
	.uid = ACTION_SET_UDP_DST_PORT,
	.args = set_port_args,
};

static struct net_mat_action set_tcp_src_port = {
	.name = set_tcp_port_src_port_str,
	.uid = ACTION_SET_TCP_SRC_PORT,
	.args = set_port_args,
};

static struct net_mat_action set_tcp_dst_port = {
	.name = set_tcp_port_dst_port_str,
	.uid = ACTION_SET_TCP_DST_PORT,
	.args = set_port_args,
};

static struct net_mat_action normal = {
	.name = normal_str,
	.uid = ACTION_NORMAL,
	.args = NULL,
};

static struct net_mat_action trap = {
	.name = trap_str,
	.uid = ACTION_TRAP,
	.args = NULL,
};

static struct net_mat_action_arg forward_to_te_args[] = {
	{ .name = forward_to_te_args_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action forward_to_te_a = {
	.name = forward_to_te_a_str,
	.uid = ACTION_FORWARD_TO_TE_A,
	.args = forward_to_te_args,
};

static struct net_mat_action forward_to_te_b = {
	.name = forward_to_te_b_str,
	.uid = ACTION_FORWARD_TO_TE_B,
	.args = forward_to_te_args,
};

static struct net_mat_action_arg forward_direct_to_te_args[] = {
	{ .name = forward_to_te_args_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = direct_index_to_te_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action forward_direct_to_te_a = {
	.name = forward_direct_to_te_a_str,
	.uid = ACTION_FORWARD_DIRECT_TO_TE_A,
	.args = forward_direct_to_te_args,
};

static struct net_mat_action forward_direct_to_te_b = {
	.name = forward_direct_to_te_b_str,
	.uid = ACTION_FORWARD_DIRECT_TO_TE_B,
	.args = forward_direct_to_te_args,
};

static struct net_mat_action_arg forward_to_l2_mp_args[] = {
	{ .name = forward_to_l2_mp_args_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action forward_to_l2_mp = {
	.name = forward_to_l2_mp_str,
	.uid = ACTION_FORWARD_TO_L2MPATH,
	.args = forward_to_l2_mp_args,
};

static struct net_mat_action count = {
	.name = count_str,
	.uid = ACTION_COUNT,
	.args = NULL,
};

#ifdef PORT_TO_VNI
static struct net_mat_action forward_to_port_to_vni = {
	.name = forward_to_port_to_vni_str,
	.uid = ACTION_FORWARD_TO_PORT_TO_VNI,
	.args = NULL,
};
#endif

static struct net_mat_action_arg set_vlan_args[] = {
	{ .name = vlan_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action set_vlan = {
	.name = set_vlan_str,
	.uid = ACTION_SET_VLAN,
	.args = set_vlan_args,
};

static struct net_mat_action_arg tunnel_encap_args[] = {
	{ .name = dst_ip,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = src_ip,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = vni,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = src_port,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = dst_port,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action_arg forward_vsi_args[] = {
	{ .name = pci_bus_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U8,},
	{ .name = pci_device_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U8,},
	{ .name = pci_function_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U8,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action tunnel_encap = {
	.name = tunnel_encap_str,
	.uid = ACTION_TUNNEL_ENCAP,
	.args = tunnel_encap_args,
};

static struct net_mat_action tunnel_decap = {
	.name = tunnel_decap_str,
	.uid = ACTION_TUNNEL_DECAP,
	.args = NULL,
};

static struct net_mat_action forward_vsi = {
	.name = forward_vsi_str,
	.uid = ACTION_FORWARD_VSI,
	.args = forward_vsi_args,
};

static struct net_mat_action_arg egress_set_args[] = {
	{ .name = egress_ports_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = egress_ports_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_VARIADIC,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action egress_set = {
	.name = egress_set_str,
	.uid = ACTION_SET_EGRESS_SET_V,
	.args = egress_set_args,
};

static struct net_mat_action_arg tunnel_encap_nsh_args[] = {
	{ .name = dst_ip,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = src_ip,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = vni,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = src_port,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = dst_port,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = service_index,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = service_path_id,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_UNSPEC,},
};

static struct net_mat_action tunnel_encap_nsh = {
	.name = tunnel_encap_nsh_str,
	.uid = ACTION_TUNNEL_ENCAP_NSH,
	.args = tunnel_encap_nsh_args,
};

static struct net_mat_action tunnel_decap_nsh = {
	.name = tunnel_decap_nsh_str,
	.uid = ACTION_TUNNEL_DECAP_NSH,
	.args = NULL,
};

static struct net_mat_action *my_action_list[] = {
	&set_egress_port,
	&drop_packet,
	&route_via_ecmp,
	&route,
	&set_dst_mac,
	&set_src_mac,
	&set_ipv4_dst_ip,
	&set_ipv4_src_ip,
	&set_udp_src_port,
	&set_udp_dst_port,
	&set_tcp_src_port,
	&set_tcp_dst_port,
	&normal,
	&trap,
	&count,
	&set_vlan,
	&tunnel_encap,
	&tunnel_decap,
	&forward_to_te_a,
	&forward_to_te_b,
	&forward_direct_to_te_a,
	&forward_direct_to_te_b,
#ifdef PORT_TO_VNI
	&forward_to_port_to_vni,
#endif
	&forward_to_l2_mp,
	&forward_vsi,
	&egress_set,
	&tunnel_encap_nsh,
	&tunnel_decap_nsh,
	NULL,
};

/********************************************************************
 * TABLE DEFINITIONS
 *******************************************************************/
enum ies_header_instance {
	HEADER_INSTANCE_ETHERNET = 1,
	HEADER_INSTANCE_VLAN_OUTER,
	HEADER_INSTANCE_VLAN_INNER,
	HEADER_INSTANCE_IPV4,
	HEADER_INSTANCE_TCP,
	HEADER_INSTANCE_UDP,
	HEADER_INSTANCE_VXLAN,
	HEADER_INSTANCE_ETHERNET_INNER,
	HEADER_INSTANCE_VLAN_OUTER_INNER,
	HEADER_INSTANCE_VLAN_INNER_INNER,
	HEADER_INSTANCE_IPV4_INNER,
	HEADER_INSTANCE_TCP_INNER,
	HEADER_INSTANCE_UDP_INNER,
	HEADER_INSTANCE_ROUTING_METADATA,
	HEADER_INSTANCE_INGRESS_PORT_METADATA,
	HEADER_INSTANCE_TE_A_METADATA,
	HEADER_INSTANCE_TE_B_METADATA,
	HEADER_INSTANCE_DIRECT_INDEX_METADATA,
	HEADER_INSTANCE_L2_MP_METADATA
};

static struct net_mat_field_ref matches_nexthop[] = {
	{ .instance = HEADER_INSTANCE_ROUTING_METADATA,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_ECMP_GROUP_ID,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = 0, .field = 0},
};

static struct net_mat_field_ref matches_mac[] = {
	{ .instance = HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_DST_MAC,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_VID,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = 0, .field = 0},
};

#ifdef PORT_TO_VNI
static struct net_mat_field_ref matches_vni[] = {
	{ .instance = HEADER_INSTANCE_INGRESS_PORT_METADATA,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_INGRESS_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = 0, .field = 0},
};
#endif

static struct net_mat_field_ref matches_l2_mp[] = {
	{ .instance = HEADER_INSTANCE_L2_MP_METADATA,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_L2_MP,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = 0, .field = 0},
};

static struct net_mat_field_ref matches_tunnel_engine[] = {
	{ .instance = HEADER_INSTANCE_DIRECT_INDEX_METADATA,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_DIRECT_INDEX,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_DST_MAC,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_SRC_MAC,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_SRC_IP,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_DST_IP,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_UDP,
	  .header = HEADER_UDP,
	  .field = HEADER_UDP_SRC_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_UDP,
	  .header = HEADER_UDP,
	  .field = HEADER_UDP_DST_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_TCP,
	  .header = HEADER_TCP,
	  .field = HEADER_TCP_SRC_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_TCP,
	  .header = HEADER_TCP,
	  .field = HEADER_TCP_DST_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = HEADER_INSTANCE_VXLAN,
	  .header = HEADER_VXLAN,
	  .field = HEADER_VXLAN_VNI,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},

	{ .instance = 0, .field = 0},
};

static struct net_mat_field_ref matches_tcam[] = {
	{ .instance = HEADER_INSTANCE_INGRESS_PORT_METADATA,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_INGRESS_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_DST_MAC,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_SRC_MAC,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_ETHERTYPE,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

#ifdef NOT_IMPLEMENTED
	{ .instance = HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_PCP,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_CFI,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},
#endif /* NOT_IMPLEMENTED */

	{ .instance = HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_VID,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

#ifdef NOT_IMPLEMENTED
	{ .instance = HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_ETHERTYPE,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_DSCP,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_ECN,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_TTL,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},
#endif /* NOT_IMPLEMENTED */

	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_PROTOCOL,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_DST_IP,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_SRC_IP,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_TCP,
	  .header = HEADER_TCP,
	  .field = HEADER_TCP_SRC_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_TCP,
	  .header = HEADER_TCP,
	  .field = HEADER_TCP_DST_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

#ifdef NOT_IMPLEMENTED
	{ .instance = HEADER_INSTANCE_TCP,
	  .header = HEADER_TCP,
	  .field = HEADER_TCP_FLAGS,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},
#endif /* NOT_IMPLEMENTED */

	{ .instance = HEADER_INSTANCE_UDP,
	  .header = HEADER_UDP,
	  .field = HEADER_UDP_SRC_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_UDP,
	  .header = HEADER_UDP,
	  .field = HEADER_UDP_DST_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = HEADER_INSTANCE_VXLAN,
	  .header = HEADER_VXLAN,
	  .field = HEADER_VXLAN_VNI,
	  .mask_type = NET_MAT_MASK_TYPE_MASK},

	{ .instance = 0, .field = 0},
};

static __u32 actions_nexthop[] = {ACTION_ROUTE, 0};
static __u32 actions_mac[] = {ACTION_SET_EGRESS_PORT,
			      ACTION_FORWARD_VSI,
			      ACTION_FORWARD_TO_L2MPATH, 0};
static __u32 actions_tcam[] = {ACTION_SET_EGRESS_PORT, ACTION_ROUTE_VIA_ECMP,
			       ACTION_DROP_PACKET,
			       ACTION_SET_VLAN, ACTION_NORMAL, ACTION_TRAP,
			       ACTION_FORWARD_TO_TE_A, ACTION_FORWARD_TO_TE_B,
			       ACTION_FORWARD_DIRECT_TO_TE_A,
			       ACTION_FORWARD_DIRECT_TO_TE_B,
			       ACTION_COUNT, ACTION_FORWARD_VSI, 0};
static __u32 actions_tunnel_engine[] = {ACTION_TUNNEL_ENCAP,
					ACTION_TUNNEL_DECAP,
					ACTION_SET_EGRESS_PORT,
					ACTION_SET_DST_MAC,
					ACTION_SET_SRC_MAC,
					ACTION_SET_IPV4_DST_IP,
					ACTION_SET_IPV4_SRC_IP,
					ACTION_SET_TCP_DST_PORT,
					ACTION_SET_TCP_SRC_PORT,
					ACTION_SET_UDP_DST_PORT,
					ACTION_SET_UDP_SRC_PORT,
					ACTION_COUNT,
					ACTION_TUNNEL_ENCAP_NSH,
					ACTION_TUNNEL_DECAP_NSH,
					0};
#ifdef PORT_TO_VNI
static __u32 actions_vni[] = {ACTION_SET_VNI, 0};
#endif

static __u32 actions_l2_mp[] = {ACTION_SET_EGRESS_SET_V, 0};

enum ies_table_id {
	TABLE_TCAM = 1,
	TABLE_TUNNEL_ENGINE_A,
	TABLE_TUNNEL_ENGINE_B,
	TABLE_NEXTHOP,
	TABLE_MAC,
	TABLE_L2_MP,
	/* End of pre-defined tables */
	TABLE_DYN_START,
};

#define TABLE_NEXTHOP_SIZE		4096
#define TABLE_MAC_SIZE			2000
#define TABLE_TUNNEL_ENDPOINT_SIZE	2000
#ifdef PORT_TO_VNI
#define TABLE_PORT_TO_VNI_SIZE		2000
#endif
#define TABLE_TCAM_SIZE			4096
#define MATCH_TABLE_SIZE		4096
#ifdef VXLAN_MCAST
#define MAX_LISTENERS_PER_GROUP		1024
#endif
#define TABLE_L2_MP_SIZE		32

static struct net_mat_tbl my_table_nexthop = {
	.name = nexthop,
	.uid = TABLE_NEXTHOP,
	.source = TABLE_NEXTHOP,
	.apply_action = TABLE_NEXTHOP,
	.size = TABLE_NEXTHOP_SIZE,
	.matches = matches_nexthop,
	.actions = actions_nexthop,
};

static struct net_mat_tbl my_table_mac = {
	.name = mac,
	.uid = TABLE_MAC,
	.source = TABLE_MAC,
	.apply_action = TABLE_MAC,
	.size = TABLE_MAC_SIZE,
	.matches = matches_mac,
	.actions = actions_mac,
};

static struct net_mat_tbl my_table_tcam = {
	.name = tcam,
	.uid = TABLE_TCAM,
	.source = TABLE_TCAM,
	.apply_action = TABLE_TCAM,
	.size = TABLE_TCAM_SIZE,
	.matches = matches_tcam,
	.actions = actions_tcam,
};

#define IES_ROUTER_MAC 0x000102030405
#define IES_VXLAN_PORT 4198

#define IES_VXLAN_SRC_MAC 2
#define IES_VXLAN_DST_MAC 3
#define IES_VXLAN_MISS_DFLT_PORT 4

static struct net_mat_named_value values_tunnel_engine[] = {
	{ .name = vxlan_src_port_str,
	  .uid = NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_SRC_PORT,
	  .type = NET_MAT_NAMED_VALUE_TYPE_U32,
	  .value.u32 = IES_VXLAN_PORT,
	  .write = 0},
	{ .name = vxlan_dst_port_str,
	  .uid = NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_DST_PORT,
	  .type = NET_MAT_NAMED_VALUE_TYPE_U32,
	  .value.u32 = IES_VXLAN_PORT,
	  .write = 0},
	{ .name = vxlan_src_mac_str,
	  .uid = NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_SRC_MAC,
	  .type = NET_MAT_NAMED_VALUE_TYPE_U64,
	  .value.u64 = IES_ROUTER_MAC,
	  .write = NET_MAT_NAMED_VALUE_IS_WRITABLE},
	{ .name = vxlan_dst_mac_str,
	  .uid = NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_DST_MAC,
	  .type = NET_MAT_NAMED_VALUE_TYPE_U64,
	  .value.u64 = IES_ROUTER_MAC,
	  .write = NET_MAT_NAMED_VALUE_IS_WRITABLE},
	{ .name = te_miss_dflt_port_str,
	  .uid = NET_MAT_TABLE_ATTR_NAMED_VALUE_MISS_DFLT_EGRESS_PORT,
	  .type = NET_MAT_NAMED_VALUE_TYPE_U16,
	  .value.u16 = 0,
	  .write = NET_MAT_NAMED_VALUE_IS_WRITABLE},
	{ .name = NULL, .uid = 0 },
};

static struct net_mat_tbl my_table_tunnel_a = {
	.name = tunnel_engine_a,
	.uid = TABLE_TUNNEL_ENGINE_A,
	.source = TABLE_TUNNEL_ENGINE_A,
	.apply_action = TABLE_TUNNEL_ENGINE_A,
	.size = TABLE_TUNNEL_ENDPOINT_SIZE,
	.matches = matches_tunnel_engine,
	.actions = actions_tunnel_engine,
	.attribs = values_tunnel_engine,
};

static struct net_mat_tbl my_table_tunnel_b= {
	.name = tunnel_engine_b,
	.uid = TABLE_TUNNEL_ENGINE_B,
	.source = TABLE_TUNNEL_ENGINE_B,
	.apply_action = TABLE_TUNNEL_ENGINE_B,
	.size = TABLE_TUNNEL_ENDPOINT_SIZE,
	.matches = matches_tunnel_engine,
	.actions = actions_tunnel_engine,
	.attribs = values_tunnel_engine,
};

#ifdef PORT_TO_VNI
static struct net_mat_tbl my_table_vni = {
	.name = port_to_vni,
	.uid = TABLE_PORT_TO_VNI,
	.source = TABLE_PORT_TO_VNI,
	.apply_action = TABLE_PORT_TO_VNI,
	.size = TABLE_PORT_TO_VNI_SIZE,
	.matches = matches_vni,
	.actions = actions_vni,
};
#endif

static struct net_mat_tbl my_table_l2_mp = {
	.name = l2_mp_str,
	.uid = TABLE_L2_MP,
	.source = TABLE_L2_MP,
	.apply_action = TABLE_L2_MP,
	.size = TABLE_L2_MP_SIZE,
	.matches = matches_l2_mp,
	.actions = actions_l2_mp,
};

static struct net_mat_tbl *my_table_list[] = {
#ifdef PORT_TO_VNI
	&my_table_vni,
#endif
	&my_table_tcam,
	&my_table_tunnel_a,
	&my_table_tunnel_b,
	&my_table_nexthop,
	&my_table_mac,
	&my_table_l2_mp,
	NULL,
};

/********************************************************************
 * Jump Table
 ********************************************************************/

static struct net_mat_jump_table my_parse_ethernet[] = {
	{
		.node = HEADER_INSTANCE_IPV4,
		.field = {
			.header = HEADER_ETHERNET,
			.field = HEADER_ETHERNET_ETHERTYPE,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 0x0800,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = HEADER_INSTANCE_VLAN_OUTER,
		.field = {
			.header = HEADER_ETHERNET,
			.field = HEADER_ETHERNET_ETHERTYPE,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 0x8100,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static __u32 my_ethernet_headers[] = {HEADER_ETHERNET, 0};
static struct net_mat_hdr_node my_header_node_ethernet = {
	.name = ether_str,
	.uid = HEADER_INSTANCE_ETHERNET,
	.hdrs = my_ethernet_headers,
	.jump = my_parse_ethernet,
};

static struct net_mat_jump_table my_parse_vlan[] = {
	{
		.node = HEADER_INSTANCE_IPV4,
		.field = {
			.header = HEADER_ETHERNET,
			.field = HEADER_ETHERNET_ETHERTYPE,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 0x0800,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static __u32 my_vlan_headers[] = {HEADER_VLAN, 0};
static struct net_mat_hdr_node my_header_node_vlan = {
	.name = vlan_str,
	.uid = HEADER_INSTANCE_VLAN_OUTER,
	.hdrs = my_vlan_headers,
	.jump = my_parse_vlan,
};

static struct net_mat_jump_table my_terminal_headers[] = {
	{
		.node = NET_MAT_JUMP_TABLE_DONE,
		.field = {0},
	},
	{
		.node = 0,
	},
};

static __u32 my_tcp_headers[] = {HEADER_TCP, 0};
static struct net_mat_hdr_node my_header_node_tcp = {
	.name = tcp_str,
	.uid = HEADER_INSTANCE_TCP,
	.hdrs = my_tcp_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_jump_table my_parse_ipv4[] = {
	{
		.node = HEADER_INSTANCE_TCP,
		.field = {
			.header = HEADER_IPV4,
			.field = HEADER_IPV4_PROTOCOL,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 6,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = HEADER_INSTANCE_UDP,
		.field = {
			.header = HEADER_IPV4,
			.field = HEADER_IPV4_PROTOCOL,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 17,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static __u32 my_ipv4_headers[] = {HEADER_IPV4, 0};
static struct net_mat_hdr_node my_header_node_ipv4 = {
	.name = ipv4_str,
	.uid = HEADER_INSTANCE_IPV4,
	.hdrs = my_ipv4_headers,
	.jump = my_parse_ipv4,
};

#define VXLAN_UDP_PORT 1234

static struct net_mat_jump_table my_parse_udp[] = {
	{
		.node = HEADER_INSTANCE_VXLAN,
		.field = {
			.header = HEADER_UDP,
			.field = HEADER_UDP_SRC_PORT,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = VXLAN_UDP_PORT,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static __u32 my_udp_headers[] = {HEADER_UDP, 0};
static struct net_mat_hdr_node my_header_node_udp = {
	.name = udp_str,
	.uid = HEADER_INSTANCE_UDP,
	.hdrs = my_udp_headers,
	.jump = my_parse_udp,
};

static struct net_mat_jump_table my_parse_vxlan[] = {
	{
		.node = HEADER_INSTANCE_ETHERNET_INNER,
		.field = {0},
	},
	{
		.node = 0,
	},
};

static __u32 my_vxlan_headers[] = {HEADER_VXLAN, 0};
static struct net_mat_hdr_node my_header_node_vxlan = {
	.name = vxlan_str,
	.uid = HEADER_INSTANCE_VXLAN,
	.hdrs = my_vxlan_headers,
	.jump = my_parse_vxlan,
};

static struct net_mat_jump_table my_parse_ethernet_inner[] = {
	{
		.node = HEADER_INSTANCE_IPV4_INNER,
		.field = {
			.header = HEADER_ETHERNET,
			.field = HEADER_ETHERNET_ETHERTYPE,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 0x0800,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = HEADER_INSTANCE_VLAN_OUTER_INNER,
		.field = {
			.header = HEADER_ETHERNET,
			.field = HEADER_ETHERNET_ETHERTYPE,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 0x8100,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static struct net_mat_hdr_node my_header_node_ethernet_inner = {
	.name = ether_inner_str,
	.uid = HEADER_INSTANCE_ETHERNET_INNER,
	.hdrs = my_ethernet_headers,
	.jump = my_parse_ethernet_inner,
};

static struct net_mat_jump_table my_parse_vlan_inner[] = {
	{
		.node = HEADER_INSTANCE_IPV4_INNER,
		.field = {
			.header = HEADER_ETHERNET,
			.field = HEADER_ETHERNET_ETHERTYPE,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 0x0800,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static struct net_mat_hdr_node my_header_node_vlan_inner = {
	.name = vlan_inner_str,
	.uid = HEADER_INSTANCE_VLAN_OUTER_INNER,
	.hdrs = my_vlan_headers,
	.jump = my_parse_vlan_inner,
};

static struct net_mat_jump_table my_parse_ipv4_inner[] = {
	{
		.node = HEADER_INSTANCE_TCP_INNER,
		.field = {
			.header = HEADER_IPV4,
			.field = HEADER_IPV4_PROTOCOL,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 6,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = HEADER_INSTANCE_UDP_INNER,
		.field = {
			.header = HEADER_IPV4,
			.field = HEADER_IPV4_PROTOCOL,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 17,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static struct net_mat_hdr_node my_header_node_tcp_inner = {
	.name = tcp_inner_str,
	.uid = HEADER_INSTANCE_TCP_INNER,
	.hdrs = my_tcp_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_udp_inner = {
	.name = udp_inner_str,
	.uid = HEADER_INSTANCE_UDP_INNER,
	.hdrs = my_udp_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_ipv4_inner = {
	.name = ipv4_inner_str,
	.uid = HEADER_INSTANCE_IPV4_INNER,
	.hdrs = my_ipv4_headers,
	.jump = my_parse_ipv4_inner,
};

static __u32 my_metadata_headers[] = {HEADER_METADATA, 0};
static struct net_mat_hdr_node my_header_node_routing_metadata = {
	.name = routing_metadata,
	.uid = HEADER_INSTANCE_ROUTING_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_ig_port_metadata = {
	.name = ig_port_metadata,
	.uid = HEADER_INSTANCE_INGRESS_PORT_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_tea_metadata = {
	.name = te_metadata_a,
	.uid = HEADER_INSTANCE_TE_A_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_teb_metadata = {
	.name = te_metadata_b,
	.uid = HEADER_INSTANCE_TE_B_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_direct_index_metadata = {
	.name = direct_index_metadata,
	.uid = HEADER_INSTANCE_DIRECT_INDEX_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_l2mp_metadata = {
	.name = l2mp_metadata,
	.uid = HEADER_INSTANCE_L2_MP_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node *my_hdr_nodes[] = {
	&my_header_node_ethernet,
	&my_header_node_vlan,
	&my_header_node_ipv4,
	&my_header_node_udp,
	&my_header_node_tcp,
	&my_header_node_vxlan,
	&my_header_node_ethernet_inner,
	&my_header_node_vlan_inner,
	&my_header_node_ipv4_inner,
	&my_header_node_udp_inner,
	&my_header_node_tcp_inner,
	&my_header_node_routing_metadata,
	&my_header_node_ig_port_metadata,
	&my_header_node_tea_metadata,
	&my_header_node_teb_metadata,
	&my_header_node_direct_index_metadata,
	&my_header_node_l2mp_metadata,
	NULL,
};

/********************************************************************
 * TABLE GRAPH
 *******************************************************************/
static struct net_mat_jump_table my_table_node_terminal_jump[] = {
	{ .field = {0}, .node = NET_MAT_JUMP_TABLE_DONE},
	{ .field = {0}, .node = 0},
};

static struct net_mat_tbl_node my_table_node_l2mpath = {
	.uid = TABLE_L2_MP,
	.jump = my_table_node_terminal_jump,
};

static struct net_mat_jump_table my_table_node_mac_jump[] = {
	{ .field = { .instance = HEADER_INSTANCE_L2_MP_METADATA,
		     .header = HEADER_METADATA,
		     .field = HEADER_METADATA_L2_MP,
		     .type = NET_MAT_FIELD_REF_ATTR_TYPE_U32,
		     .v.u32 = {
			.value_u32 = 0,
			.mask_u32 = 0xffffffff
		     }
		   },
	  .node = 0},
	{ .field = {0}, .node = TABLE_L2_MP},
	{ .field = {0}, .node = 0},
};

static struct net_mat_tbl_node my_table_node_mac = {
	.uid = TABLE_MAC,
	.jump = my_table_node_mac_jump,
};

static struct net_mat_jump_table my_table_node_next_hop_jump[] = {
	{ .field = {0}, .node = TABLE_MAC},
	{ .field = {0}, .node = 0},
};

static struct net_mat_tbl_node my_table_node_next_hop = {
	.uid = TABLE_NEXTHOP,
	.jump = my_table_node_next_hop_jump
};

static struct net_mat_jump_table my_table_node_tcam_jump[] = {
	{ .field = { .instance = HEADER_INSTANCE_TE_A_METADATA,
		     .header = HEADER_METADATA,
		     .field = HEADER_METADATA_TE_A,
		     .mask_type = NET_MAT_FIELD_REF_ATTR_TYPE_U8,
		     .type = NET_MAT_FIELD_REF_ATTR_TYPE_U8,
		     .v.u16 = {
		     	.value_u16 = 0xffff,
		     	.mask_u16 = 0xffff
		     }},
	  .node = TABLE_TUNNEL_ENGINE_A},
	{ .field = { .instance = HEADER_INSTANCE_TE_B_METADATA,
		     .header = HEADER_METADATA,
		     .field = HEADER_METADATA_TE_B,
		     .mask_type = NET_MAT_FIELD_REF_ATTR_TYPE_U8,
		     .type = NET_MAT_FIELD_REF_ATTR_TYPE_U8,
		     .v.u16 = {
		     	.value_u16 = 0xffff,
		     	.mask_u16 = 0xffff
		     }},
	  .node = TABLE_TUNNEL_ENGINE_B},
	{ .field = {0}, .node = TABLE_NEXTHOP},
	{ .field = {0}, .node = 0},
};

static struct net_mat_tbl_node my_table_node_tcam = {
	.uid = TABLE_TCAM,
	.flags = NET_MAT_TABLE_INGRESS_ROOT |
		 NET_MAT_TABLE_EGRESS_ROOT  |
		 NET_MAT_TABLE_DYNAMIC,
	.jump = my_table_node_tcam_jump
};


static struct net_mat_jump_table my_table_node_tunnel_engine_jump[] = {
	{ .field = {0}, .node = TABLE_TCAM},
	{ .field = {0}, .node = 0},
};

static struct net_mat_tbl_node my_table_node_tunnel_engine_a = {
	.uid = TABLE_TUNNEL_ENGINE_A,
	.flags = NET_MAT_TABLE_DYNAMIC,
	.jump = my_table_node_tunnel_engine_jump,
};

static struct net_mat_tbl_node my_table_node_tunnel_engine_b = {
	.uid = TABLE_TUNNEL_ENGINE_B,
	.flags = NET_MAT_TABLE_DYNAMIC,
	.jump = my_table_node_tunnel_engine_jump,
};

#ifdef PORT_TO_VNI
static struct net_mat_jump_table my_table_node_vni_jump[] = {
	{ .field = {0}, .node = TABLE_TCAM},
	{ .field = {0}, .node = 0},
};

static struct net_mat_tbl_node my_table_node_vni = {
	.uid = TABLE_PORT_TO_VNI,
	.flags = NET_MAT_TABLE_DYNAMIC,
	.jump = my_table_node_vni_jump,
};
#endif

static struct net_mat_tbl_node *my_tbl_nodes[] = {
#ifdef PORT_TO_VNI
	&my_table_node_vni,
#endif
	&my_table_node_tcam,
	&my_table_node_tunnel_engine_a,
	&my_table_node_tunnel_engine_b,
	&my_table_node_next_hop,
	&my_table_node_mac,
	&my_table_node_l2mpath,
	NULL,
};

#endif /* _IES_PIPELINE_H */
