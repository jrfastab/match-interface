/*******************************************************************************
  Better Pipeline - A fictional pipeline model for testing
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

#ifndef _BETTER_PIPELINE_H
#define _BETTER_PIPELINE_H

#include "if_mat.h"

/********************************************************************
 * HEADER DEFINITIONS
 *******************************************************************/
static char src_mac[] =  "src_mac";
static char dst_mac[] =  "dst_mac";
static char ethertype[] =  "ethertype";
static char ether_str[] =  "ethernet";
static char pcp[] = "pcp";
static char cfi[] = "cfi";
static char vid[] = "vid";
static char vlan_str[] = "vlan";
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
static char csum[] = "csum";
static char src_ip[] = "src_ip";
static char dst_ip[] = "dst_ip";
static char options[] = "options";
static char ipv4_str[] = "ipv4";
static char src_port[] = "src_port";
static char dst_port[] = "dst_port";
static char seq[] = "seq";
static char ack[] = "ack";
static char offset[] = "offset";
static char reserved[] = "reserved";
static char window[] = "window";
static char urgent[] = "urgent";
static char tcp_str[] = "tcp";
static char udp_str[] = "udp";
static char vxlan_str[] = "vxlan";
static char vxlan_header[] = "vxlan_header";
static char vni[] = "vni";
static char egress_queue[] = "egress_queue";
static char host_metadata[] = "host_metadata";
static char tunnel_id[] = "tunnel_id";
static char ecmp_index[] = "ecmp_index";
static char ingress_port[] = "ingress_port";
static char metadata_t_str[] = "metadata_t";
static char egress_port[] = "egress_port";
static char empty[] = "";
static char set_egress_port_str[] = "set_egress_port";
static char set_tunnel_id_str[] = "set_tunnel_id";
static char set_egress_queue_str[] = "set_egress_queue";
static char set_host_meta_str[] = "set_host_meta";
static char vxlan_decap_str[] = "vxlan_decap";
static char vxlan_encap_str[] = "vxlan_encap";
static char drop_str[] = "drop_packet";
static char ecmp_group_base[] = "ecmp_group_base";
static char ecmp_group_size[] = "ecmp_group_size";
static char route_via_ecmp_str[] = "route_via_ecmp";
static char newDMAC[] = "newDMAC";
static char newVLAN[] = "newVLAN";
static char route_str[] = "route";
static char fwd_group_base[] = "fwd_group_base";
static char fwd_group_size[] = "fwd_group_size";
static char forward_via_ecmp_str[] = "forward_via_ecmp";
static char mac_address[] = "mac_address";
static char set_dst_mac_str[] = "set_dst_mac";
static char set_src_mac_str[] = "set_src_mac";
static char normal_str[] = "normal";
static char trap_str[] = "trap";
static char ecmp_group[] = "ecmp_group";
static char l2fwd[] = "l2fwd";
static char tcam[] = "tcam";
static char tunnel_encap[] = "tunnel_encap";
static char forward_metadata[] = "forward_metadata";
static char routing_metadata[] = "routing_metadata";
static char tunnel_metadata[] = "tunnel_metadata";
static char ig_port_metadata[] = "ig_port_metadata";
static char forward_group[] = "forward_group";
static char count_str[] = "count";
static char set_vlan_str[] = "set_vlan";

#define HEADER_ETHERNET_SRC_MAC 1
#define HEADER_ETHERNET_DST_MAC 2
#define HEADER_ETHERNET_ETHERTYPE 3
static struct net_mat_field ethernet_fields[3] = {
	{ .name = src_mac, .uid = HEADER_ETHERNET_SRC_MAC, .bitwidth = 48},
	{ .name = dst_mac, .uid = HEADER_ETHERNET_DST_MAC, .bitwidth = 48},
	{ .name = ethertype, .uid = HEADER_ETHERNET_ETHERTYPE, .bitwidth = 16},
};

#define HEADER_ETHERNET 1
static struct net_mat_hdr ethernet = {
	.name = ether_str,
	.uid = HEADER_ETHERNET,
	.field_sz = 3,
	.fields = ethernet_fields,
};

#define HEADER_VLAN_PCP 1
#define HEADER_VLAN_CFI 2
#define HEADER_VLAN_VID 3
#define HEADER_VLAN_ETHERTYPE 4
static struct net_mat_field vlan_fields[4] = {
	{ .name = pcp, .uid = HEADER_VLAN_PCP, .bitwidth = 3,},
	{ .name = cfi, .uid = HEADER_VLAN_CFI, .bitwidth = 1,},
	{ .name = vid, .uid = HEADER_VLAN_VID, .bitwidth = 12,},
	{ .name = ethertype, .uid = HEADER_VLAN_ETHERTYPE, .bitwidth = 16,},
};

#define HEADER_VLAN 2
static struct net_mat_hdr vlan = {
	.name = vlan_str,
	.uid = HEADER_VLAN,
	.field_sz = 4,
	.fields = vlan_fields,
};

#define HEADER_IPV4_VERSION 1
#define HEADER_IPV4_IHL 2
#define HEADER_IPV4_DSCP 3
#define HEADER_IPV4_ECN 4
#define HEADER_IPV4_LENGTH 5
#define HEADER_IPV4_IDENTIFICATION 6
#define HEADER_IPV4_FLAGS 7
#define HEADER_IPV4_FRAGMENT_OFFSET 8
#define HEADER_IPV4_TTL 9
#define HEADER_IPV4_PROTOCOL 10
#define HEADER_IPV4_CSUM 11
#define HEADER_IPV4_SRC_IP 12
#define HEADER_IPV4_DST_IP 13
#define HEADER_IPV4_OPTIONS 14
static struct net_mat_field ipv4_fields[14] = {
	{ .name = version,
	  .uid = 1,
	  .bitwidth = 4,},
	{ .name = ihl,
	  .uid = 2,
	  .bitwidth = 4,},
	{ .name = dscp,
	  .uid = 3,
	  .bitwidth = 6,},
	{ .name = ecn,
	  .uid = 4,
	  .bitwidth = 2,},
	{ .name = length,
	  .uid = 5,
	  .bitwidth = 8,},
	{ .name = ident,
	  .uid = 6,
	  .bitwidth = 8,},
	{ .name = flags,
	  .uid = 7,
	  .bitwidth = 3,},
	{ .name = frag_off,
	  .uid = 8,
	  .bitwidth = 13,},
	{ .name = ttl,
	  .uid = 9,
	  .bitwidth = 1,},
	{ .name = protocol,
	  .uid = 10,
	  .bitwidth = 8,},
	{ .name = csum,
	  .uid = 11,
	  .bitwidth = 8,},
	{ .name = src_ip,
	  .uid = 12,
	  .bitwidth = 32,},
	{ .name = dst_ip,
	  .uid = 13,
	  .bitwidth = 32,},
	{ .name = options,
	  .uid = 14,
	  .bitwidth = 0,},
	/* TBD options */
};

#define HEADER_IPV4 3
static struct net_mat_hdr ipv4 = {
	.name = ipv4_str,
	.uid = HEADER_IPV4,
	.field_sz = 14,
	.fields = ipv4_fields,
};

#define HEADER_TCP_SRC_PORT 1
#define HEADER_TCP_DST_PORT 2
#define HEADER_TCP_SEQ 3
#define HEADER_TCP_ACK 4
#define HEADER_TCP_OFFSET 5
#define HEADER_TCP_RESERVED 6
#define HEADER_TCP_FLAGS 7
#define HEADER_TCP_WINDOW 8
#define HEADER_TCP_CSUM 9
#define HEADER_TCP_URGENT 10
static struct net_mat_field tcp_fields[10] = {
	{ .name = src_port,
	  .uid = 1,
	  .bitwidth = 16,
	},
	{ .name = dst_port,
	  .uid = 2,
	  .bitwidth = 16,
	},
	{ .name = seq,
	  .uid = 3,
	  .bitwidth = 32,
	},
	{ .name = ack,
	  .uid = 4,
	  .bitwidth = 32,
	},
	{ .name = offset,
	  .uid = 5,
	  .bitwidth = 4,
	},
	{ .name = reserved,
	  .uid = 6,
	  .bitwidth = 3},
	{ .name = flags,
	  .uid = 7,
	  .bitwidth = 9},
	{ .name = window,
	  .uid = 8,
	  .bitwidth = 8,},
	{ .name = csum,
	  .uid = 9,
	  .bitwidth = 16,},
	{ .name = urgent,
	  .uid = 10,
	  .bitwidth = 16},
	/* TBD options */
};

#define HEADER_TCP 4
static struct net_mat_hdr tcp = {
	.name = tcp_str,
	.uid = HEADER_TCP,
	.field_sz = 10,
	.fields = tcp_fields,
};

#define HEADER_UDP_SRC_PORT 1
#define HEADER_UDP_DST_PORT 2
#define HEADER_UDP_LENGTH 3
#define HEADER_UDP_CSUM 4
static struct net_mat_field udp_fields[4] = {
	{ .name = src_port,
	  .uid = 1,
	  .bitwidth = 16},
	{ .name = dst_port,
	  .uid = 2,
	  .bitwidth = 16},
	{ .name = length,
	  .uid = 3,
	  .bitwidth = 16},
	{ .name = csum,
	  .uid = 4,
	  .bitwidth = 16},
};

#define HEADER_UDP 5
static struct net_mat_hdr udp = {
	.name = udp_str,
	.uid = HEADER_UDP,
	.field_sz = 4,
	.fields = udp_fields,
};

#define HEADER_VXLAN_VXLAN_HEADER 1
#define HEADER_VXLAN_VNI 2
#define HEADER_VXLAN_RESERVED 3
static struct net_mat_field vxlan_fields[3] = {
	{ .name = vxlan_header,
	  .uid = 1,
	  .bitwidth = 32},
	{ .name = vni,
	  .uid = 2,
	  .bitwidth = 24},
	{ .name = reserved,
	  .uid = 3,
	  .bitwidth = 8},
};

#define HEADER_VXLAN 6
static struct net_mat_hdr vxlan = {
	.name = vxlan_str,
	.uid = HEADER_VXLAN,
	.field_sz = 3,
	.fields = vxlan_fields,
};

#define HEADER_METADATA_EGRESS_QUEUE 1
#define HEADER_METADATA_HOST_METADATA 2
#define HEADER_METADATA_TUNNEL_ID 3
#define HEADER_METADATA_ECMP_INDEX 4
#define HEADER_METADATA_INGRESS_PORT 5
static struct net_mat_field metadata_fields[5] = {
	{ .name = egress_queue,
	  .uid = HEADER_METADATA_EGRESS_QUEUE,
	  .bitwidth = 8,},
	{ .name = host_metadata,
	  .uid = HEADER_METADATA_HOST_METADATA,
	  .bitwidth = 16,},
	{ .name = tunnel_id,
	  .uid = HEADER_METADATA_TUNNEL_ID,
	  .bitwidth = 16,},
	{ .name = ecmp_index,
	  .uid = HEADER_METADATA_ECMP_INDEX,
	  .bitwidth = 32,},
	{ .name = ingress_port,
	  .uid = HEADER_METADATA_INGRESS_PORT,
	  .bitwidth = 32,},
};

#define HEADER_METADATA 7
static struct net_mat_hdr metadata_t = {
	.name = metadata_t_str,
	.uid = HEADER_METADATA,
	.field_sz = 5,
	.fields = metadata_fields,
};

static struct net_mat_action_arg set_egress_port_args[2] = {
	{
		.name = egress_port,
		.type = NET_MAT_ACTION_ARG_TYPE_U32,
		.v.value_u32 = 0,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_NULL,
	},
};

static struct net_mat_hdr nill = {
	.name = empty, .uid = 0, .field_sz = 0, .fields = NULL
};

static struct net_mat_hdr *my_header_list[] = {
	&ethernet,
	&vlan,
	&ipv4,
	&tcp,
	&udp,
	&vxlan,
	&metadata_t,
	&nill,
};

/********************************************************************
 * ACTION DEFINITIONS
 *******************************************************************/

enum better_pipeline_action_ids {
	ACTION_SET_EGRESS_PORT = 1,
	ACTION_SET_TUNNEL_ID,
	ACTION_SET_EGRESS_QUEUE,
	ACTION_SET_HOST_METADATA,
	ACTION_VXLAN_DECAP,
	ACTION_VXLAN_ENCAP,
	ACTION_DROP_PACKET,
	ACTION_ROUTE_VIA_ECMP,
	ACTION_ROUTE,
	ACTION_FORWARD_VIA_ECMP,
	ACTION_SET_DST_MAC,
	ACTION_SET_SRC_MAC,
	ACTION_SET_VLAN,
	ACTION_NORMAL,
	ACTION_TRAP,
	ACTION_COUNT,
};

static struct net_mat_action set_egress_port = {
	.name = set_egress_port_str,
	.uid = ACTION_SET_EGRESS_PORT,
	.args = set_egress_port_args,
};

static struct net_mat_action count = {
	.name = count_str,
	.uid = ACTION_COUNT,
	.args = NULL,
};

static struct net_mat_action_arg set_tunnel_id_args[] = {
	{
		.name = tunnel_id,
		.type = NET_MAT_ACTION_ARG_TYPE_U16,
		.v.value_u32 = 0,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_NULL,
	},
};

static struct net_mat_action set_tunnel_id = {
	.name = set_tunnel_id_str,
	.uid = ACTION_SET_TUNNEL_ID,
	.args = set_tunnel_id_args,
};

static struct net_mat_action_arg set_egress_queue_args[] = {
	{
		.name = egress_queue,
		.type = NET_MAT_ACTION_ARG_TYPE_U16,
		.v.value_u32 = 0,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_NULL,
	},
};

static struct net_mat_action set_egress_queue = {
	.name = set_egress_queue_str,
	.uid = ACTION_SET_EGRESS_QUEUE,
	.args = set_egress_queue_args,
};

static struct net_mat_action_arg set_host_metadata_args[] = {
	{
		.name = host_metadata,
		.type = NET_MAT_ACTION_ARG_TYPE_U16,
		.v.value_u32 = 0,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_NULL,
	},
};

static struct net_mat_action set_host_metadata = {
	.name = set_host_meta_str,
	.uid = ACTION_SET_HOST_METADATA,
	.args = set_host_metadata_args,
};

static struct net_mat_action_arg vxlan_decap_args[] = {
	{
		.name = vxlan_decap_str,
		.type = NET_MAT_ACTION_ARG_TYPE_U16,
		.v.value_u32 = 0,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_NULL,
	},
};

static struct net_mat_action vxlan_decap = {
	.name = vxlan_decap_str,
	.uid = ACTION_VXLAN_DECAP,
	.args = vxlan_decap_args,
};

static struct net_mat_action_arg vxlan_encap_args[] = {
	{
		.name = vxlan_encap_str,
		.type = NET_MAT_ACTION_ARG_TYPE_U16,
		.v.value_u32 = 0,
	},
	{
		.name = empty,
		.type = NET_MAT_ACTION_ARG_TYPE_NULL,
	},
};

static struct net_mat_action vxlan_encap = {
	.name = vxlan_encap_str,
	.uid = ACTION_VXLAN_ENCAP,
	.args = vxlan_encap_args,
};

static struct net_mat_action drop_packet = {
	.name = drop_str,
	.uid = ACTION_DROP_PACKET,
	.args = NULL,
};

static struct net_mat_action_arg route_via_ecmp_args[] = {
	{ .name = ecmp_group_base,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = ecmp_group_size,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_NULL,},
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
	  .type = NET_MAT_ACTION_ARG_TYPE_NULL,},
};

static struct net_mat_action route = {
	.name = route_str,
	.uid = ACTION_ROUTE,
	.args = route_args,
};

static struct net_mat_action_arg forward_via_ecmp_args[] = {
	{ .name = fwd_group_base,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = fwd_group_size,
	  .type = NET_MAT_ACTION_ARG_TYPE_U32,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_NULL,},
};

static struct net_mat_action forward_via_ecmp = {
	.name = forward_via_ecmp_str,
	.uid = ACTION_FORWARD_VIA_ECMP,
	.args = forward_via_ecmp_args,
};

static struct net_mat_action_arg set_mac_args[] = {
	{ .name = mac_address,
	  .type = NET_MAT_ACTION_ARG_TYPE_U64,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_NULL,},
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

static struct net_mat_action_arg set_vlan_args[] = {
	{ .name = vlan_str,
	  .type = NET_MAT_ACTION_ARG_TYPE_U16,},
	{ .name = empty,
	  .type = NET_MAT_ACTION_ARG_TYPE_NULL,},
};

static struct net_mat_action set_vlan = {
	.name = set_vlan_str,
	.uid = ACTION_SET_VLAN,
	.args = set_vlan_args,
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

static struct net_mat_action *my_action_list[] = {
	&set_egress_port,
	&set_tunnel_id,
	&set_egress_queue,
	&set_host_metadata,
	&vxlan_decap,
	&vxlan_encap,
	&drop_packet,
	&route_via_ecmp,
	&route,
	&forward_via_ecmp,
	&set_dst_mac,
	&set_src_mac,
	&set_vlan,
	&normal,
	&trap,
	&count,
	NULL,
};

/********************************************************************
 * TABLE DEFINITIONS
 *******************************************************************/
#define HEADER_INSTANCE_ETHERNET 1
#define HEADER_INSTANCE_VXLAN 2
#define HEADER_INSTANCE_VLAN_OUTER 3
#define HEADER_INSTANCE_VLAN_INNER 4
#define HEADER_INSTANCE_IPV4 5
#define HEADER_INSTANCE_TCP 6
#define HEADER_INSTANCE_UDP 7
#define HEADER_INSTANCE_ROUTING_METADATA 8
#define HEADER_INSTANCE_FORWARD_METADATA 9
#define HEADER_INSTANCE_TUNNEL_METADATA 10
#define HEADER_INSTANCE_INGRESS_PORT_METADATA 11

static struct net_mat_field_ref matches_ecmp_group[2] = {
	{ .instance = HEADER_INSTANCE_ROUTING_METADATA,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_ECMP_INDEX,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = 0,
	  .field = 0},
};

static struct net_mat_field_ref matches_vxlan_decap[4] = {
	{ .instance = HEADER_INSTANCE_VXLAN,
	  .header = HEADER_VXLAN,
	  .field = HEADER_VXLAN_VNI,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_DST_IP,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_SRC_IP,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = 0, .field = 0},
};

static struct net_mat_field_ref matches_l2fwd[3] = {
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

static struct net_mat_field_ref matches_forward_group[2] = {
	{ .instance = HEADER_INSTANCE_FORWARD_METADATA,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_ECMP_INDEX,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

static struct net_mat_field_ref matches_tunnel_encap[2] = {
	{ .instance = HEADER_INSTANCE_TUNNEL_METADATA,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_TUNNEL_ID,
	  .mask_type = NET_MAT_MASK_TYPE_EXACT},
	{ .instance = 0, .field = 0},
};

static struct net_mat_field_ref matches_tcam[20] = {
	{ .instance = HEADER_INSTANCE_INGRESS_PORT_METADATA,
	  .header = HEADER_METADATA,
	  .field = HEADER_METADATA_INGRESS_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_DST_MAC,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_SRC_MAC,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_ETHERNET,
	  .header = HEADER_ETHERNET,
	  .field = HEADER_ETHERNET_ETHERTYPE,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_PCP,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_CFI,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_VID,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_VLAN_OUTER,
	  .header = HEADER_VLAN,
	  .field = HEADER_VLAN_ETHERTYPE,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_DSCP,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_ECN,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_TTL,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_PROTOCOL,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_DST_IP,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_IPV4,
	  .header = HEADER_IPV4,
	  .field = HEADER_IPV4_SRC_IP,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_TCP,
	  .header = HEADER_TCP,
	  .field = HEADER_TCP_SRC_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_TCP,
	  .header = HEADER_TCP,
	  .field = HEADER_TCP_DST_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_TCP,
	  .header = HEADER_TCP,
	  .field = HEADER_TCP_FLAGS,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_UDP,
	  .header = HEADER_UDP,
	  .field = HEADER_UDP_SRC_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
	{ .instance = HEADER_INSTANCE_UDP,
	  .header = HEADER_UDP,
	  .field = HEADER_UDP_DST_PORT,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},

	{ .instance = HEADER_INSTANCE_VXLAN,
	  .header = HEADER_VXLAN,
	  .field = HEADER_VXLAN_VNI,
	  .mask_type = NET_MAT_MASK_TYPE_LPM},
};

static __u32 actions_ecmp_group[] = { ACTION_ROUTE, ACTION_SET_EGRESS_PORT,
			ACTION_SET_TUNNEL_ID, 0};

static __u32 actions_vxlan_decap[] = { ACTION_VXLAN_DECAP, 0 };

static __u32 actions_l2fwd[] = { ACTION_SET_EGRESS_PORT,
			ACTION_SET_TUNNEL_ID, 0 };

static __u32 actions_forward_group[] = { ACTION_SET_EGRESS_PORT,
			ACTION_SET_TUNNEL_ID, 0 };
static __u32 actions_tunnel_encap[] = { ACTION_VXLAN_ENCAP, 0 };

static __u32 actions_tcam[] = { ACTION_SET_EGRESS_PORT, ACTION_ROUTE_VIA_ECMP,
			ACTION_SET_TUNNEL_ID, ACTION_DROP_PACKET,
			ACTION_SET_VLAN,
			ACTION_NORMAL, ACTION_TRAP, ACTION_COUNT, 0};

#define TABLE_TCAM 1
#define TABLE_ECMP_GROUP 2
#define TABLE_FORWARD_GROUP 3
#define TABLE_L2FWD 4
#define TABLE_TUNNEL_ENCAP 5
#define TABLE_VXLAN_DECAP 6
#define TABLE_TCAM_DYN_START 9
#define TABLE_MAX_NUM_TCAM_DYN 32


static struct net_mat_tbl my_table_ecmp_group = {
	.name = ecmp_group,
	.uid = TABLE_ECMP_GROUP,
	.source = 2,
	.apply_action = 2,
	.size = 128,
	.matches = matches_ecmp_group,
	.actions = actions_ecmp_group,
};

static struct net_mat_tbl my_table_vxlan_decap = {
	.name = vxlan_decap_str,
	.uid = TABLE_VXLAN_DECAP,
	.source = 4,
	.apply_action = 4,
	.size = 2000,
	.matches = matches_vxlan_decap,
	.actions = actions_vxlan_decap,
};

static struct net_mat_tbl my_table_l2fwd = {
	.name = l2fwd,
	.uid = TABLE_L2FWD,
	.source = 3,
	.apply_action = 3,
	.size = 2000,
	.matches = matches_l2fwd,
	.actions = actions_l2fwd,
};

static struct net_mat_tbl my_table_forward_group = {
	.name = forward_group,
	.uid = TABLE_FORWARD_GROUP,
	.source = 3,
	.apply_action = 3,
	.size = 2000,
	.matches = matches_forward_group,
	.actions = actions_forward_group,
};

static struct net_mat_tbl my_table_tunnel_encap = {
	.name = tunnel_encap,
	.uid = TABLE_TUNNEL_ENCAP,
	.source = 4,
	.apply_action = 4,
	.size = 2000,
	.matches = matches_tunnel_encap,
	.actions = actions_tunnel_encap,
};

static struct net_mat_tbl my_table_tcam = {
	.name = tcam,
	.uid = TABLE_TCAM,
	.source = 1,
	.apply_action = 1,
	.size = 4096,
	.matches = matches_tcam,
	.actions = actions_tcam,
};

static struct net_mat_tbl *my_table_list[] = {
	&my_table_tcam,
	&my_table_forward_group,
	&my_table_l2fwd,
	&my_table_ecmp_group,
	&my_table_tunnel_encap,
	&my_table_vxlan_decap,
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
				.value_u16 = 0x8000,
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
				.value_u16 = 0x08100,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static __u32 my_ethernet_headers[2] = {HEADER_ETHERNET, 0};
static struct net_mat_hdr_node my_header_node_ethernet = {
	.name = ether_str,
	.uid = HEADER_INSTANCE_ETHERNET,
	.hdrs = my_ethernet_headers,
	.jump = my_parse_ethernet,
};

static struct net_mat_jump_table my_parse_vlan[3] = {
	{
		.node = HEADER_INSTANCE_IPV4,
		.field = {
			.header = HEADER_ETHERNET,
			.field = HEADER_ETHERNET_ETHERTYPE,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 0x08000,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static __u32 my_vlan_headers[2] = {HEADER_VLAN, 0};
static struct net_mat_hdr_node my_header_node_vlan = {
	.name = vlan_str,
	.uid = HEADER_INSTANCE_VLAN_OUTER,
	.hdrs = my_vlan_headers,
	.jump = my_parse_vlan,
};

static struct net_mat_jump_table my_terminal_headers[2] = {
	{
		.node = NET_MAT_JUMP_TABLE_DONE,
		.field = {0},
	},
	{
		.node = 0,
	},
};

static __u32 my_tcp_headers[2] = {HEADER_TCP, 0};
static struct net_mat_hdr_node my_header_node_tcp = {
	.name = tcp_str,
	.uid = HEADER_INSTANCE_TCP,
	.hdrs = my_tcp_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_jump_table my_parse_ipv4[3] = {
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

static __u32 my_ipv4_headers[2] = {HEADER_IPV4, 0};
static struct net_mat_hdr_node my_header_node_ipv4 = {
	.name = ipv4_str,
	.uid = HEADER_INSTANCE_IPV4,
	.hdrs = my_ipv4_headers,
	.jump = my_parse_ipv4,
};

static struct net_mat_jump_table my_parse_udp[2] = {
	{
		.node = HEADER_INSTANCE_VXLAN,
		.field = {
			.header = HEADER_UDP,
			.field = HEADER_UDP_DST_PORT,
			.type = NET_MAT_FIELD_REF_ATTR_TYPE_U16,
			.v.u16 = {
				.value_u16 = 4789,
				.mask_u16 = 0xFFFF,
			}
		}
	},
	{
		.node = 0,
	},
};

static __u32 my_udp_headers[2] = {HEADER_UDP, 0};
static struct net_mat_hdr_node my_header_node_udp = {
	.name = udp_str,
	.uid = HEADER_INSTANCE_UDP,
	.hdrs = my_udp_headers,
	.jump = my_parse_udp,
};

static __u32 my_vxlan_headers[2] = {HEADER_VXLAN, 0};
static struct net_mat_hdr_node my_header_node_vxlan = {
	.name = vxlan_str,
	.uid = HEADER_INSTANCE_VXLAN,
	.hdrs = my_vxlan_headers,
	.jump = my_terminal_headers,
};

static __u32 my_metadata_headers[2] = {HEADER_METADATA, 0};
static struct net_mat_hdr_node my_header_node_routing_metadata = {
	.name = routing_metadata,
	.uid = HEADER_INSTANCE_ROUTING_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_forward_metadata = {
	.name = forward_metadata,
	.uid = HEADER_INSTANCE_FORWARD_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_tunnel_metadata = {
	.name = tunnel_metadata,
	.uid = HEADER_INSTANCE_TUNNEL_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node my_header_node_ig_port_metadata = {
	.name = ig_port_metadata,
	.uid = HEADER_INSTANCE_INGRESS_PORT_METADATA,
	.hdrs = my_metadata_headers,
	.jump = my_terminal_headers,
};

static struct net_mat_hdr_node *my_hdr_nodes[] = {
	&my_header_node_ethernet,
	&my_header_node_vlan,
	&my_header_node_ipv4,
	&my_header_node_udp,
	&my_header_node_vxlan,
	&my_header_node_tcp,
	&my_header_node_routing_metadata,
	&my_header_node_forward_metadata,
	&my_header_node_tunnel_metadata,
	&my_header_node_ig_port_metadata,
	NULL,
};

/********************************************************************
 * TABLE GRAPH
 *******************************************************************/
static struct net_mat_jump_table my_table_node_ecmp_group_jump[2] = {
	{ .field = {0}, .node = TABLE_L2FWD},
	{ .field = {0}, .node = 0},
};

static struct net_mat_tbl_node my_table_node_ecmp_group = {
	.uid = TABLE_ECMP_GROUP,
	.jump = my_table_node_ecmp_group_jump};


static struct net_mat_jump_table my_table_node_vxlan_decap_jump[2] = {
	{ .field = {0}, .node = NET_MAT_JUMP_TABLE_DONE},
	{ .field = {0}, .node = 0},
};

static struct net_mat_tbl_node my_table_node_vxlan_decap = {
	.uid = TABLE_VXLAN_DECAP,
	.jump = my_table_node_vxlan_decap_jump};

static struct net_mat_jump_table my_table_node_l2_fwd_jump[2] = {
	{ .field = {0}, .node = TABLE_FORWARD_GROUP},
	{ .field = {0}, .node = 0},
};
static struct net_mat_tbl_node my_table_node_l2_fwd = {
	.uid = TABLE_L2FWD,
	.jump = my_table_node_l2_fwd_jump};

static struct net_mat_jump_table my_table_node_forward_group_jump[2] = {
	{ .field = {0}, .node = TABLE_TUNNEL_ENCAP},
	{ .field = {0}, .node = 0},
};
static struct net_mat_tbl_node my_table_node_forward_group = {
	.uid = TABLE_FORWARD_GROUP,
	.jump = my_table_node_forward_group_jump};

static struct net_mat_jump_table my_table_node_tunnel_encap_jump[2] = {
	{ .field = {0}, .node = TABLE_VXLAN_DECAP},
	{ .field = {0}, .node = 0},
};
static struct net_mat_tbl_node my_table_node_tunnel_encap = {
	.uid = TABLE_TUNNEL_ENCAP,
	.jump = my_table_node_tunnel_encap_jump};

static struct net_mat_jump_table my_table_node_terminal_jump[2] = {
	{ .field = {0}, .node = TABLE_ECMP_GROUP},
	{ .field = {0}, .node = 0},
};
static struct net_mat_tbl_node my_table_node_tcam = {
	.uid = TABLE_TCAM,
	.flags = NET_MAT_TABLE_INGRESS_ROOT |
		 NET_MAT_TABLE_EGRESS_ROOT  |
		 NET_MAT_TABLE_DYNAMIC,
	.jump = my_table_node_terminal_jump};

static struct net_mat_tbl_node *my_tbl_nodes[] = {
	&my_table_node_tcam,
	&my_table_node_ecmp_group,
	&my_table_node_l2_fwd,
	&my_table_node_forward_group,
	&my_table_node_tunnel_encap,
	&my_table_node_vxlan_decap,
	NULL,
};

#endif /* _BETTER_PIPELINE_H */
