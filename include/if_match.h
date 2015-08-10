/*******************************************************************************
  if_match.h - match action table configuration interface
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

#ifndef _IF_MATCH_H
#define _IF_MATCH_H

#include <linux/types.h>
#define MATCHLIB_PID_FILE "/var/run/matchd.pid"
#define NET_MAT_DFLT_FAMILY 555

/**
 * @struct net_mat_fields
 * @brief defines a field in a header
 *
 * @name string identifier for pretty printing
 * @uid  unique identifier for field
 * @bitwidth length of field in bits
 */
struct net_mat_field {
	char *name;
	__u32 uid;
	__u32 bitwidth;
};

/**
 * @struct net_mat_hdr
 * @brief defines a match (header/field) an endpoint can use
 *
 * @name string identifier for pretty printing
 * @uid unique identifier for header
 * @field_sz number of fields are in the set
 * @fields the set of fields in the net_mat_hdr
 */
struct net_mat_hdr {
	char *name;
	__u32 uid;
	__u32 field_sz;
	struct net_mat_field *fields;
};

enum net_mat_action_arg_type {
	NET_MAT_ACTION_ARG_TYPE_UNSPEC,
	NET_MAT_ACTION_ARG_TYPE_NULL,
	NET_MAT_ACTION_ARG_TYPE_U8,
	NET_MAT_ACTION_ARG_TYPE_U16,
	NET_MAT_ACTION_ARG_TYPE_U32,
	NET_MAT_ACTION_ARG_TYPE_U64,
	NET_MAT_ACTION_ARG_TYPE_VARIADIC,
	__NET_MAT_ACTION_ARG_TYPE_VAL_MAX,
};

static const char *__net_mat_action_arg_type_str[] =  {
	[NET_MAT_ACTION_ARG_TYPE_UNSPEC]	= "unspec",
	[NET_MAT_ACTION_ARG_TYPE_NULL]		= "null",
	[NET_MAT_ACTION_ARG_TYPE_U8]		= "u8",
	[NET_MAT_ACTION_ARG_TYPE_U16]		= "u16",
	[NET_MAT_ACTION_ARG_TYPE_U32]		= "u32",
	[NET_MAT_ACTION_ARG_TYPE_U64]		= "u64",
	[NET_MAT_ACTION_ARG_TYPE_VARIADIC]	= "(variadic)",
};

static inline const char *net_mat_action_arg_type_str(__u32 i) {
	return i < __NET_MAT_ACTION_ARG_TYPE_VAL_MAX ? __net_mat_action_arg_type_str[i] : "";
}

/**
 * @struct net_mat_action_arg
 * @brief encodes action arguments in structures one per argument
 *
 * @name    string identifier for pretty printing
 * @type    type of argument either u8, u16, u32, u64
 * @value_# indicate value/mask value type on of u8, u16, u32, or u64
 */
struct net_mat_action_arg {
	char *name;
	enum net_mat_action_arg_type type;
	union {
		__u8  value_u8;
		__u16 value_u16;
		__u32 value_u32;
		__u64 value_u64;
	} v;
};

/**
 * @struct net_mat_action
 * @brief a description of a endpoint defined action
 *
 * @name printable name
 * @uid unique action identifier
 * @args null terminated list of action arguments
 */
struct net_mat_action {
	char *name;
	__u32 uid;
	struct net_mat_action_arg *args;
};

/**
 * @struct net_mat_field_ref
 * @brief uniquely identify field as instance:header:field tuple
 *
 * @next_node next node in jump table otherwise ignored
 * @instance identify unique instance of field reference
 * @header   identify unique header reference
 * @field    identify unique field in above header reference
 * @mask_type indicate mask type
 * @type     indicate value/mask value type on of u8, u16, u32, or u64
 * @value_u# value of field reference
 * @mask_u#  mask value of field reference
 */
struct net_mat_field_ref {
	__u32 instance;
	__u32 header;
	__u32 field;
	__u32 mask_type;
	__u32 type;
	union {
		struct {
			__u8 value_u8;
			__u8 mask_u8;
		} u8;
		struct {
			__u16 value_u16;
			__u16 mask_u16;
		} u16;
		struct {
			__u32 value_u32;
			__u32 mask_u32;
		} u32;
		struct {
			__u64 value_u64;
			__u64 mask_u64;
		} u64;
	} v;
};

#define NET_MAT_NAMED_VALUE_IS_WRITABLE 0x01

/**
 * @struct net_mat_table_attribs
 * @brief structure for describing a table attribute
 *
 * @name string identifier for pretty printing
 * @uid unique identifier for the attribute
 * @type the type of value
 * @value the value of the attribute
 * @write 0x01 if the value can be configured
 */
struct net_mat_named_value {
	char *name;
	__u32 uid;
	__u32 type;
	union {
		__u8  u8;
		__u16 u16;
		__u32 u32;
		__u64 u64;
	} value;
	__u8 write;
};

/**
 * @struct net_mat_tbl
 * @brief define match action table with supported match/actions
 *
 * @name string identifier for pretty printing
 * @uid unique identifier for table
 * @source uid of parent table
 * @size max number of entries for table or -1 for unbounded
 * @matches null terminated set of supported match types given by match uid
 * @actions null terminated set of supported action types given by action uid
 * @attribs null terminated set of table attributes given by named value tuples
 */
struct net_mat_tbl {
	char *name;
	__u32 uid;
	__u32 source;
	__u32 apply_action;
	__u32 size;
	struct net_mat_field_ref *matches;
	__u32 *actions;
	struct net_mat_named_value *attribs;
};

/**
 * @struct net_mat_jump_table
 * @brief encodes an edge of the table graph or header graph
 *
 * @field   field reference must be true to follow edge
 * @node    node identifier to connect edge to
 */

struct net_mat_jump_table {
	struct net_mat_field_ref field;
	__u32 node; /* <0 is a parser error */
};

/* @struct net_mat_hdr_node
 * @brief node in a header graph of header fields.
 *
 * @name string identifier for pretty printing
 * @uid  unique id of the graph node
 * @hdrs null terminated list of hdrs identified by this node
 * @jump encoding of graph structure as a case jump statement
 */
struct net_mat_hdr_node {
	char *name;
	__u32 uid;
	__u32 *hdrs;
	struct net_mat_jump_table *jump;
};

/* @struct net_mat_tbl_node
 * @brief
 *
 * @uid	  unique id of the table node
 * @flags bitmask of table attributes
 * @jump  encoding of graph structure as a case jump statement
 */
struct net_mat_tbl_node {
	__u32 uid;
	__u32 flags;
	struct net_mat_jump_table *jump;
};

/**
 * @struct net_mat_rule
 * @brief describes the match/action entry
 *
 * @uid unique identifier for rule 
 * @priority priority to execute rule match/action in table
 * @match null terminated set of match uids match criteria
 * @action null terminated set of action uids to apply to match
 *
 * rules must match all entries in match set.
 */
struct net_mat_rule {
	__u32 table_id;
	__u32 uid;
	__u32 priority;
	__u32 hw_ruleid;
	__u64 bytes; /**< count of bytes matching this rule */
	__u64 packets; /**< count of packets matching this rule */
	struct net_mat_field_ref *matches;
	struct net_mat_action *actions;
};

/**
 * @struct net_mat_port_stats
 * @brief per port statsistics strucutre
 *
 * @rx_* rx bytes/packet stats
 * @tx_* tx bytes/packet stats
 */
struct net_mat_port_stats {
	uint64_t rx_bytes;
	uint64_t rx_packets;

	uint64_t tx_bytes;
	uint64_t tx_packets;
};

enum flag_state {
	NET_MAT_PORT_T_FLAG_UNSPEC,
	NET_MAT_PORT_T_FLAG_ENABLED,
	NET_MAT_PORT_T_FLAG_DISABLED,
	__NET_MAT_PORT_T_FLAG_MAX,
};
#define NET_MAT_PORT_T_FLAG_MAX (__NET_MAT_PORT_T_FLAG_MAX - 1)

static const char *__flag_state_str[] =
{
	[NET_MAT_PORT_T_FLAG_UNSPEC] =		"",
	[NET_MAT_PORT_T_FLAG_ENABLED] =		"enabled",
	[NET_MAT_PORT_T_FLAG_DISABLED] =	"disabled",
};

static inline const char *flag_state_str(__u32 i) {
	return i < __NET_MAT_PORT_T_FLAG_MAX ? __flag_state_str[i] : "";
}

#define NET_MAT_PORT_T_DEF_PRI_UNSPEC	(UINT32_MAX)

struct net_mat_port_vlan {
	__u32 def_vlan;
	__u32 def_priority;
	enum flag_state drop_tagged;
	enum flag_state drop_untagged;
	__u8 vlan_membership_bitmask[512];
};

enum {
	NET_MAT_FIELD_UNSPEC,
	NET_MAT_FIELD,
	__NET_MAT_FIELD_MAX,
};
#define NET_MAT_FIELD_MAX (__NET_MAT_FIELD_MAX - 1)

/* Max length supported by kernel name strings only the first n characters
 * will be used by the kernel API. This is to prevent arbitrarily long
 * strings being passed from user space.
 */
#define NET_MAT_MAX_NAME 80

enum {
	NET_MAT_FIELD_ATTR_UNSPEC,
	NET_MAT_FIELD_ATTR_NAME,
	NET_MAT_FIELD_ATTR_UID,
	NET_MAT_FIELD_ATTR_BITWIDTH,
	__NET_MAT_FIELD_ATTR_MAX,
};
#define NET_MAT_FIELD_ATTR_MAX (__NET_MAT_FIELD_ATTR_MAX - 1)

enum {
	NET_MAT_HEADER_UNSPEC,
	NET_MAT_HEADER,
	__NET_MAT_HEADER_MAX,
};
#define NET_MAT_HEADER_MAX (__NET_MAT_HEADER_MAX - 1)

enum {
	NET_MAT_HEADER_ATTR_UNSPEC,
	NET_MAT_HEADER_ATTR_NAME,
	NET_MAT_HEADER_ATTR_UID,
	NET_MAT_HEADER_ATTR_FIELDS,
	__NET_MAT_HEADER_ATTR_MAX,
};
#define NET_MAT_HEADER_ATTR_MAX (__NET_MAT_HEADER_ATTR_MAX - 1)

enum {
	NET_MAT_MASK_TYPE_UNSPEC,
	NET_MAT_MASK_TYPE_EXACT,
	NET_MAT_MASK_TYPE_LPM,
	NET_MAT_MASK_TYPE_MASK,
};

enum {
	NET_MAT_FIELD_REF_UNSPEC,
	NET_MAT_FIELD_REF_NEXT_NODE,
	NET_MAT_FIELD_REF_INSTANCE,
	NET_MAT_FIELD_REF_HEADER,
	NET_MAT_FIELD_REF_FIELD,
	NET_MAT_FIELD_REF_MASK_TYPE,
	NET_MAT_FIELD_REF_TYPE,
	NET_MAT_FIELD_REF_VALUE,
	NET_MAT_FIELD_REF_MASK,
	__NET_MAT_FIELD_REF_MAX,
};
#define NET_MAT_FIELD_REF_MAX (__NET_MAT_FIELD_REF_MAX - 1)

enum {
	NET_MAT_FIELD_REFS_UNSPEC,
	NET_MAT_FIELD_REF,
	__NET_MAT_FIELD_REFS_MAX,
};
#define NET_MAT_FIELD_REFS_MAX (__NET_MAT_FIELD_REFS_MAX - 1)

enum {
	NET_MAT_FIELD_REF_ATTR_TYPE_UNSPEC,
	NET_MAT_FIELD_REF_ATTR_TYPE_U8,
	NET_MAT_FIELD_REF_ATTR_TYPE_U16,
	NET_MAT_FIELD_REF_ATTR_TYPE_U32,
	NET_MAT_FIELD_REF_ATTR_TYPE_U64,
};

enum {
	NET_MAT_ACTION_ARG_UNSPEC,
	NET_MAT_ACTION_ARG_NAME,
	NET_MAT_ACTION_ARG_TYPE,
	NET_MAT_ACTION_ARG_VALUE,
	__NET_MAT_ACTION_ARG_MAX,
};
#define NET_MAT_ACTION_ARG_MAX (__NET_MAT_ACTION_ARG_MAX - 1)

enum {
	NET_MAT_ACTION_ARGS_UNSPEC,
	NET_MAT_ACTION_ARG,
	__NET_MAT_ACTION_ARGS_MAX,
};
#define NET_MAT_ACTION_ARGS_MAX (__NET_MAT_ACTION_ARGS_MAX - 1)

enum {
	NET_MAT_ACTION_UNSPEC,
	NET_MAT_ACTION,
	__NET_MAT_ACTION_MAX,
};
#define NET_MAT_ACTION_MAX (__NET_MAT_ACTION_MAX - 1)

enum {
	NET_MAT_ACTION_ATTR_UNSPEC,
	NET_MAT_ACTION_ATTR_NAME,
	NET_MAT_ACTION_ATTR_UID,
	NET_MAT_ACTION_ATTR_SIGNATURE,
	__NET_MAT_ACTION_ATTR_MAX,
};
#define NET_MAT_ACTION_ATTR_MAX (__NET_MAT_ACTION_ATTR_MAX - 1)

enum {
	NET_MAT_ACTION_SET_UNSPEC,
	NET_MAT_ACTION_SET_ACTIONS,
	__NET_MAT_ACTION_SET_MAX,
};
#define NET_MAT_ACTION_SET_MAX (__NET_MAT_ACTION_SET_MAX - 1)

/* Value attributes are used to define well-known table properties
 * that may not apply to all table types. For example tables defining
 * tunnels may require attributes to restrict port numbers or dst_mac
 * and src_mac. This is more analogous to defining hardware quirks than
 * features.
 */
enum {
	NET_MAT_TABLE_ATTR_VALUE_UNSPEC,
	NET_MAT_TABLE_ATTR_NAMED_VALUE,
	__NET_MAT_TABLE_ATTR_VALUE_MAX,
};
#define NET_MAT_TABLE_ATTR_VALUE_MAX (__NET_MAT_TABLE_ATTR_VALUE_MAX - 1)

/* Define set of known value types for named values */
enum net_mat_named_value_type {
	NET_MAT_NAMED_VALUE_TYPE_UNSPEC,
	NET_MAT_NAMED_VALUE_TYPE_NULL,
	NET_MAT_NAMED_VALUE_TYPE_U8,
	NET_MAT_NAMED_VALUE_TYPE_U16,
	NET_MAT_NAMED_VALUE_TYPE_U32,
	NET_MAT_NAMED_VALUE_TYPE_U64,
	__NET_MAT_NAMED_VALUE_TYPE_MAX,
};

/* Define the set of known table named values enumerators */
enum {
	NET_MAT_TABLE_ATTR_NAMED_VALUE_UNSPEC,
	NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_SRC_PORT,
	NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_DST_PORT,
	NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_SRC_MAC,
	NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_DST_MAC,
	NET_MAT_TABLE_ATTR_NAMED_VALUE_MISS_DFLT_EGRESS_PORT,
	__NET_MAT_TABLE_ATTR_NAMED_VALUE_MAX,
};

enum {
	NET_MAT_TABLE_ATTR_VALUE_T_UNSPEC,
	NET_MAT_TABLE_ATTR_VALUE_T_NAME,
	NET_MAT_TABLE_ATTR_VALUE_T_UID,
	NET_MAT_TABLE_ATTR_VALUE_T_TYPE,
	NET_MAT_TABLE_ATTR_VALUE_T_VALUE,
	NET_MAT_TABLE_ATTR_VALUE_T_WRITE,
	__NET_MAT_TABLE_ATTR_VALUE_T_MAX,
};
#define NET_MAT_TABLE_ATTR_VALUE_T_MAX (__NET_MAT_TABLE_ATTR_VALUE_T_MAX - 1)

enum {
	NET_MAT_TABLE_UNSPEC,
	NET_MAT_TABLE,
	__NET_MAT_TABLE_MAX,
};
#define NET_MAT_TABLE_MAX (__NET_MAT_TABLE_MAX - 1)

enum {
	NET_MAT_TABLE_ATTR_UNSPEC,
	NET_MAT_TABLE_ATTR_NAME,
	NET_MAT_TABLE_ATTR_UID,
	NET_MAT_TABLE_ATTR_SOURCE,
	NET_MAT_TABLE_ATTR_APPLY,
	NET_MAT_TABLE_ATTR_SIZE,
	NET_MAT_TABLE_ATTR_MATCHES,
	NET_MAT_TABLE_ATTR_ACTIONS,
	NET_MAT_TABLE_ATTR_NAMED_VALUES,
	__NET_MAT_TABLE_ATTR_MAX,
};
#define NET_MAT_TABLE_ATTR_MAX (__NET_MAT_TABLE_ATTR_MAX - 1)

#define NET_MAT_JUMP_TABLE_DONE 0

enum {
	NET_MAT_JUMP_ENTRY_UNSPEC,
	NET_MAT_JUMP_ENTRY,
	__NET_MAT_JUMP_ENTRY_MAX,
};

enum {
	NET_MAT_HEADER_NODE_HDRS_UNSPEC,
	NET_MAT_HEADER_NODE_HDRS_VALUE,
	__NET_MAT_HEADER_NODE_HDRS_MAX,
};
#define NET_MAT_HEADER_NODE_HDRS_MAX (__NET_MAT_HEADER_NODE_HDRS_MAX - 1)

enum {
	NET_MAT_HEADER_NODE_UNSPEC,
	NET_MAT_HEADER_NODE_NAME,
	NET_MAT_HEADER_NODE_UID,
	NET_MAT_HEADER_NODE_HDRS,
	NET_MAT_HEADER_NODE_JUMP,
	__NET_MAT_HEADER_NODE_MAX,
};
#define NET_MAT_HEADER_NODE_MAX (__NET_MAT_HEADER_NODE_MAX - 1)

enum {
	NET_MAT_HEADER_GRAPH_UNSPEC,
	NET_MAT_HEADER_GRAPH_NODE,
	__NET_MAT_HEADER_GRAPH_MAX,
};
#define NET_MAT_HEADER_GRAPH_MAX (__NET_MAT_HEADER_GRAPH_MAX - 1)

#define	NET_MAT_TABLE_EGRESS_ROOT 1
#define	NET_MAT_TABLE_INGRESS_ROOT 2
#define	NET_MAT_TABLE_DYNAMIC 4

enum {
	NET_MAT_TABLE_GRAPH_NODE_UNSPEC,
	NET_MAT_TABLE_GRAPH_NODE_UID,
	NET_MAT_TABLE_GRAPH_NODE_FLAGS,
	NET_MAT_TABLE_GRAPH_NODE_JUMP,
	__NET_MAT_TABLE_GRAPH_NODE_MAX,
};
#define NET_MAT_TABLE_GRAPH_NODE_MAX (__NET_MAT_TABLE_GRAPH_NODE_MAX - 1)

enum {
	NET_MAT_TABLE_GRAPH_UNSPEC,
	NET_MAT_TABLE_GRAPH_NODE,
	__NET_MAT_TABLE_GRAPH_MAX,
};
#define NET_MAT_TABLE_GRAPH_MAX (__NET_MAT_TABLE_GRAPH_MAX - 1)

enum {
	NET_MAT_RULE_UNSPEC,
	NET_MAT_RULE,
	__NET_MAT_RULE_MAX,
};
#define NET_MAT_RULE_MAX (__NET_MAT_RULE_MAX - 1)

enum {
	NET_MAT_TABLE_RULES_UNSPEC,
	NET_MAT_TABLE_RULES_TABLE,
	NET_MAT_TABLE_RULES_MINPRIO,
	NET_MAT_TABLE_RULES_MAXPRIO,
	NET_MAT_TABLE_RULES_RULES,
	__NET_MAT_TABLE_RULES_MAX,
};
#define NET_MAT_TABLE_RULES_MAX (__NET_MAT_TABLE_RULES_MAX - 1)

enum {
	/* Abort with normal errmsg */
	NET_MAT_RULES_ERROR_ABORT,
	/* Ignore errors and continue without logging */
	NET_MAT_RULES_ERROR_CONTINUE,
	/* Abort and reply with invalid rule fields */
	NET_MAT_RULES_ERROR_ABORT_LOG,
	/* Continue and reply with list of invalid rules */
	NET_MAT_RULES_ERROR_CONT_LOG,
	__NET_MAT_RULES_ERROR_MAX,
};
#define NET_MAT_RULES_ERROR_MAX (__NET_MAT_RULES_ERROR_MAX - 1)

enum {
	NET_MAT_ATTR_UNSPEC,
	NET_MAT_ATTR_ERROR,
	NET_MAT_ATTR_TABLE,
	NET_MAT_ATTR_UID,
	NET_MAT_ATTR_PRIORITY,
	NET_MAT_ATTR_BYTES,
	NET_MAT_ATTR_PACKETS,
	NET_MAT_ATTR_MATCHES,
	NET_MAT_ATTR_ACTIONS,
	__NET_MAT_ATTR_MAX,
};
#define NET_MAT_ATTR_MAX (__NET_MAT_ATTR_MAX - 1)

struct net_mat_port_pci {
	uint8_t bus;
	uint8_t device;
	uint8_t function;
};

enum {
	NET_MAT_PORT_T_STATS_RXTX_UNSPEC,
	NET_MAT_PORT_T_STATS_BYTES,
	NET_MAT_PORT_T_STATS_PACKETS,
	__NET_MAT_PORT_T_STATS_RXTX_MAX,
};
#define NET_MAT_PORT_T_STATS_RXTX_MAX (__NET_MAT_PORT_T_STATS_RXTX_MAX - 1)

enum {
	NET_MAT_PORT_T_STATS_UNSPEC,
	NET_MAT_PORT_T_STATS_RX,
	NET_MAT_PORT_T_STATS_TX,
	__NET_MAT_PORT_T_STATS_MAX,
};
#define NET_MAT_PORT_T_STATS_MAX (__NET_MAT_PORT_T_STATS_MAX - 1)

enum {
	NET_MAT_PORT_T_VLAN_UNSPEC,
	NET_MAT_PORT_T_VLAN_DEF_VLAN,
	NET_MAT_PORT_T_VLAN_DROP_TAGGED,
	NET_MAT_PORT_T_VLAN_DROP_UNTAGGED,
	NET_MAT_PORT_T_VLAN_DEF_PRIORITY,
	NET_MAT_PORT_T_VLAN_MEMBERSHIP,
	__NET_MAT_PORT_T_VLAN_MAX,
};
#define NET_MAT_PORT_T_VLAN_MAX (__NET_MAT_PORT_T_VLAN_MAX - 1)

enum {
	NET_MAT_PORT_T_TYPE_UNSPEC,
	NET_MAT_PORT_T_TYPE_NETWORK,
	NET_MAT_PORT_T_TYPE_HOST,
	NET_MAT_PORT_T_TYPE_CPU,
	__NET_MAT_PORT_T_TYPE_MAX,
};
#define NET_MAT_PORT_T_TYPE_MAX (__NET_MAT_PORT_T_TYPE_MAX - 1)

static const char *__port_type_str[NET_MAT_PORT_T_TYPE_MAX + 1] =
{
	[NET_MAT_PORT_T_TYPE_UNSPEC] =		"",
	[NET_MAT_PORT_T_TYPE_NETWORK] =	"network",
	[NET_MAT_PORT_T_TYPE_HOST] =		"host",
	[NET_MAT_PORT_T_TYPE_CPU] =		"cpu",
};

static inline const char *port_type_str(__u32 i) {
	return i < __NET_MAT_PORT_T_TYPE_MAX ? __port_type_str[i] : "";
}

enum port_state {
	NET_MAT_PORT_T_STATE_UNSPEC,
	NET_MAT_PORT_T_STATE_UP,
	NET_MAT_PORT_T_STATE_DOWN,
	__NET_MAT_PORT_T_STATE_MAX,
};
#define NET_MAT_PORT_T_STATE_MAX (__NET_MAT_PORT_T_STATE_MAX - 1)

static const char *__port_state_str[] =
{
	[NET_MAT_PORT_T_STATE_UNSPEC] =	"",
	[NET_MAT_PORT_T_STATE_UP] =		"up",
	[NET_MAT_PORT_T_STATE_DOWN] =		"down",
};

static inline const char *port_state_str(__u32 i) {
	return i < __NET_MAT_PORT_T_STATE_MAX ? __port_state_str[i] : "";
}

enum port_speed {
	NET_MAT_PORT_T_SPEED_UNSPEC,
	NET_MAT_PORT_T_SPEED_1G	= 1000,
	NET_MAT_PORT_T_SPEED_2D5G	= 2500,
	NET_MAT_PORT_T_SPEED_10G	= 10000,
	NET_MAT_PORT_T_SPEED_20G	= 20000,
	NET_MAT_PORT_T_SPEED_25G	= 25000,
	NET_MAT_PORT_T_SPEED_40G	= 40000,
	NET_MAT_PORT_T_SPEED_100G	= 100000,
	__NET_MAT_PORT_T_SPEED_MAX
};
#define NET_MAT_PORT_T_SPEED_MAX (__NET_MAT_PORT_T_SPEED_MAC - 1)

static const char *__port_speed_str[] =
{
	[NET_MAT_PORT_T_SPEED_UNSPEC] =	"",
	[NET_MAT_PORT_T_SPEED_1G] =		"1G",
	[NET_MAT_PORT_T_SPEED_2D5G] =		"2.5G",
	[NET_MAT_PORT_T_SPEED_10G] =		"10G",
	[NET_MAT_PORT_T_SPEED_20G] =		"20G",
	[NET_MAT_PORT_T_SPEED_25G] =		"25G",
	[NET_MAT_PORT_T_SPEED_40G] =		"40G",
	[NET_MAT_PORT_T_SPEED_100G] =		"100G",
};

static inline const char *port_speed_str(__u32 i) {
	return i < __NET_MAT_PORT_T_SPEED_MAX ? __port_speed_str[i] : "";
}

enum {
	NET_MAT_PORT_T_UNSPEC,
	NET_MAT_PORT_T_ID,
	NET_MAT_PORT_T_PHYS_ID,
	NET_MAT_PORT_T_TYPE,
	NET_MAT_PORT_T_STATE,
	NET_MAT_PORT_T_SPEED,
	NET_MAT_PORT_T_PCI,
	NET_MAT_PORT_T_MAC_ADDR,
	NET_MAT_PORT_T_STATS,
	NET_MAT_PORT_T_MAX_FRAME_SIZE,
	NET_MAT_PORT_T_VLAN,
	NET_MAT_PORT_T_LOOPBACK,
	NET_MAT_PORT_T_GLORT,
	__NET_MAT_PORT_T_MAX,
};
#define NET_MAT_PORT_T_MAX (__NET_MAT_PORT_T_MAX - 1)

enum port_type {
	NET_MAT_PORT_TYPE_UNSPEC,
	NET_MAT_PORT_TYPE_NETWORK,
	NET_MAT_PORT_TYPE_HOST,
	NET_MAT_PORT_TYPE_CPU,
	__NET_MAT_PORT_TYPE_MAX,
};

#define NET_MAT_PORT_ID_UNSPEC ~(0U)

struct net_mat_port {
	__u32 port_id;
	__u32 port_phys_id;
	char *name;
	enum port_type type;
	enum port_state state;
	enum port_speed speed;
	__u32 max_frame_size;
	__u64 mac_addr;
	struct net_mat_port_pci pci;
	struct net_mat_port_stats stats;
	struct net_mat_port_vlan vlan;
	enum flag_state loopback;
	__u32 glort;
};

enum {
	NET_MAT_PORT_UNSPEC,
	NET_MAT_PORT,
	NET_MAT_PORT_MIN_INDEX,
	NET_MAT_PORT_MAX_INDEX,
	__NET_MAT_PORT_MAX,
};
#define NET_MAT_PORT_MAX (__NET_MAT_PORT_MAX - 1)

enum {
	NET_MAT_IDENTIFIER_UNSPEC,
	NET_MAT_IDENTIFIER_IFINDEX, /* net_device ifindex */
};

enum {
	NET_MAT_UNSPEC,
	NET_MAT_IDENTIFIER_TYPE,
	NET_MAT_IDENTIFIER,

	NET_MAT_TABLES,
	NET_MAT_HEADERS,
	NET_MAT_ACTIONS,
	NET_MAT_HEADER_GRAPH,
	NET_MAT_TABLE_GRAPH,

	NET_MAT_RULES,
	NET_MAT_RULES_ERROR,

	NET_MAT_PORTS,

	__NET_MAT_MAX,
	NET_MAT_MAX = (__NET_MAT_MAX - 1),
};

enum {
	NET_MAT_TABLE_CMD_GET_TABLES,
	NET_MAT_TABLE_CMD_GET_HEADERS,
	NET_MAT_TABLE_CMD_GET_ACTIONS,
	NET_MAT_TABLE_CMD_GET_HDR_GRAPH,
	NET_MAT_TABLE_CMD_GET_TABLE_GRAPH,

	NET_MAT_TABLE_CMD_GET_RULES,
	NET_MAT_TABLE_CMD_SET_RULES,
	NET_MAT_TABLE_CMD_DEL_RULES,
	NET_MAT_TABLE_CMD_UPDATE_RULES,

	NET_MAT_TABLE_CMD_CREATE_TABLE,
	NET_MAT_TABLE_CMD_DESTROY_TABLE,
	NET_MAT_TABLE_CMD_UPDATE_TABLE,

	NET_MAT_PORT_CMD_GET_PORTS,
	NET_MAT_PORT_CMD_GET_LPORT,
	NET_MAT_PORT_CMD_GET_PHYS_PORT,
	NET_MAT_PORT_CMD_SET_PORTS,

	__NET_MAT_CMD_MAX,
	NET_MAT_CMD_MAX = (__NET_MAT_CMD_MAX - 1),
};

#define NET_MAT_GENL_NAME "net_mat_nl"
#define NET_MAT_GENL_VERSION 0x1

#endif /* _IF_MATCH_H */
