/*******************************************************************************
  Implementation of the IES (Intel Ethernet Switch) backend
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <inttypes.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#include "fm_sdk.h"
#include "fm_sdk_fm10000_int.h"

#include "models/ies_pipeline.h" /* Pipeline model */
#include "ieslib.h"
#include "matchlib.h"
#include "backend.h"
#include "matlog.h"

#define FM_MAIN_SWITCH         0
#define FM_DEFAULT_VLAN 1
#define MATCH_DEEP_INSPECTION_PROFILE_NSH 4
#define MATCH_DEEP_INSPECTION_PROFILE 5
#define MATCH_NSH_PORT 4790
#define MATCH_VXLAN_GPE_NSH_PROTO 4

fm_semaphore seqSem;
fm_int sw = FM_MAIN_SWITCH;

static struct my_ecmp_group ecmp_group[TABLE_NEXTHOP_SIZE];
static int l2mp_group[TABLE_L2_MP_SIZE];
static __u32 dummy_nh_ipaddr = 0x01010000;
#ifdef VXLAN_MCAST
static int match_mcast_group[MATCH_TABLE_SIZE];
#endif /* VXLAN_MCAST */

static int ies_pipeline_open(void *arg)
{
	struct switch_args *conf = (struct switch_args *)arg;
	int err = 0;
	int i;

	if (!conf->disable_switch_init) {
		err = switch_init(conf->single_vlan);
		if (err) {
			MAT_LOG(ERR, "switch_init() failed (%d)\n", err);
			return err;
		}
	}

	if (!conf->disable_switch_router_init) {
		err = switch_router_init(IES_ROUTER_MAC, 1, 0, 1, 1, 0);
		if (err) {
			MAT_LOG(ERR, "switch_router_init() failed (%d)\n", err);
			return err;
		}
	}

	for (i = 0; i < 2; i++) {
		fm_fm10000TeDGlort teDGlort;
		fm_fm10000TeTrapCfg teTrapCfg;

		if (conf->disable_switch_tunnel_engine_a_init && i == 0)
			continue;
		if (conf->disable_switch_tunnel_engine_b_init && i == 1)
			continue;

		err = switch_configure_tunnel_engine(i,
						     IES_ROUTER_MAC,
						     IES_ROUTER_MAC,
						     4789, 4789,
						     MATCH_NSH_PORT,
						     MATCH_NSH_PORT);
		if (err) {
			MAT_LOG(ERR, "switch_configure_tunnel_engine(%i) failed (%d)\n", i, err);
			return err;
		}

		err = fm10000GetTeDGlort(sw, i, 0, &teDGlort, false);
		if (err) {
			MAT_LOG(ERR, "GetTeDglort(%i) failed (%d)\n",
				i, err);
			return err;
		}

		teDGlort.setSGlort = true;
		err = fm10000SetTeDGlort(sw, i, 0, &teDGlort, false);
		if (err) {
			MAT_LOG(ERR, "SetTeDglort(%i) failed (%d)\n",
				i, err);
			return err;
		}

		err = fm10000GetTeTrap(sw, 0, &teTrapCfg, false);
		if (err) {
			MAT_LOG(ERR, "GetTeTrap(%i) failed (%d)\n", i, err);
			return err;
		}
		teTrapCfg.trapGlort = 0;
		teTrapCfg.noFlowMatch = FM_FM10000_TE_TRAP_DGLORT0;
		err = fm10000SetTeTrap(sw, 0, &teTrapCfg,
				       FM10000_TE_TRAP_BASE_DGLORT | FM10000_TE_TRAP_NO_FLOW_MATCH, false);
		if (err) {
			MAT_LOG(ERR, "SetTeTrap(%i) failed (%d)\n", i, err);
			return err;
		}
		MAT_LOG(DEBUG, "tunnel_engine(%i) is configured\n", i);
	}

	MAT_LOG(INFO, "switch is ready for accepting commands..\n");

	return 0;
}

static void ies_pipeline_close(void)
{
	switch_close();
}

static void ies_pipeline_get_rule_counters(struct net_mat_rule *rule)
{
	__u32 switch_table_id;
	int err;
	int i;

	/* make sure this rule specified the count action */
	for (i = 0; rule->actions[i].uid; ++i)
		if (rule->actions[i].uid == ACTION_COUNT)
			break;

	if (rule->actions[i].uid == 0)
		return;

	switch_table_id = rule->table_id - TABLE_DYN_START + 1;
	err = switch_get_rule_counters(rule->hw_ruleid, switch_table_id,
				       &rule->packets, &rule->bytes);
	if (err)
		MAT_LOG(ERR, "switch_get_rule_counters error (%d)\n", err);
}

static int ies_pipeline_del_rules(struct net_mat_rule *rule)
{
	unsigned char mac[6];
	__u64 mac_address = 0x0;
	int vlan_id = FM_DEFAULT_VLAN;
	__u32 switch_table_id = rule->table_id - TABLE_DYN_START + 1;
	int err = -EINVAL; /* Setting default to be EINVAL, change as needed*/
	struct net_mat_tbl *tbl, *src;
	int i;
	struct net_mat_field_ref *match;

	if (!rule->table_id) {
		MAT_LOG(ERR, "%s: No table_id in del_rule cmd\n", __func__);
		goto done;
	}

	switch (rule->table_id) {
	case TABLE_TCAM:
		MAT_LOG(ERR, "%s: direct rule programming to TABLE_TCAM is not supported\n",
			__func__);
		goto done;
		break;
#if 0
	case TABLE_ECMP_GROUP:
		MAT_LOG(ERR, "%s: rule programming to TABLE_ECMP_GROUP is not supported\n",
			__func__);
		err = -EINVAL;
		break;
	case TABLE_FORWARD_GROUP:
		MAT_LOG(ERR, "%s: rule programming to TABLE_FORWARD_GROUP is not supported\n",
			__func__);
		err = -EINVAL;
		break;
#endif
	case TABLE_NEXTHOP:
		err = switch_del_nh_entry(rule->matches, rule->actions);
		break;
	case TABLE_MAC:
		for (i = 0; rule->matches[i].instance; i++) {
			match = &rule->matches[i];
			switch (match->instance) {
			case HEADER_INSTANCE_ETHERNET:
				mac_address = match->v.u64.value_u64;
				memcpy(mac,
				       (unsigned  char *)&match->v.u64.value_u64, 6);
				break;
			case HEADER_INSTANCE_VLAN_OUTER:
				if (match->field != HEADER_VLAN_VID)
					goto done;

				vlan_id = match->v.u16.value_u16;
				break;
			default:
				goto done;
			}
		}

#ifdef DEBUG
		MAT_LOG(DEBUG, "%s: deleting mac entry vlan %d mac %02x:%02x:%02x:%02x:%02x:%02x\n",
			__func__, vlan_id, mac[0], mac[1], mac[2], mac[3],
			mac[4], mac[5]);
#endif /* DEBUG */

		err = switch_del_mac_entry(vlan_id, mac_address);
		break;
	case TABLE_L2_MP:
		err =  switch_del_L2MP_rule_entry(rule->matches);
		break;
	default:
		tbl = get_tables(rule->table_id);
		if (NULL == tbl) {
			err = -EINVAL;
			MAT_LOG(ERR, "%s: unknown table %i\n",
				__func__, rule->table_id);
			goto done;
		}

		src = get_tables(tbl->source);
		if (!src) {
			err = -EINVAL;
			MAT_LOG(ERR, "%s: unknown table source %i\n",
				__func__, tbl->source);
			goto done;
		}
		switch_table_id = rule->table_id - TABLE_DYN_START + 1;
		if (src->uid == TABLE_TCAM)
			err =  switch_del_TCAM_rule_entry(rule->hw_ruleid,
							  switch_table_id);
		else if ((src->uid == TABLE_TUNNEL_ENGINE_A) ||
			 (src->uid == TABLE_TUNNEL_ENGINE_B)) {
			err =  switch_del_TE_rule_entry(rule->hw_ruleid,
							switch_table_id);
		} else {
			err = -EINVAL;
			MAT_LOG(ERR, "%s: table %i has unknown source %d\n",
				__func__, rule->table_id, src->uid);
			goto done;
		}
		break;
	}
	/* In +ve scenario, err code will be updated automatically*/
done:
	return err;
}

static int ies_pipeline_set_rules(struct net_mat_rule *rule)
{
	struct net_mat_field_ref *match;
	struct net_mat_action *action;
	__u32 switch_table_id;
	int err = -EINVAL; /* Setting default to be EINVAL, change as needed*/
	struct net_mat_tbl *tbl, *src;

	if (!rule->table_id) {
		MAT_LOG(ERR, "%s: No table_id in set_rule cmd\n", __func__);
		goto done;
	}

	match = &rule->matches[0];
	action = &rule->actions[0];

	if (!match) {
		MAT_LOG(ERR, "%s: nop match abort\n", __func__);
		goto done;
	}

	if (!action) {
		MAT_LOG(ERR, "%s: nop action abort\n", __func__);
		goto done;
	}

	switch (rule->table_id) {
	case TABLE_TCAM:
		MAT_LOG(ERR, "%s: direct rule programming to TABLE_TCAM is not supported\n",
			__func__);
		goto done;
	case TABLE_TUNNEL_ENGINE_A:
	case TABLE_TUNNEL_ENGINE_B:
		MAT_LOG(ERR, "%s: direct rule programming to TABLE_TUNNEL_ENGINE_A or B is not supported\n",
			__func__);
		goto done;
	case TABLE_NEXTHOP:
		err = switch_add_nh_entry(rule->matches, rule->actions);
		break;
	case TABLE_MAC:
		err = switch_add_mac_entry(rule->matches, rule->actions);
		break;
	case TABLE_L2_MP:
		err = switch_add_L2MP_rule_entry(rule->matches, rule->actions);
		break;
	default:
		tbl = get_tables(rule->table_id);
		if (NULL == tbl) {
			err = -EINVAL;
			MAT_LOG(ERR, "%s: unknown table %i\n",
				__func__, rule->table_id);
			goto done;
		}

		src = get_tables(tbl->source);
		if (!src) {
			err = -EINVAL;
			MAT_LOG(ERR, "%s: unknown table source %i\n",
				__func__, tbl->source);
			goto done;
		}
		switch_table_id = rule->table_id - TABLE_DYN_START + 1;
		if (src->uid == TABLE_TCAM)
			err = switch_add_TCAM_rule_entry(&(rule->hw_ruleid),
							 switch_table_id,
							 rule->priority,
							 rule->matches,
							 rule->actions);
		else if ((src->uid == TABLE_TUNNEL_ENGINE_A) ||
			 (src->uid == TABLE_TUNNEL_ENGINE_B)) {
			err = switch_add_TE_rule_entry(&(rule->hw_ruleid),
						       switch_table_id,
						       rule->priority,
						       rule->matches,
						       rule->actions);
		} else {
			err = -EINVAL;
			MAT_LOG(ERR, "%s: table %i has unknown source %d\n",
				__func__, rule->table_id, src->uid);
			goto done;
		}
		break;
	}
	/* In +ve scenario, err code will be updated automatically*/
done:
	return err;
}

static int ies_pipeline_create_table(struct net_mat_tbl *tbl)
{
	__u32 switch_table_id;
	int err = -EINVAL;

	switch_table_id = tbl->uid - TABLE_DYN_START + 1;
	if (switch_table_id >= FM_FLOW_MAX_TABLE_TYPE) {
		MAT_LOG(ERR, "Error: Table ID must be between %u and %u, inclusive\n",
			TABLE_DYN_START,
			TABLE_DYN_START + FM_FLOW_MAX_TABLE_TYPE - 2);
		return err;
	}

	if (tbl->source == TABLE_TCAM) {
		err = switch_create_TCAM_table(switch_table_id,
					       tbl->matches, tbl->actions,
					       tbl->size, 1);
	} else if (tbl->source == TABLE_TUNNEL_ENGINE_A ||
		   tbl->source == TABLE_TUNNEL_ENGINE_B) {
		int te = (tbl->source == TABLE_TUNNEL_ENGINE_A) ? 0 : 1;

		err = switch_create_TE_table(te, switch_table_id,
					     tbl->matches, tbl->actions,
					     tbl->size, 1);
	}

	return err;
}

static int ies_pipeline_destroy_table(struct net_mat_tbl *tbl)
{
	__u32 switch_table_id;
	int err = -EINVAL;

	switch_table_id = tbl->uid - TABLE_DYN_START + 1;

	if (tbl->source == TABLE_TCAM) {
		err = switch_del_TCAM_table(switch_table_id);
	} else if (tbl->source == TABLE_TUNNEL_ENGINE_A ||
		   tbl->source == TABLE_TUNNEL_ENGINE_B) {
		err = switch_del_TE_table(switch_table_id);
	}

	return err;
}

static int ies_pipeline_update_table(struct net_mat_tbl *tbl)
{
	fm_fm10000TeTrapCfg teTrapCfg;
	bool have_dflt_port = false;
	int i, te, err = -EINVAL;
	__u16 dflt_port = 0;
	__u64 smac, dmac;

	if (!tbl->attribs)
		return -EINVAL;

	smac = values_tunnel_engine[IES_VXLAN_SRC_MAC].value.u64;
	dmac = values_tunnel_engine[IES_VXLAN_DST_MAC].value.u64;

	for (i = 0; tbl->attribs[i].uid; i++) {
		switch (tbl->attribs[i].uid) {
		case NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_SRC_MAC:
			smac = tbl->attribs[i].value.u64;
			break;
		case NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_DST_MAC:
			dmac = tbl->attribs[i].value.u64;
			break;
		case NET_MAT_TABLE_ATTR_NAMED_VALUE_MISS_DFLT_EGRESS_PORT:
			dflt_port = tbl->attribs[i].value.u16;
			have_dflt_port = true;
			break;
		default:
			return -EINVAL;
		}
	}

	switch (tbl->uid) {
	case TABLE_TUNNEL_ENGINE_A:
		te = 0;
		break;
	case TABLE_TUNNEL_ENGINE_B:
		te = 1;
		break;
	default:
		MAT_LOG(ERR, "ERROR: Table %i, does not support updates\n", tbl->uid);
		return -EINVAL;
	}

	err =  switch_tunnel_engine_set_default_smac(te, smac);
	if (err) {
		MAT_LOG(ERR, "Error: set_default_smac failed (%d)\n", err);
		return err;
	}

	err =  switch_tunnel_engine_set_default_dmac(te, dmac);
	if (err) {
		MAT_LOG(ERR, "Error: set_default_dmac failed (%d)\n", err);
		return err;
	}

	values_tunnel_engine[IES_VXLAN_SRC_MAC].value.u64 = smac;
	values_tunnel_engine[IES_VXLAN_DST_MAC].value.u64 = dmac;

	if (!have_dflt_port)
		return err;

	err = fm10000GetTeTrap(sw, te, &teTrapCfg, false);
	if (err) {
		MAT_LOG(ERR, "GetTeTrap(%i) failed (%d)\n", i, err);
		return err;
	}
	teTrapCfg.trapGlort = dflt_port;
	teTrapCfg.noFlowMatch = FM_FM10000_TE_TRAP_DGLORT0;
	err = fm10000SetTeTrap(sw, 0, &teTrapCfg,
			       FM10000_TE_TRAP_BASE_DGLORT | FM10000_TE_TRAP_NO_FLOW_MATCH, false);
	if (err) {
		MAT_LOG(ERR, "SetTeTrap(%i) failed (%d)\n", i, err);
		return err;
	}

	values_tunnel_engine[IES_VXLAN_MISS_DFLT_PORT].value.u16 = dflt_port;

	return err;
}

static int cleanup(const char *src, int err)
{
	MAT_LOG(ERR, "ERROR: %s: %s\n", src, fmErrorMsg(err));
	return -1;
}

static void ies_get_pkt_stats(struct net_mat_port_stats *s, fm_portCounters *c)
{
	s->rx_packets = c->cntRxUcstPkts +
			c->cntRxBcstPkts +
			c->cntRxMcstPkts;

	s->tx_packets = c->cntTxUcstPkts +
			c->cntTxBcstPkts +
			c->cntTxMcstPkts;
}

static int ies_ports_get(struct net_mat_port **ports)
{
	struct net_mat_port *p;
	fm_switchInfo swInfo;
	int cpi;
	int i;

	fmGetSwitchInfo(sw, &swInfo);

	p = calloc((size_t)swInfo.numCardPorts + 1, sizeof(struct net_mat_port));
	if (!p)
		return -ENOMEM;

	for (i = 0, cpi = 1 ; cpi < swInfo.numCardPorts ; cpi++)  {
		fm_int err;
		fm_int port;
		fm_bool	pi = FM_DISABLED;
		fm_bool drop_tagged = FM_DISABLED;
		fm_bool drop_untagged = FM_DISABLED;
		fm_int loopback = FM_PORT_LOOPBACK_OFF;
		fm_int mode, state, info[64];
		fm_portCounters counter;
		fm_uint32 speed;

		err = fmMapCardinalPort(sw, cpi, &port, NULL);
		if (err != FM_OK) {
			free(p);
			return cleanup("fmMapCardinalPort", err);
		}

		err = fmGetPortAttribute(sw, port, FM_PORT_INTERNAL, &pi);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute", err);
			continue;
		}

		if (pi == FM_ENABLED)
			continue;

		err = fmGetPortAttribute(sw, port, FM_PORT_SPEED, &speed);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute(... FM_PORT_SPEED ...", err);
			continue;
		}

		err = fmGetPortAttribute(sw, port, FM_PORT_MAX_FRAME_SIZE,
					 &p[i].max_frame_size);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute()", err);
			continue;
		}

		err = fmGetPortState(sw, port, &mode, &state, info);
		if (err != FM_OK && err != FM_ERR_BUFFER_FULL) {
			cleanup("fmGetPortState()", err);
			continue;
		}

		err = fmGetPortCounters(sw, port, &counter);
		if (err != FM_OK)
			cleanup("fmGetPortCounters()", err);
		else
			ies_get_pkt_stats(&p[i].stats, &counter);

		switch (speed) {
		case 100000:
			p[i].speed = NET_MAT_PORT_T_SPEED_100G;
			break;
		case 40000:
			p[i].speed = NET_MAT_PORT_T_SPEED_40G;
			break;
		case 20000:
			p[i].speed = NET_MAT_PORT_T_SPEED_20G;
			break;
		case 10000:
			p[i].speed = NET_MAT_PORT_T_SPEED_10G;
			break;
		case 1000:
			p[i].speed = NET_MAT_PORT_T_SPEED_1G;
			break;
		case 2500:
			p[i].speed = NET_MAT_PORT_T_SPEED_2D5G;
			break;
		default:
			p[i].speed = 0;
			break;
		}

		switch (state) {
		case FM_PORT_STATE_UP:
			p[i].state = NET_MAT_PORT_T_STATE_UP;
			break;
		case FM_PORT_STATE_DOWN:
			p[i].state = NET_MAT_PORT_T_STATE_DOWN;
			break;
		default:
			MAT_LOG(ERR, "Warning: unknown port state %i\n", state);
			break;
		}

		err = fmGetPortAttribute(sw, port, FM_PORT_DEF_VLAN,
					 &p[i].vlan.def_vlan);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute()", err);
			continue;
		}

		err = fmGetPortAttribute(sw, port, FM_PORT_DROP_TAGGED,
					 &drop_tagged);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute()", err);
			continue;
		}

		switch (drop_tagged) {
		case FM_DISABLED:
			p[i].vlan.drop_tagged = NET_MAT_PORT_T_FLAG_DISABLED;
			break;
		case FM_ENABLED:
			p[i].vlan.drop_tagged = NET_MAT_PORT_T_FLAG_ENABLED;
			break;
		default:
			p[i].vlan.drop_tagged = NET_MAT_PORT_T_FLAG_UNSPEC;
			MAT_LOG(ERR, "Warning: unknown flag value %d\n", drop_tagged);
			break;
		}

		err = fmGetPortAttribute(sw, port, FM_PORT_DROP_UNTAGGED,
					 &drop_untagged);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute()", err);
			continue;
		}

		switch (drop_untagged) {
		case FM_DISABLED:
			p[i].vlan.drop_untagged = NET_MAT_PORT_T_FLAG_DISABLED;
			break;
		case FM_ENABLED:
			p[i].vlan.drop_untagged = NET_MAT_PORT_T_FLAG_ENABLED;
			break;
		default:
			p[i].vlan.drop_untagged = NET_MAT_PORT_T_FLAG_UNSPEC;
			MAT_LOG(ERR, "Warning: unknown flag value %d\n", drop_untagged);
			break;
		}

		err = fmGetPortAttribute(sw, port, FM_PORT_DEF_PRI,
					 &p[i].vlan.def_priority);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute()", err);
			continue;
		}

		err = fmGetPortAttribute(sw, port, FM_PORT_LOOPBACK, &loopback);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute()", err);
			continue;
		}

		switch (loopback) {
		case FM_PORT_LOOPBACK_OFF:
			p[i].loopback = NET_MAT_PORT_T_FLAG_DISABLED;
			break;
		case FM_PORT_LOOPBACK_TX2RX:
			p[i].loopback = NET_MAT_PORT_T_FLAG_ENABLED;
			break;
		default:
			p[i].loopback = NET_MAT_PORT_T_FLAG_UNSPEC;
			MAT_LOG(ERR, "Warning: unknown or unsupported loopback value %d\n", loopback);
			break;
		}

		p[i].port_id = (__u32)cpi;
		i++;
	}

	*ports = p;

	return 0;
}

static fm_uint32 speed_to_mode(enum port_speed speed)
{
	switch(speed) {
	case NET_MAT_PORT_T_SPEED_1G:
		return FM_ETH_MODE_1000BASE_X;
	case NET_MAT_PORT_T_SPEED_10G:
		return FM_ETH_MODE_10GBASE_SR;
	case NET_MAT_PORT_T_SPEED_25G:
		return FM_ETH_MODE_25GBASE_SR;
	case NET_MAT_PORT_T_SPEED_40G:
		return FM_ETH_MODE_40GBASE_SR4;
	case NET_MAT_PORT_T_SPEED_100G:
		return FM_ETH_MODE_100GBASE_SR4;
	default:
		return FM_ETH_MODE_DISABLED;
	}
}

static int set_port_speed(int port, enum port_speed speed)
{
	fm_uint32 cur_mode = FM_ETH_MODE_DISABLED;
	fm_uint32 new_mode = FM_ETH_MODE_DISABLED;
	int err;

	err = fmGetPortAttribute(sw, port, FM_PORT_ETHERNET_INTERFACE_MODE,
	                         &cur_mode);
	if (err != FM_OK)
		return cleanup("fmGetPortAttribute", err);

	/*
	 * Set the new Ethernet mode based on the existing mode and desired
	 * speed. Only fiber modes can be explicitely set since many copper
	 * modes are required to be auto-negotiated.
	 */
	switch (cur_mode) {
	case FM_ETH_MODE_1000BASE_X:
	case FM_ETH_MODE_10GBASE_SR:
	case FM_ETH_MODE_25GBASE_SR:
	case FM_ETH_MODE_40GBASE_SR4:
	case FM_ETH_MODE_100GBASE_SR4:
		new_mode = speed_to_mode(speed);
		break;
	default:
		new_mode = FM_ETH_MODE_DISABLED;
		break;
	}

	if (new_mode == FM_ETH_MODE_DISABLED) {
		MAT_LOG(ERR, "Cannot set port %d speed to %s\n", port,
		        port_speed_str(speed));
		return -EINVAL;
	} else if (new_mode != cur_mode) {
		err = fmSetPortAttribute(sw, port,
		                         FM_PORT_ETHERNET_INTERFACE_MODE,
		                         &new_mode);
		if (err != FM_OK)
			return cleanup("fmSetPortAttribute", err);
	}

	MAT_LOG(DEBUG, "Port %d speed %s\n", port, port_speed_str(speed));
	return 0;
}

static int ies_ports_set(struct net_mat_port *ports)
{
	struct net_mat_port *p;
	fm_switchInfo swInfo;
	fm_bool drop_tagged = FM_DISABLED;
	fm_bool drop_untagged = FM_DISABLED;
	fm_int loopback = FM_PORT_LOOPBACK_OFF;
	int i, err = 0;

	fmGetSwitchInfo(sw, &swInfo);

	for (p = &ports[0], i = 0 ; p->port_id > 0; p = &ports[i], i++)  {
		fm_int port = (int)p->port_id;

		switch (p->state) {
		case NET_MAT_PORT_T_STATE_UNSPEC:
			break;
		case NET_MAT_PORT_T_STATE_UP:
			err = fmSetPortState(sw, port, FM_PORT_MODE_UP, 0);
			break;
		case NET_MAT_PORT_T_STATE_DOWN:
			err = fmSetPortState(sw, port, FM_PORT_MODE_ADMIN_DOWN, 0);
			break;
		default:
			return -EINVAL;
		}

		if (err) {
			MAT_LOG(ERR, "Error: SetPortState failed!\n");
			return -EINVAL;
		}

		if (p->speed != NET_MAT_PORT_T_SPEED_UNSPEC) {
			err = set_port_speed(port, p->speed);
			if (err) {
				MAT_LOG(ERR, "Error: Set Port Speed failed!\n");
				return -EINVAL;
			}
		}

		if (p->max_frame_size) {
			err = fmSetPortAttribute(sw, port,
						 FM_PORT_MAX_FRAME_SIZE,
						 &p->max_frame_size);
			if (err) {
				MAT_LOG(ERR, "Error: SetPortAttribute FM_PORT_MAX_FRAME_SIZE failed!\n");
				return -EINVAL;
			}
		}

		if (p->vlan.def_vlan) {
			err = fmSetPortAttribute(sw, port, FM_PORT_DEF_VLAN,
						 &p->vlan.def_vlan);
			if (err) {
				MAT_LOG(ERR, "Error: SetPortAttribute FM_PORT_DEF_VLAN failed!\n");
				return -EINVAL;
			}
		}

		switch (p->vlan.drop_tagged) {
		case NET_MAT_PORT_T_FLAG_UNSPEC:
			break;
		case NET_MAT_PORT_T_FLAG_ENABLED:
			drop_tagged = FM_ENABLED;
			err = fmSetPortAttribute(sw, port, FM_PORT_DROP_TAGGED, &drop_tagged);
			break;
		case NET_MAT_PORT_T_FLAG_DISABLED:
			drop_tagged = FM_DISABLED;
			err = fmSetPortAttribute(sw, port, FM_PORT_DROP_TAGGED, &drop_tagged);
			break;
		default:
			return -EINVAL;
		}

		if (err) {
			MAT_LOG(ERR, "Error: fmSetPortAttribute FM_PORT_DROP_TAGGED failed!\n");
			return -EINVAL;
		}

		switch (p->vlan.drop_untagged) {
		case NET_MAT_PORT_T_FLAG_UNSPEC:
			break;
		case NET_MAT_PORT_T_FLAG_ENABLED:
			drop_untagged = FM_ENABLED;
			err = fmSetPortAttribute(sw, port, FM_PORT_DROP_UNTAGGED, &drop_untagged);
			break;
		case NET_MAT_PORT_T_FLAG_DISABLED:
			drop_untagged = FM_DISABLED;
			err = fmSetPortAttribute(sw, port, FM_PORT_DROP_UNTAGGED, &drop_untagged);
			break;
		default:
			return -EINVAL;
		}

		if (err) {
			MAT_LOG(ERR, "Error: fmSetPortAttribute FM_PORT_DROP_UNTAGGED failed!\n");
			return -EINVAL;
		}

		if (p->vlan.def_priority != NET_MAT_PORT_T_DEF_PRI_UNSPEC) {
			err = fmSetPortAttribute(sw, port, FM_PORT_DEF_PRI,
			                         &p->vlan.def_priority);
			if (err) {
				MAT_LOG(ERR, "Error: SetPortAttribute FM_PORT_DEF_PRI failed!\n");
				return -EINVAL;
			}
		}

		switch (p->loopback) {
		case NET_MAT_PORT_T_FLAG_UNSPEC:
			break;
		case NET_MAT_PORT_T_FLAG_ENABLED:
			loopback = FM_PORT_LOOPBACK_TX2RX;
			err = fmSetPortAttribute(sw, port, FM_PORT_LOOPBACK, &loopback);
			break;
		case NET_MAT_PORT_T_FLAG_DISABLED:
			loopback = FM_PORT_LOOPBACK_OFF;
			err = fmSetPortAttribute(sw, port, FM_PORT_LOOPBACK, &loopback);
			break;
		default:
			return -EINVAL;
		}

		if (err) {
			MAT_LOG(ERR, "Error: fmSetPortAttribute FM_PORT_LOOPBACK failed!\n");
			return -EINVAL;
		}
	}

	return err;
}

/*
 * Convert a PCI address to a PEP number.
 *
 * The PEP number is read from the Vital Product Data (VPD)
 * file stored in the device's pci sysfs directory.
 *
 * The PCI domain is hardcoded to 0 for now.
 *
 * The PCI device and functions are hardcoded to 0 because the VPD
 * file is only present for the physical function, which is device 0,
 * function 0.
 *
 * @param bus
 *   The pci bus number.
 *
 * @return
 *   The PEP number on success, or a negative error code.
 */
#define PCI_PATH_BASE "/sys/bus/pci/devices"
#define PCI_DEV_FMT "0000:%02" PRIx8 ":00.0"
#define PCI_VPD "vpd"
static int pci_to_pep(uint8_t bus)
{
	char fname[PATH_MAX];
	uint32_t buf[BUFSIZ];
	FILE *f;
	size_t n;
	int err;

	/* read Vital Product Data from sysfs pci device file */
	err = snprintf(fname, sizeof(fname),
		       PCI_PATH_BASE "/" PCI_DEV_FMT "/" PCI_VPD, bus);

	if (err < 0 || err >= (int)sizeof(fname))
		return -ENOMEM;

	f = fopen(fname, "r");
	if (!f) {
		MAT_LOG(ERR, "Error: Cannot open %s\n", fname);
		return -errno;
	}

	n = fread(buf, sizeof(uint32_t), 8, f);
	if (n != 8) {
		MAT_LOG(ERR, "Error: Cannot read %s\n", fname);
		fclose(f);
		return -errno;
	}

	fclose(f);

	/* pep index is stored in bits 12:9 of the sixth dword in the vpd */
	return (int)((buf[5] & 0xf00) >> 8);
}

static int pci_to_lport(uint8_t bus, uint8_t device, uint8_t function,
                        unsigned int *lport,  unsigned int *glort)
{
	int err;
	int index;
	int pep;
	int port = -1;
	int type;

	pep = pci_to_pep(bus);
	if (pep < 0) {
		MAT_LOG(ERR, "Error: %02x:%02x.%d is not supported.\n",
		        bus, device, function);
		return -EINVAL;
	}

	if (!device && !function) {
		/* PF always has device == 0 and function == 0 */
		index = 0;
		type = FM_PCIE_PORT_PF;
	} else if (function < 8) {
		/*
		 * For a VF, there are up to 8 functions created per PCI
		 * device. If there are more than 7 VFs created, the device
		 * will be incremented, and the function numbering will
		 * restart from 0.
		 */
		index = (device * 8 + function) - 1;
		type = FM_PCIE_PORT_VF;
	} else {
		MAT_LOG(ERR, "Error: %02x:%02x.%d has invalid function.\n",
		        bus, device, function);
		return -EINVAL;
	}

	err = fmGetPcieLogicalPort(sw, pep, type, index, &port);
	if (err != FM_OK)
		return cleanup("fmGetPcieLogicalPort", err);

	if (port < 0) {
		MAT_LOG(ERR, "Error: unexpected negative lport\n");
		return -EINVAL;
	}

	*lport = (unsigned int)port;
	if (glort) {
		err = fmGetLogicalPortGlort(sw, (fm_int)*lport, glort);
		if (err != FM_OK)
			return cleanup("fmGetLogicalPortGlort", err);
	}

	if (glort)
		MAT_LOG(DEBUG, "get_lport pci %u:%u.%u lport %d glort 0x%x\n",
		        bus, device, function, *lport, *glort);
	else
		MAT_LOG(DEBUG, "get_lport pci %u:%u.%u lport %d\n",
		        bus, device, function, *lport);

	return 0;
}

static int lport_to_glort(unsigned int lport,  unsigned int *glort)
{
	int status = -EINVAL;

	if (glort) {
		status = fmGetLogicalPortGlort(sw, (fm_int)lport, glort);
		if (status != FM_OK)
			return cleanup("fmGetLogicalPortGlort", status);
	}

	return status;
}

static int mac_to_lport(uint64_t mac, unsigned int *lport, unsigned int *glort)
{
	fm_status err;
	fm_int nEntries = 0;
	fm_macAddressEntry *entries = NULL;
	int i;

	err = fmGetAddressTableExt(sw, &nEntries, NULL, 0);
	if (err)
		return cleanup(__func__, err);

	if (nEntries == 0)
		return -ENOENT;

	entries = malloc(sizeof(*entries) * (size_t)nEntries);
	if (!entries)
		return -ENOMEM;

	err = fmGetAddressTableExt(sw, &nEntries, entries, nEntries);
	if (err) {
		free(entries);
		return cleanup(__func__, err);
	}

	for (i = 0; i < nEntries; ++i) {
		uint64_t hw_addr = entries[i].macAddress;
		int port = entries[i].port;

		if (mac == hw_addr) {
			*lport = (unsigned int)port;

			if (glort) {
				err = fmGetLogicalPortGlort(sw, (fm_int)*lport,
				                            glort);
				if (err != FM_OK) {
					free(entries);
					return cleanup("fmGetLogicalPortGlort",
					               err);
				}
			}

			free(entries);
			return 0;
		}
	}

	free(entries);
	return -ENOENT;
}

static int ies_port_get_lport(struct net_mat_port *port,
                              unsigned int *lport, unsigned int *glort)
{
	int err = -EINVAL;

	if (port->pci.bus != 0)
		err = pci_to_lport(port->pci.bus, port->pci.device,
		                   port->pci.function, lport, glort);
	else if (port->mac_addr != 0)
		err = mac_to_lport(port->mac_addr, lport, glort);
	else if (port->port_id != 0) {
		*lport = port->port_id;
		err = lport_to_glort(port->port_id, glort);
	}

	return err;
}

static int lport_to_phys_port(unsigned int lport, unsigned int *phys_port,
                              unsigned int *glort)
{
	int port_id;
	int err;

	PROTECT_SWITCH(sw);
	err = fmMapLogicalPortToPhysical(GET_SWITCH_PTR(sw), (int)lport, &port_id);
	UNPROTECT_SWITCH(sw);

	if (err != FM_OK)
		return cleanup("fmMapLogicalPortToPhysical", err);

	if (glort) {
		err = fmGetLogicalPortGlort(sw, (fm_int)lport, glort);
		if (err != FM_OK)
			return cleanup("fmGetLogicalPortGlort", err);
	}

	*phys_port = (unsigned int) port_id;

	return 0;
}

static int ies_port_get_phys_port(struct net_mat_port *port,
                                  unsigned int *phys_port, unsigned int *glort)
{
	int err = -EINVAL;

	if (port->port_id != 0)
		err = lport_to_phys_port(port->port_id, phys_port, glort);

	return err;
}

struct match_backend ies_pipeline_backend = {
	.name = "ies_pipeline",
	.hdrs = my_header_list,
	.actions = my_action_list,
	.tbls = my_table_list,
	.hdr_nodes = my_hdr_nodes,
	.tbl_nodes = my_tbl_nodes,
	.open = ies_pipeline_open,
	.close = ies_pipeline_close,
	.get_rule_counters = ies_pipeline_get_rule_counters,
	.del_rules = ies_pipeline_del_rules,
	.set_rules = ies_pipeline_set_rules,
	.create_table = ies_pipeline_create_table,
	.destroy_table = ies_pipeline_destroy_table,
	.update_table = ies_pipeline_update_table,
	.get_ports = ies_ports_get,
	.set_ports = ies_ports_set,
	.get_lport = ies_port_get_lport,
	.get_phys_port = ies_port_get_phys_port,
};

MATCH_BACKEND_REGISTER(ies_pipeline_backend)

static void eventHandler(fm_int event, fm_int sw, void *ptr)
{
	fm_eventPort *portEvent = (fm_eventPort *) ptr;

	FM_NOT_USED(sw);

	switch (event) {
	case FM_EVENT_SWITCH_INSERTED:
		MAT_LOG(INFO, "Switch #%d inserted!\n", sw);
		if (sw == FM_MAIN_SWITCH)
			fmSignalSemaphore(&seqSem);
		break;

	case FM_EVENT_PORT:
		MAT_LOG(INFO, "port event: port %d is %s\n", portEvent->port, (portEvent->linkStatus ? "up" : "down"));
		break;

	case FM_EVENT_PKT_RECV:
		MAT_LOG(INFO, "packet received\n");
		break;
	}
}

static int configure_deep_inspection(void)
{
	int err;
	fm_parserDiCfg dip;
	fm_parserDiCfg dip_expect = {
		.index = MATCH_DEEP_INSPECTION_PROFILE,
		.parserDiCfgFields = {
			.enable = 1,
			.protocol = 0x11, /* UDP */
			.l4Port = 4789, /* VXLAN */
			.l4Compare = 1,
			.wordOffset = 0x76543210,
		},
	};

	/* read existing deep inspection configuration */
	memset(&dip, 0, sizeof(dip));
	dip.index = MATCH_DEEP_INSPECTION_PROFILE;

	err = fmGetSwitchAttribute(sw, FM_SWITCH_PARSER_DI_CFG, &dip);
	if (err != FM_OK) {
		MAT_LOG(ERR, "Error: get deep inspection parser\n");
		return cleanup("fmGetSwitchAttribute", err);
	}

	if (!memcmp(&dip, &dip_expect, sizeof(dip)))
		/* parser is configured as expected */
		return 0;
	else if (dip.parserDiCfgFields.enable)
		/* parser is configured, but not as expected */
		return -EEXIST;

	/* parser needs to be configured */
	err = fmSetSwitchAttribute(sw, FM_SWITCH_PARSER_DI_CFG, &dip_expect);
	if (err != FM_OK) {
		MAT_LOG(ERR, "Error: deep inspection parser\n");
		return cleanup("fmSetSwitchAttribute", err);
	}

	return 0;
}

static int configure_deep_inspection_nsh(void)
{
	int err;
	fm_parserDiCfg dip;
	fm_parserDiCfg dip_expect = {
		.index = MATCH_DEEP_INSPECTION_PROFILE_NSH,
		.parserDiCfgFields = {
			.enable = 1,
			.protocol = 0x11, /* UDP */
			.l4Port = MATCH_NSH_PORT, /* VXLAN-GPE */
			.l4Compare = 1,
			.wordOffset = 0x76543210,
		},
	};

	/* read existing deep inspection configuration */
	memset(&dip, 0, sizeof(dip));
	dip.index = MATCH_DEEP_INSPECTION_PROFILE_NSH;

	err = fmGetSwitchAttribute(sw, FM_SWITCH_PARSER_DI_CFG, &dip);
	if (err != FM_OK) {
		fprintf(stderr, "Error: get deep inspection parser\n");
		return cleanup("fmGetSwitchAttribute", err);
	}

	if (!memcmp(&dip, &dip_expect, sizeof(dip)))
		/* parser is configured as expected */
		return 0;
	else if (dip.parserDiCfgFields.enable)
		/* parser is configured, but not as expected */
		return -EEXIST;

	/* parser needs to be configured */
	err = fmSetSwitchAttribute(sw, FM_SWITCH_PARSER_DI_CFG, &dip_expect);
	if (err != FM_OK) {
		fprintf(stderr, "Error: deep inspection parser\n");
		return cleanup("fmSetSwitchAttribute", err);
	}

	return 0;
}

static void
ies_log(fm_text buf, fm_voidptr cookie1 __attribute__((unused)),
	fm_voidptr cookie2 __attribute__((unused)))
{
	MAT_LOG(DEBUG, "%s", buf);
}

int switch_init(int one_vlan)
{
	fm_status       err = 0;
	fm_timestamp    wait = { 3, 0 };
	fm_int          cpi;
	fm_int          port;
	fm_uint16	vlan;
	fm_switchInfo   swInfo;
	fm_bool		vr = FM_ENABLED;
	fm_bool		bv = FM_DISABLED;
	fm_bool		re = FM_ENABLED;
	fm_bool		pi = FM_DISABLED;
	fm_int		pc = FM_PORT_PARSER_STOP_AFTER_L4;
	fm_uint32	defvlan;
	fm_logCallBackSpec logCallBackSpec;
#ifdef VXLAN_MCAST
	int		i;
#endif /* VXLAN_MCAST */

	fmOSInitialize();

	logCallBackSpec.callBack = ies_log;
	err = fmSetLoggingType(FM_LOG_TYPE_CALLBACK, 0, &logCallBackSpec);
	if (err)
		return cleanup("fmSetLoggingType", err);

	fmCreateSemaphore(seq_str, FM_SEM_BINARY, &seqSem, 0);

	err = fmInitialize(eventHandler);
	if (err != FM_OK)
		return cleanup("fmInitialize", err);

	fmWaitSemaphore(&seqSem, &wait);

	err = fmSetSwitchState(sw, TRUE);
	if (err != FM_OK)
		return cleanup("fmSetSwitchState", err);

	defvlan = vlan = FM_DEFAULT_VLAN;

	fmGetSwitchInfo(sw, &swInfo);

	if (one_vlan) {
		MAT_LOG(DEBUG, "initializing single vlan setup ...\n");
		fmCreateVlan(sw, vlan);
		MAT_LOG(DEBUG, "enable vlan reflect on vlan %d\n", vlan);
		fmSetVlanAttribute(sw, vlan, FM_VLAN_REFLECT, &vr);
	}

	/* init non cpu ports and put them into their own vlan, make sure */
	/* the parser goes to l4, no vlan boundary check, and routable    */
	for (cpi = 1 ; cpi < swInfo.numCardPorts ; cpi++) {
		err = fmMapCardinalPort(sw, cpi, &port, NULL);
		if (err != FM_OK)
			return cleanup("fmMapCardinalPort", err);

		MAT_LOG(DEBUG, "cpi=%d, port=%d\n", cpi, port);

		err = fmGetPortAttribute(sw, port, FM_PORT_INTERNAL, &pi);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute", err);
			MAT_LOG(DEBUG, "skip port %d\n", port);
			continue;
		}
		if (pi == FM_ENABLED) {
			MAT_LOG(DEBUG, "skip internal port %d\n", port);
			continue;
		}

		if (!one_vlan) {
			vlan = (fm_uint16)port;
			defvlan = (fm_uint32)vlan;

			MAT_LOG(DEBUG, "creating vlan %d\n", vlan);
			fmCreateVlan(sw, vlan);

			MAT_LOG(DEBUG, "enable vlan reflect on vlan %d\n", vlan);
			fmSetVlanAttribute(sw, vlan, FM_VLAN_REFLECT, &vr);
		}

		err = fmSetPortState(sw, port, FM_PORT_STATE_UP, 0);
		if (err != FM_OK)
			return cleanup("fmSetPortState", err);

		MAT_LOG(DEBUG, "set port %d to UP\n", port);

		err = fmAddVlanPort(sw, vlan, port, FALSE);
		if (err != FM_OK)
			return cleanup("fmAddVlanPort", err);

		MAT_LOG(DEBUG, "add port %d to vlan %u\n", port, vlan);

		err = fmSetVlanPortState(sw, vlan, port, FM_STP_STATE_FORWARDING);
		if (err != FM_OK)
			return cleanup("fmSetVlanPortState", err);

		MAT_LOG(DEBUG, "set STP state of port %d in vlan %u to forwarding\n", port, vlan);

		err = fmSetPortAttribute(sw, port, FM_PORT_DEF_VLAN, &defvlan);
		if (err != FM_OK)
			return cleanup("fmSetPortAttribute", err);

		MAT_LOG(DEBUG, "set pvid for  port %d to vlan %u\n", port, vlan);

		err = fmSetPortAttribute(sw, port, FM_PORT_DROP_BV, &bv);
		if (err != FM_OK)
			return cleanup("fmSetPortAttribute", err);

		MAT_LOG(DEBUG, "set FM_PORT_DROP_BV for port %d to %d\n", port, bv);

		err = fmSetPortAttribute(sw, port, FM_PORT_PARSER, &pc);
		if (err != FM_OK)
			return cleanup("fmSetPortAttribute", err);

		MAT_LOG(DEBUG, "set FM_PORT_PARSER for port %d to %d\n", port, pc);

		err = fmSetPortAttribute(sw, port, FM_PORT_ROUTABLE, &re);
		if (err != FM_OK)
			return cleanup("fmSetPortAttribute", err);

		MAT_LOG(DEBUG, "set FM_PORT_ROUTABLE for port %d to %d\n", port, re);
	}

	/* port cpu port on default vlan */
	defvlan = vlan = FM_DEFAULT_VLAN;
	err = fmGetCpuPort(sw, &port);
	if (err != FM_OK)
		return cleanup("fmGetCpuPort", err);

	MAT_LOG(DEBUG, "find cpu port %d\n", port);
	err = fmAddVlanPort(sw, vlan, port, FALSE);
	if (err != FM_OK)
		return cleanup("fmAddVlanPort", err);

	MAT_LOG(DEBUG, "add port %d to vlan %u\n", port, vlan);
	err = fmSetPortAttribute(sw, port, FM_PORT_DEF_VLAN, &defvlan);
	if (err != FM_OK)
		return cleanup("fmSetPortAttribute", err);

	MAT_LOG(DEBUG, "set pvid for  port %d to vlan %u\n", port, vlan);

	MAT_LOG(DEBUG, "Switch is UP, all ports are now enabled\n");

#ifdef VXLAN_MCAST
	for (i = 0; i < MATCH_TABLE_SIZE; i++)
		match_mcast_group[i] = -1;
#endif /* VXLAN_MCAST */

	return err;
}

static void switch_clean_shm(void)
{
	char *shm_key_env = NULL, *shm_key_str = NULL;
	int shm_key = 0;
	int shm_id = 0;
	struct shmid_ds shm_info;

	MAT_LOG(DEBUG, "Cleaning up shared memory...");
	shm_key_env = getenv("FM_API_SHM_KEY");
	if (shm_key_env != NULL) {
		shm_key_str = strtok(shm_key_env, ",");
		if (!shm_key_str)
			return;
		shm_key = (int)strtol(shm_key_str, NULL, 10);
		MAT_LOG(DEBUG, "shm_key=%d", shm_key);

		shm_id = shmget(shm_key, 0, 0);
		MAT_LOG(DEBUG, ",shm_id=0x%x", shm_id);

		 if (shm_id != -1)
			shmctl(shm_id, IPC_RMID, &shm_info);
	}
	MAT_LOG(DEBUG, "...done.\n");
}

void switch_close(void)
{
	switch_clean_shm();

	MAT_LOG(DEBUG, "Calling fmTerminate()\n");
	fmTerminate();
}

int switch_router_init(__u64 router_mac, int update_dmac, int update_smac,
		       int update_vlan, int update_ttl, int curr_sw)
{
	fm_status       err = 0;
	int		i;
	fm_int          cpi;
	fm_int          port;
	fm_uint32	ru = 0;
	fm_bool		pi = FM_DISABLED;
	fm_bool		rt = 0;
	fm_switchInfo   swInfo;

	for (i = 0; i < TABLE_NEXTHOP_SIZE; i++) {
		ecmp_group[i].hw_group_id = -1;
		ecmp_group[i].num_nhs = 0;
	}

	memset(l2mp_group, -1, sizeof(l2mp_group));

	if (curr_sw)
		sw = curr_sw;

	fmGetSwitchInfo(sw, &swInfo);

	ru = (fm_uint32)(update_dmac ? FM_PORT_ROUTED_FRAME_UPDATE_DMAC : 0) |
	     (fm_uint32)(update_smac ? FM_PORT_ROUTED_FRAME_UPDATE_SMAC : 0) |
	     (fm_uint32)(update_vlan ? FM_PORT_ROUTED_FRAME_UPDATE_VLAN : 0);

	rt = update_ttl ? FM_ENABLED : FM_DISABLED;

	for (cpi = 1 ; cpi < swInfo.numCardPorts ; cpi++) {
		err = fmMapCardinalPort(sw, cpi, &port, NULL);
		if (err != FM_OK)
			return cleanup("fmMapCardinalPort", err);

		MAT_LOG(DEBUG, "cpi=%d, port=%d\n", cpi, port);

		err = fmGetPortAttribute(sw, port, FM_PORT_INTERNAL, &pi);
		if (err != FM_OK) {
			cleanup("fmGetPortAttribute", err);
			MAT_LOG(DEBUG, "skip port %d\n", port);
			continue;
		}
		if (pi == FM_ENABLED) {
			MAT_LOG(DEBUG, "skip internal port %d\n", port);
			continue;
		}

		err = fmSetPortAttribute(sw, port, FM_PORT_ROUTED_FRAME_UPDATE_FIELDS, &ru);
		if (err != FM_OK)
			return cleanup("fmSetPortAttribute", err);

		MAT_LOG(DEBUG, "set FM_PORT_ROUTED_FRAME_UPDATE_FIELDS for port %d to 0x%08x\n", port, ru);

		err = fmSetPortAttribute(sw, port, FM_PORT_UPDATE_TTL, &rt);
		if (err != FM_OK)
			return cleanup("fmSetPortAttribute", err);

		MAT_LOG(DEBUG, "set FM_PORT_UPDATE_TTL for port %d to %d\n", port, rt);
	}

	err = fmSetRouterAttribute(sw, FM_ROUTER_PHYSICAL_MAC_ADDRESS, (void *)&router_mac);
	if (err != FM_OK)
		return cleanup("fmSetRouterAttribute", err);

	MAT_LOG(DEBUG, "set default router mac to 0x%012llx\n", router_mac);

	err = fmSetRouterState(sw, 0, FM_ROUTER_STATE_ADMIN_UP);
	if (err != FM_OK)
		return cleanup("fmSetRouterState", err);

	MAT_LOG(DEBUG, "bring up the default router\n");

	return err;
}

int switch_configure_tunnel_engine(int te, __u64 smac, __u64 dmac, __u16 l4dst, __u16 parser_vxlan_port,
				   __u16 l4dst_nsh, __u16 parser_nsh_port)
{
	fm_status                err = FM_OK;
	//fm_switch               *switchPtr;
	fm_fm10000TeGlortCfg     teGlortCfg;
	fm_fm10000TeChecksumCfg  teChecksumCfg;
	fm_uint32                checksumCfgFieldSelectMask;
	fm_fm10000TeTunnelCfg    tunnelCfg;
	fm_uint32                tunnelCfgFieldSelectMask;
	fm_fm10000TeParserCfg    parserCfg;
	fm_uint32                parserCfgFieldSelectMask;

#ifdef DEBUG
	MAT_LOG(DEBUG, "configuring tunnel engine %d: smac 0x%012llx, dmac 0x%012llx, l4dst %d, parser_vxlan_port %d\n",
		te, smac, dmac, l4dst, parser_vxlan_port);
#endif /* DEBUG */

	//switchPtr = GET_SWITCH_PTR(sw);

	teGlortCfg.encapDglort = 0;
	teGlortCfg.decapDglort = 0;
	err = fm10000SetTeDefaultGlort(sw,
				       te,
				       &teGlortCfg,
				       FM10000_TE_DEFAULT_GLORT_ENCAP_DGLORT |
				       FM10000_TE_DEFAULT_GLORT_DECAP_DGLORT,
				       TRUE);
	if (err != FM_OK)
		return cleanup("fm10000SetTeChecksum", err);

	checksumCfgFieldSelectMask = 0;

	teChecksumCfg.notIp = FM_FM10000_TE_CHECKSUM_COMPUTE;
	checksumCfgFieldSelectMask |= FM10000_TE_CHECKSUM_NOT_IP;

	teChecksumCfg.notTcpOrUdp = FM_FM10000_TE_CHECKSUM_COMPUTE;
	checksumCfgFieldSelectMask |= FM10000_TE_CHECKSUM_NOT_TCP_OR_UDP;

	teChecksumCfg.tcpOrUdp = FM_FM10000_TE_CHECKSUM_COMPUTE;
	checksumCfgFieldSelectMask |= FM10000_TE_CHECKSUM_TCP_OR_UDP;

	err = fm10000SetTeChecksum(sw,
				   te,
				   &teChecksumCfg,
				   checksumCfgFieldSelectMask,
				   TRUE);
	if (err != FM_OK)
		return cleanup("fm10000SetTeChecksum", err);

	tunnelCfgFieldSelectMask = 0;

	tunnelCfg.l4DstVxLan = l4dst /*FM10000_FLOW_VXLAN_PORT*/;
	tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_L4DST_VXLAN;

	tunnelCfg.l4DstNge = l4dst_nsh /*FM10000_FLOW_NGE_PORT*/;
	tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_L4DST_NGE;

	tunnelCfg.dmac = dmac /*switchPtr->physicalRouterMac*/;
	tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_DMAC;

	tunnelCfg.smac = smac /*switchPtr->physicalRouterMac*/;
	tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_SMAC;

	//tunnelCfg.ngeTime = FALSE;
	//tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_NGE_TIME;

	tunnelCfg.encapProtocol = MATCH_VXLAN_GPE_NSH_PROTO;
	tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_PROTOCOL;

	//tunnelCfg.encapVersion = FM10000_FLOW_NVGRE_VERSION;
	//tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_VERSION;

	err = fm10000SetTeDefaultTunnel(sw,
					te,
					&tunnelCfg,
					tunnelCfgFieldSelectMask,
					TRUE);
	if (err != FM_OK)
		return cleanup("fm10000SetTeDefaultTunnel", err);

	parserCfgFieldSelectMask = 0;

	parserCfg.checkProtocol = FALSE;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_CHECK_PROTOCOL;

	parserCfg.checkVersion = FALSE;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_CHECK_VERSION;

	parserCfg.checkNgeOam = FALSE;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_CHECK_NGE_OAM;

	parserCfg.checkNgeC = FALSE;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_CHECK_NGE_C;

	parserCfg.vxLanPort = parser_vxlan_port /*FM10000_FLOW_VXLAN_PORT*/;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_VXLAN_PORT;

	parserCfg.ngePort = parser_nsh_port /*FM10000_FLOW_NGE_PORT*/;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_NGE_PORT;

	err = fm10000SetTeParser(sw,
				 te,
				 &parserCfg,
				 parserCfgFieldSelectMask,
				 TRUE);
	if (err != FM_OK)
		return cleanup("fm10000SetTeParser", err);

	return err;
}

int switch_tunnel_engine_set_default_nge_port(int te, __u16 port)
{
	fm_status                err;
	fm_fm10000TeTunnelCfg    tunnelCfg;
	fm_uint32                tunnelCfgFieldSelectMask;
	fm_fm10000TeParserCfg    parserCfg;
	fm_uint32                parserCfgFieldSelectMask;

	tunnelCfgFieldSelectMask = 0;

	tunnelCfg.l4DstNge = port;
	tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_L4DST_NGE;

	tunnelCfg.encapProtocol = MATCH_VXLAN_GPE_NSH_PROTO;
	tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_PROTOCOL;

	err = fm10000SetTeDefaultTunnel(sw, te, &tunnelCfg,
					tunnelCfgFieldSelectMask, TRUE);
	if (err != FM_OK)
		return cleanup("fm10000SetTeDefaultTunnel", err);

	parserCfgFieldSelectMask = 0;

	parserCfg.checkProtocol = FALSE;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_CHECK_PROTOCOL;

	parserCfg.checkVersion = FALSE;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_CHECK_VERSION;

	parserCfg.checkNgeOam = FALSE;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_CHECK_NGE_OAM;

	parserCfg.checkNgeC = FALSE;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_CHECK_NGE_C;

	parserCfg.ngePort = port;
	parserCfgFieldSelectMask |= FM10000_TE_PARSER_NGE_PORT;

	err = fm10000SetTeParser(sw, te, &parserCfg,
				 parserCfgFieldSelectMask, TRUE);
	if (err != FM_OK)
		return cleanup("fm10000SetTeParser", err);

	return err;
}

int switch_tunnel_engine_set_default_smac(int te, __u64 smac)
{
	fm_status                err = FM_OK;
	fm_fm10000TeTunnelCfg    tunnelCfg;
	fm_uint32                tunnelCfgFieldSelectMask;

#ifdef DEBUG
	MAT_LOG(DEBUG, "setting tunnel engine %d default smac 0x%012llx\n", te, smac);
#endif /* DEBUG */

	tunnelCfgFieldSelectMask = 0;

	tunnelCfg.smac = smac;
	tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_SMAC;

	err = fm10000SetTeDefaultTunnel(sw,
					te,
					&tunnelCfg,
					tunnelCfgFieldSelectMask,
					TRUE);
	if (err != FM_OK)
		return cleanup("fm10000SetTeDefaultTunnel", err);

	return err;
}

int switch_tunnel_engine_set_default_dmac(int te, __u64 dmac)
{
	fm_status                err = FM_OK;
	fm_fm10000TeTunnelCfg    tunnelCfg;
	fm_uint32                tunnelCfgFieldSelectMask;

#ifdef DEBUG
	MAT_LOG(DEBUG, "setting tunnel engine %d default dmac 0x%012llx\n", te, dmac);
#endif /* DEBUG */

	tunnelCfgFieldSelectMask = 0;

	tunnelCfg.dmac = dmac;
	tunnelCfgFieldSelectMask |= FM10000_TE_DEFAULT_TUNNEL_DMAC;

	err = fm10000SetTeDefaultTunnel(sw,
					te,
					&tunnelCfg,
					tunnelCfgFieldSelectMask,
					TRUE);
	if (err != FM_OK)
		return cleanup("fm10000SetTeDefaultTunnel", err);

	return err;
}

void switch_debug(int on)
{
	if (!on)
		return;

	fmDbgDumpArpTable(sw, FALSE);
	fmDbgDumpFFU(sw, TRUE, TRUE);
	fmDbgDumpStatChanges(sw, TRUE);
}

int switch_get_rule_counters(__u32 ruleid, __u32 switch_table_id,
			     __u64 *pkts, __u64 *octets)
{
	fm_status err = FM_OK;
	fm_flowCounters counters;

	err = fmGetFlowCount(sw, (int)switch_table_id, (int)ruleid, &counters);
	if (err != FM_OK)
		return cleanup("fmGetFlowCount", err);
#ifdef DEBUG
	else
		MAT_LOG(DEBUG, "%s: rule table %d ruleid %d pkts %lld octets %lld\n",
			__func__, switch_table_id, ruleid, counters.cntPkts, counters.cntOctets);
#endif /* DEBUG */

	if (pkts)
		*pkts = counters.cntPkts;
	if (octets)
		*octets = counters.cntOctets;

	return err;
}

int
switch_add_mac_entry(struct net_mat_field_ref *matches,
		     struct net_mat_action *actions)
{
	fm_macAddressEntry macEntry;
	fm_status err;
	uint64_t mac_address = 0;
	uint16_t vlan_id = FM_DEFAULT_VLAN;
	bool mac_found = false;
	bool lport_found = false;
	bool vsi_found = false;
	struct net_mat_port port;
	int lport = -1;
	__u32 group;
	int i;
	unsigned int glort = 0;

	for (i = 0; matches && matches[i].instance; i++) {
		switch (matches[i].instance) {
		case HEADER_INSTANCE_ETHERNET:
			mac_address = matches[i].v.u64.value_u64;
			mac_found = true;
			break;
		case HEADER_INSTANCE_VLAN_OUTER:
			if (matches[i].field != HEADER_VLAN_VID)
				return -EINVAL;
			vlan_id = matches[i].v.u16.value_u16;
			break;
		default:
			MAT_LOG(ERR, "Error: unknown match instance %d\n",
				matches[i].instance);
			return -EINVAL;
		}
	}

	for (i = 0; actions && actions[i].uid; i++) {
		switch (actions[i].uid) {
		case ACTION_FORWARD_VSI:
			memset(&port, 0, sizeof(port));
			port.pci.bus = actions[i].args[0].v.value_u8;
			port.pci.device = actions[i].args[1].v.value_u8;
			port.pci.function = actions[i].args[2].v.value_u8;
			vsi_found = true;
			break;
		case ACTION_SET_EGRESS_PORT:
			lport = (int)actions[i].args[0].v.value_u32;
			lport_found = true;
			break;
		case ACTION_FORWARD_TO_L2MPATH:
			group = actions[i].args[0].v.value_u32;
			if (group >= TABLE_L2_MP_SIZE)
				return -EINVAL;

			/* Get the logical port associated with LBG.*/
			err = fmGetLBGAttribute(sw, l2mp_group[group],
						FM_LBG_LOGICAL_PORT, &lport);
			if (err != FM_OK)
				return cleanup("fmGetLBGAttribute", err);

			if (lport < 0)
				return -EINVAL;
			lport_found = true;
			break;
		default:
			MAT_LOG(ERR, "Error: unknown action id\n");
			return -EINVAL;
		}
	}

	if (!mac_found) {
		MAT_LOG(ERR, "Error: mac address is required\n");
		return -EINVAL;
	}

	if (vsi_found && lport_found) {
		MAT_LOG(ERR, "Error: FORWARD_VSI and SET_EGRESS_PORT actions are mutually exclusive\n");
		return -EINVAL;
	}

	if (!(vsi_found || lport_found)) {
		MAT_LOG(ERR, "Error: no action specified\n");
		return -EINVAL;
	}

	if (vsi_found) {
		err = ies_port_get_lport(&port, (unsigned int *)&lport, &glort);
		if (err) {
			MAT_LOG(ERR, "Error: pci to log port\n");
			return -EINVAL;
		}
	}

	memset(&macEntry, 0, sizeof(fm_macAddressEntry));

	macEntry.type = FM_ADDRESS_STATIC;
	macEntry.vlanID = vlan_id;
	macEntry.macAddress = mac_address;
	macEntry.destMask = FM_DESTMASK_UNUSED;
	macEntry.port = lport;

#ifdef DEBUG
	MAT_LOG(DEBUG, "adding mac address 0x%012lx to port %d in vlan %d\n",
		mac_address, lport, vlan_id);
#endif

	err = fmAddAddress(sw, &macEntry);
	if (err != FM_OK)
		return cleanup("fmAddAddress", err);

	return 0;
}

int switch_del_mac_entry(int vlan, __u64 mac)
{
	fm_status err;
	fm_macAddressEntry macEntry;

#ifdef DEBUG
	int i;

	fm_macAddressEntry *entries, *p;
	fm_int nEntries;

	MAT_LOG(DEBUG, "reading mac table before ...\n");

	entries = malloc(sizeof(fm_macAddressEntry) * FM_MAX_ADDR);
	if (entries == NULL) {
		MAT_LOG(ERR, "err allocating space for mac table.\n");
		return -ENOMEM;
	}
	err = fmGetAddressTable(sw, &nEntries, entries);
	if (err != FM_OK) {
		free(entries);
		return cleanup("fmAddAddress", err);
	}

	p = entries;
	for (i = 0; i < nEntries; i++) {
		MAT_LOG(DEBUG, "mac entry %d: address 0x%012llx, port %d, vlan %d\n",
			i, p->macAddress, p->port, p->vlanID);
		p++;
	}
#endif /* DEBUG */

	memset(&macEntry, 0, sizeof(fm_macAddressEntry));

	macEntry.type = FM_ADDRESS_STATIC;
	macEntry.vlanID = (fm_uint16)vlan;
	macEntry.macAddress = mac;
	macEntry.destMask = FM_DESTMASK_UNUSED;
#ifdef DEBUG
	MAT_LOG(DEBUG, "deleting mac entry vlan %d address 0x%012llx \n", vlan, mac);
#endif /* DEBUG */
	err = fmDeleteAddress(sw, &macEntry);
	if (err != FM_OK)
		return cleanup("fmAddAddress", err);

#ifdef DEBUG
	MAT_LOG(DEBUG, "reading mac table after ...\n");

	err = fmGetAddressTable(sw, &nEntries, entries);
	if (err != FM_OK)
		return cleanup("fmAddAddress", err);

	p = entries;
	for (i = 0; i < nEntries; i++) {
		MAT_LOG(DEBUG, "mac entry %d: address 0x%012llx, port %d, vlan %d\n",
			i, p->macAddress, p->port, p->vlanID);
		p++;
	}

	free(entries);
#endif /* DEBUG */

	return 0;
}

int switch_create_TCAM_table(__u32 table_id, struct net_mat_field_ref *matches, __u32 *actions, __u32 size, int max_actions)
{
	fm_status err = 0;
	fm_flowCondition condition = 0;
	fm_bool has_priority = FM_DISABLED;
	fm_bool has_count = FM_DISABLED;
	int i;
	for (i = 0; matches && matches[i].instance; i++) {
		switch (matches[i].instance) {
		case HEADER_INSTANCE_ETHERNET:
			switch (matches[i].field) {
			case HEADER_ETHERNET_SRC_MAC:
				condition |= FM_FLOW_MATCH_SRC_MAC;
				break;
			case HEADER_ETHERNET_DST_MAC:
				condition |= FM_FLOW_MATCH_DST_MAC;
				break;
			case HEADER_ETHERNET_ETHERTYPE:
				condition |= FM_FLOW_MATCH_ETHERTYPE;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_ETHERNET, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_VLAN_OUTER:
			switch (matches[i].field) {
			case HEADER_VLAN_VID:
				condition |= FM_FLOW_MATCH_VLAN;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_VLAN, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_IPV4:
			switch (matches[i].field) {
			case HEADER_IPV4_SRC_IP:
				condition |= FM_FLOW_MATCH_SRC_IP;
				break;
			case HEADER_IPV4_DST_IP:
				condition |= FM_FLOW_MATCH_DST_IP;
				break;
			case HEADER_IPV4_PROTOCOL:
				condition |= FM_FLOW_MATCH_PROTOCOL;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_IPV4, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_TCP:
			switch (matches[i].field) {
			case HEADER_TCP_SRC_PORT:
				condition |= FM_FLOW_MATCH_L4_SRC_PORT;
				condition |= FM_FLOW_MATCH_PROTOCOL;
				break;
			case HEADER_TCP_DST_PORT:
				condition |= FM_FLOW_MATCH_L4_DST_PORT;
				condition |= FM_FLOW_MATCH_PROTOCOL;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_TCP, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_UDP:
			switch (matches[i].field) {
			case HEADER_UDP_SRC_PORT:
				condition |= FM_FLOW_MATCH_L4_SRC_PORT;
				condition |= FM_FLOW_MATCH_PROTOCOL;
				break;
			case HEADER_UDP_DST_PORT:
				condition |= FM_FLOW_MATCH_L4_DST_PORT;
				condition |= FM_FLOW_MATCH_PROTOCOL;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_UDP, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_INGRESS_PORT_METADATA:
			switch (matches[i].field) {
			case HEADER_METADATA_INGRESS_PORT:
				condition |= FM_FLOW_MATCH_SRC_PORT;
				break;
			case HEADER_METADATA_INGRESS_LPORT:
#ifdef FM_FLOW_MATCH_LOGICAL_PORT
				condition |= FM_FLOW_MATCH_LOGICAL_PORT;
#else
				MAT_LOG(ERR, "Please update your IES software to match on logical port\n");
				err = -EINVAL;
#endif
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_METADATA, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_VXLAN:
			switch (matches[i].field) {
			case HEADER_VXLAN_VNI:
				if (configure_deep_inspection()) {
					MAT_LOG(ERR, "deep inspection\n");
					err = -EINVAL;
					break;
				}
				condition |= FM_FLOW_MATCH_L4_DEEP_INSPECTION;
				break;
			default:
				MAT_LOG(ERR, "match error in HEADER_VXLAN, field=%d\n", matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_NSH:
			switch (matches[i].field) {
			case HEADER_NSH_SERVICE_PATH_ID:
			case HEADER_NSH_SERVICE_INDEX:
				if (configure_deep_inspection_nsh()) {
					MAT_LOG(ERR, "deep inspection nsh\n");
					err = -EINVAL;
					break;
				}
				condition |= FM_FLOW_MATCH_L4_DEEP_INSPECTION;
				break;
			default:
				MAT_LOG(ERR, "match error in HEADER_NSH, field=%d\n", matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		default:
			MAT_LOG(ERR, "%s: match error in INSTANCE, instance=%d\n", __func__, matches[i].field);
			err = -EINVAL;
			break;
		}
	}

	if (err == -EINVAL)
		return err;

	/* condition = FM_FLOW_TABLE_COND_ALL_12_TUPLE; */

	for (i = 0; actions && actions[i]; i++) {
		MAT_LOG(DEBUG, "actions[%d] = %d\n", i, actions[i]);
		switch (actions[i]) {
		case ACTION_COUNT:
			has_count = FM_ENABLED;
			break;
		}
	}

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: set TCAM table %d to be with count %d\n", __func__, table_id, has_count);
#endif /* DEBUG */
	err = fmSetFlowAttribute(sw, (fm_int)table_id, FM_FLOW_TABLE_WITH_COUNT, &has_count);
	if (err != FM_OK)
		return cleanup("fmSetFlowAttribute", err);

	has_priority = FM_ENABLED; /* fix me */
#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: set TCAM table %d to be with priority %d\n", __func__, table_id, has_priority);
#endif /* DEBUG */
	err = fmSetFlowAttribute(sw, (fm_int)table_id, FM_FLOW_TABLE_WITH_PRIORITY, &has_priority);
	if (err != FM_OK)
		return cleanup("fmSetFlowAttribute", err);

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: creating rule TCAM table: table %d, condition 0x%llx, maxEntries %d, maxActions %d\n",
		__func__, table_id, condition, size, max_actions);
#endif /* DEBUG */
	err = fmCreateFlowTCAMTable(sw, (fm_int)table_id, condition, size, (fm_uint32)max_actions);
	if (err != FM_OK)
		return cleanup("fmCreateFlowTCAMTable", err);

	return 0;
}

int switch_del_TCAM_table(__u32 table_id)
{
	fm_status err = 0;

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: deleting rule TCAM table %d\n", __func__, table_id);
#endif /* DEBUG */
	err = fmDeleteFlowTCAMTable(sw, (int)table_id);
	if (err != FM_OK)
		return cleanup("fmDeleteFlowTCAMTable", err);

	return 0;
}

int switch_add_nh_entry(struct net_mat_field_ref *matches, struct net_mat_action *actions)
{
	fm_status err = 0;
	__u32 ecmp_group_id = 0;
	__u64 new_dmac = 0;
	__u16 new_vlan = 0;
	fm_int hw_group_id = -1;
	fm_nextHop nh;
	fm_arpEntry arp;

	if (!matches ||
	    (matches[0].instance != HEADER_INSTANCE_ROUTING_METADATA) ||
	    (matches[0].field != HEADER_METADATA_ECMP_GROUP_ID) ||
	    (matches[1].instance)) {
		MAT_LOG(ERR, "%s: error in matches\n", __func__);
		return -EINVAL;
	}

	ecmp_group_id = matches[0].v.u32.value_u32;
#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: match EDMP_GROUP_ID: %d\n", __func__, ecmp_group_id);
#endif /* DEBUG */
	if (ecmp_group_id >= TABLE_NEXTHOP_SIZE) {
		MAT_LOG(ERR, "%s: invalid ecmp group id %d\n", __func__, ecmp_group_id);
		return -EINVAL;
	}

	if (!actions ||
	    (actions[0].uid != ACTION_ROUTE) ||
	    (actions[1].uid)) {
		MAT_LOG(ERR, "%s: error in actions\n", __func__);
		return -EINVAL;
	}

	new_dmac = actions[0].args[0].v.value_u64;
	new_vlan = actions[0].args[1].v.value_u16;
	if (new_vlan >= 4096) {
		MAT_LOG(ERR, "%s: invalid newVLAN %d\n", __func__, new_vlan);
		return -EINVAL;
	}
#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: action ROUTE(0x%012llx:%u)\n", __func__, new_dmac, new_vlan);
#endif /* DEBUG */

	if (ecmp_group[ecmp_group_id].hw_group_id == -1) {
#ifdef DEBUG
		MAT_LOG(DEBUG, "%s: creating ecmp group %d\n", __func__, ecmp_group_id);
#endif /* DEBUG */
		err = fmCreateECMPGroupV2(sw, &hw_group_id, NULL);
		if (err != FM_OK) {
			return cleanup("fmDeleteFlowTCAMTable", err);
		} else {
			ecmp_group[ecmp_group_id].hw_group_id = hw_group_id;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: created ecmp group %d, hw_group_id %d\n",
				__func__, ecmp_group_id, hw_group_id);
#endif /* DEBUG */
		}
	}

	ecmp_group[ecmp_group_id].num_nhs++;

	memset(&arp, 0, sizeof(arp));
	arp.ipAddr.addr[0] = dummy_nh_ipaddr + (__u32)ecmp_group[ecmp_group_id].num_nhs +
			((__u32)ecmp_group[ecmp_group_id].hw_group_id << 8);
	arp.ipAddr.isIPv6 = FALSE;
	arp.interface = -1; /* my_iface[new_vlan]; */
	arp.vlan = new_vlan;
	arp.macAddr = new_dmac;
#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: adding arp entry (0x%08x:0x%012llx:%u)\n",
		__func__, arp.ipAddr.addr[0], new_dmac, new_vlan);
#endif /* DEBUG */
	err = fmAddARPEntry(sw, &arp);
	if (err != FM_OK) {
		return cleanup("fmAddARPEntry", err);
		ecmp_group[ecmp_group_id].num_nhs--;
		return err;
	}

	memset(&nh, 0, sizeof(nh));
	nh.addr = arp.ipAddr;
	/* nh.interfaceAddr = dummy_iface_addr; */
	nh.vlan = new_vlan;
	nh.trapCode = FM_TRAPCODE_L3_ROUTED_NO_ARP_0;

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: adding nh entry (0x%08x:%u) to group %u\n",
		__func__, nh.addr.addr[0], nh.vlan, ecmp_group_id);
#endif /* DEBUG */
	err = fmAddECMPGroupNextHops(sw, ecmp_group[ecmp_group_id].hw_group_id, 1, &nh);
	if (err != FM_OK) {
		return cleanup("fmAddECMPGroupNextHops", err);
		ecmp_group[ecmp_group_id].num_nhs--;
	}

	return err;
}

static fm_status switch_search_arp_entry(__u16 vlan, __u64 dmac, fm_arpEntry *parp)
{
	fm_status err = 0;
	fm_voidptr ptr;

	err = fmGetARPEntryFirst(sw, &ptr, parp);
	if (err != FM_OK) {
#ifdef DEBUG
		MAT_LOG(DEBUG, "%s: fmGetARPEntryFirst() returns %d\n", __func__, err);
#endif /* DEBUG */
		return err;
	}

	if ((parp->macAddr == dmac) && (parp->vlan == vlan)) {
#ifdef DEBUG
		MAT_LOG(DEBUG, "%s: fmGetARPEntryFirst() found arp entry (0x%08x:0x%012llx:%u)\n",
			__func__, parp->ipAddr.addr[0], dmac, vlan);
#endif /* DEBUG */
		return err;
	}

	while (((err = fmGetARPEntryNext(sw, &ptr, parp)) == FM_OK) &&
	       ((parp->macAddr != dmac) || (parp->vlan != vlan)));

#ifdef DEBUG
	if (err == FM_OK)
		MAT_LOG(DEBUG, "%s: fmGetARPEntryNext() found arp entry (0x%08x:0x%012llx:%u)\n",
			__func__, parp->ipAddr.addr[0], dmac, vlan);
	else
		MAT_LOG(DEBUG, "%s: fmGetARPEntryNext() returns %d\n", __func__, err);
#endif /* DEBUG */

	return err;
}

int switch_del_nh_entry(struct net_mat_field_ref *matches, struct net_mat_action *actions)
{
	fm_status err = 0;
	__u32 ecmp_group_id = 0;
	__u64 new_dmac = 0;
	__u16 new_vlan = 0;
	fm_int hw_group_id = -1;
	fm_nextHop nh;
	fm_arpEntry arp;

	ecmp_group_id = matches[0].v.u32.value_u32;
	if (ecmp_group_id >= TABLE_NEXTHOP_SIZE) {
		MAT_LOG(ERR, "%s: invalid ecmp group id %d\n", __func__, ecmp_group_id);
		return -EINVAL;
	}
#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: match EDMP_GROUP_ID: %d\n", __func__, ecmp_group_id);
#endif /* DEBUG */
	hw_group_id = ecmp_group[ecmp_group_id].hw_group_id;

	new_dmac = actions[0].args[0].v.value_u64;
	new_vlan = actions[0].args[1].v.value_u16;
#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: action ROUTE(0x%012llx:%u)\n", __func__, new_dmac, new_vlan);
#endif /* DEBUG */

	err = switch_search_arp_entry(new_vlan, new_dmac, &arp);
	if (err != FM_OK) {
		MAT_LOG(ERR, "%s: unable to find arp entry(dmac = 0x%12llx, vlan = %u)\n",
			__func__, new_dmac, new_vlan);
		return -ENOENT;
	}

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: deleting arp entry (0x%08x:0x%012llx:%u)\n",
		__func__, arp.ipAddr.addr[0], new_dmac, new_vlan);
#endif /* DEBUG */
	err = fmDeleteARPEntry(sw, &arp);
	if (err != FM_OK) {
		return cleanup("fmDeleteARPEntry", err);
		return err;
	}

	memset(&nh, 0, sizeof(nh));
	nh.addr = arp.ipAddr;
	memset(&nh.interfaceAddr, 0, sizeof(nh.interfaceAddr));
	/* nh.interfaceAddr = dummy_iface_addr; */
	nh.vlan = new_vlan;
	nh.trapCode = FM_TRAPCODE_L3_ROUTED_NO_ARP_0;

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: deleting nh entry (0x%08x:%u) from group %u\n",
		__func__, nh.addr.addr[0], nh.vlan, ecmp_group_id);
#endif /* DEBUG */
	err = fmDeleteECMPGroupNextHops(sw, hw_group_id, 1, &nh);
	if (err != FM_OK)
		return cleanup("fmDeleteECMPGroupNextHops", err);

	ecmp_group[ecmp_group_id].num_nhs--;
#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: ecmp group %u has %d entries\n", __func__, ecmp_group_id, ecmp_group[ecmp_group_id].num_nhs);
#endif /* DEBUG */

#if 0
	if (ecmp_group[ecmp_group_id].num_nhs == 0) {
#ifdef DEBUG
		MAT_LOG(DEBUG, "%s: deleting ecmp group %u\n", __func__, ecmp_group_id);
#endif /* DEBUG */
		err = fmDeleteECMPGroup(sw, hw_group_id);
		if (err != FM_OK)
			return cleanup("fmDeleteECMPGroup", err);

		ecmp_group[ecmp_group_id].hw_group_id = -1;
	}
#endif /* 0 */

	return err;
}

#ifdef VXLAN_MCAST
static int switch_construct_mcast_group(fm_int *mcast_lport,
					fm_int *mcast_group,
					int num_mcast_listeners,
					__unused struct my_mcast_listener *mcast_listeners)
{
	int i;
	fm_status err = 0;
	fm_bool l3switch_only = FM_ENABLED;
	fm_mcastGroupListener *listeners;
	size_t listeners_size;

	listeners_size = sizeof(fm_mcastGroupListener) * (__u32)num_mcast_listeners;
	listeners = malloc(listeners_size);
	if (listeners == NULL) {
		MAT_LOG(ERR, "%s: unable to allocate listener list\n", __func__);
		return -ENOMEM;
	}
	bzero(listeners, listeners_size);

	err = fmCreateMcastGroup(sw, mcast_group);
	if (err != FM_OK) {
		cleanup("fmCreateMcastGroup", err);

		goto done;
	}

	err = fmSetMcastGroupAttribute(sw, *mcast_group, FM_MCASTGROUP_L3_SWITCHING_ONLY, &l3switch_only);
	if (err != FM_OK) {
		cleanup("fmSetMcastGroupAttribute", err);

		err = fmDeleteMcastGroup(sw, *mcast_group);
		if (err != FM_OK) {
			cleanup("fmDeleteMcastGroup", err);
			goto done;
		}

		goto done;
	}

	err = fmActivateMcastGroup(sw, *mcast_group);
	if (err != FM_OK) {
		cleanup("fmActivateMcastGroup", err);

		err = fmDeleteMcastGroup(sw, *mcast_group);
		if (err != FM_OK) {
			cleanup("fmDeleteMcastGroup", err);
			goto done;
		}

		goto done;
	}

	err = fmGetMcastGroupPort(sw, *mcast_group, mcast_lport);
	if (err != FM_OK) {
		cleanup("fmGetMcastGroupPort", err);

		err = fmDeactivateMcastGroup(sw, *mcast_group);
		if (err != FM_OK) {
			cleanup("fmDeactivateMcastGroup", err);
			goto done;
		}

		err = fmDeleteMcastGroup(sw, *mcast_group);
		if (err != FM_OK) {
			cleanup("fmDeleteMcastGroup", err);
			goto done;
		}

		goto done;
	}

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: create and activate mcast group %d lport %d\n", __func__, *mcast_group, *mcast_lport);
#endif /* DEBUG */

	for (i = 0; i < num_mcast_listeners; i++) {
		switch (mcast_listeners[i].t) {
		case FLOW_MCAST_LISTENER_PORT_VLAN:
			listeners[i].listenerType = FM_MCAST_GROUP_LISTENER_PORT_VLAN;
			listeners[i].info.portVlanListener.vlan = (fm_uint16)mcast_listeners[i].l.p.vlan;
			listeners[i].info.portVlanListener.port = mcast_listeners[i].l.p.port;
			break;
		case FLOW_MCAST_LISTENER_FLOW_TUNNEL:
			listeners[i].listenerType = FM_MCAST_GROUP_LISTENER_FLOW_TUNNEL;
			listeners[i].info.flowListener.tableIndex = mcast_listeners[i].l.f.table;
			listeners[i].info.flowListener.flowId = mcast_listeners[i].l.f.flow;
			break;
		default:
			err = -EINVAL;
			MAT_LOG(ERR, "%s: unknown listener type %d\n", __func__, listeners[i].listenerType);
			goto done;
		}

	}

	err = fmAddMcastGroupListenerListV2(sw, *mcast_group, num_mcast_listeners, listeners);
	if (err != FM_OK) {
		cleanup("fmCreateMcastGroup", err);

		err = fmDeactivateMcastGroup(sw, *mcast_group);
		if (err != FM_OK) {
			cleanup("fmDeactivateMcastGroup", err);
			goto done;
		}

		err = fmDeleteMcastGroup(sw, *mcast_group);
		if (err != FM_OK) {
			cleanup("fmDeleteMcastGroup", err);
			goto done;
		}

		goto done;
	}

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: add %d listeners to  mcast group %d\n", __func__, num_mcast_listeners, *mcast_group);
#endif /* DEBUG */

done:
	free(listeners);

	return err;
}
#endif /* VXLAN_MCAST */

static int
set_vni_cond(__u32 vni, __u32 mask,
	     fm_flowCondition *cond, fm_flowValue *condVal)
{
	static const int vni_bits = 24;
	static const int vni_offset = 4;
	fm_byte *di_val;
	fm_byte *di_mask;

	if (!cond || !condVal)
		return -EINVAL;

	/* VNI can only be 24 bits long */
	if ((vni > (1U << vni_bits) - 1) || (mask > (1U << vni_bits) - 1))
		return -ERANGE;

	di_val = condVal->L4DeepInspection;
	di_mask = condVal->L4DeepInspectionMask;

	/* VNI appears 4 bytes into the VXLAN header */
	di_val[vni_offset + 0] = ((__u8 *)&vni)[2];
	di_val[vni_offset + 1] = ((__u8 *)&vni)[1];
	di_val[vni_offset + 2] = ((__u8 *)&vni)[0];

	di_mask[vni_offset + 0] = ((__u8 *)&mask)[2];
	di_mask[vni_offset + 1] = ((__u8 *)&mask)[1];
	di_mask[vni_offset + 2] = ((__u8 *)&mask)[0];

	*cond |= FM_FLOW_MATCH_L4_DEEP_INSPECTION;

	return 0;
}

static int
set_nsh_spi_cond(__u32 spi, __u32 mask,
		 fm_flowCondition *cond, fm_flowValue *condVal)
{
	static const int spi_bits = 24;
	static const int spi_offset = 12;
	fm_byte *di_val;
	fm_byte *di_mask;

	if (!cond || !condVal)
		return -EINVAL;

	/* Service Path ID can only be 24 bits long */
	if ((spi > (1U << spi_bits) - 1) || (mask > (1U << spi_bits) - 1))
		return -ERANGE;

	di_val = condVal->L4DeepInspection;
	di_mask = condVal->L4DeepInspectionMask;

	/* SPI appears 4 bytes into the NSH header, after VXLAN-GPE */
	di_val[spi_offset + 0] = ((__u8 *)&spi)[2];
	di_val[spi_offset + 1] = ((__u8 *)&spi)[1];
	di_val[spi_offset + 2] = ((__u8 *)&spi)[0];

	di_mask[spi_offset + 0] = ((__u8 *)&mask)[2];
	di_mask[spi_offset + 1] = ((__u8 *)&mask)[1];
	di_mask[spi_offset + 2] = ((__u8 *)&mask)[0];

	*cond |= FM_FLOW_MATCH_L4_DEEP_INSPECTION;

	return 0;
}

int switch_add_TCAM_rule_entry(__u32 *flowid, __u32 table_id, __u32 priority, struct net_mat_field_ref *matches, struct net_mat_action *actions)
{
	int i;
	fm_status err = 0;
	fm_flowCondition cond = 0;
	fm_flowValue condVal;
	fm_flowAction act = 0;
	fm_flowParam param;
	__u32 vni;
	__u32 vni_mask;
	__u32 spi;
	__u32 spi_mask;
	__u8 si;
	__u8 si_mask;
	/* nsh service index appears 15B following UDP header */
	const int si_off = 15;
	struct net_mat_port port;
	__u32 group_id;
#ifdef VXLAN_MCAST
	struct my_mcast_listener mcast_listeners[MAX_LISTENERS_PER_GROUP];
	int num_mcast_listeners = 0;
	fm_int mcast_lport;
	fm_int mcast_group = -1;
#endif /* VXLAN_MCAST */

	memset(&condVal, 0, sizeof(condVal));
	memset(&param, 0, sizeof(param));

	for (i = 0; matches && matches[i].instance; i++) {
		switch (matches[i].instance) {
		case HEADER_INSTANCE_ETHERNET:
			switch (matches[i].field) {
			case HEADER_ETHERNET_SRC_MAC:
				cond |= FM_FLOW_MATCH_SRC_MAC;
				condVal.src = matches[i].v.u64.value_u64;
				condVal.srcMask = matches[i].v.u64.mask_u64;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match SRC_MAC(0x%016llx:0x%016llx)\n", __func__, condVal.src, condVal.srcMask);
#endif /* DEBUG */
				break;
			case HEADER_ETHERNET_DST_MAC:
				cond |= FM_FLOW_MATCH_DST_MAC;
				condVal.dst = matches[i].v.u64.value_u64;
				condVal.dstMask = matches[i].v.u64.mask_u64;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match DST_MAC(0x%016llx:0x%016llx)\n", __func__, condVal.dst, condVal.dstMask);
#endif /* DEBUG */
				break;
			case HEADER_ETHERNET_ETHERTYPE:
				cond |= FM_FLOW_MATCH_ETHERTYPE;
				condVal.ethType = matches[i].v.u16.value_u16;
				condVal.ethTypeMask = matches[i].v.u16.mask_u16;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match ETHERTYPE(0x%04x:0x%04x)\n", __func__, condVal.ethType, condVal.ethTypeMask);
#endif /* DEBUG */
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_INSTANCE_ETHERNET, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_VLAN_OUTER:
			switch (matches[i].field) {
			case HEADER_VLAN_VID:
				cond |= FM_FLOW_MATCH_VLAN;
				condVal.vlanId = matches[i].v.u16.value_u16;
				condVal.vlanIdMask = matches[i].v.u16.mask_u16;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match VLAN(0x%04x:0x%04x)\n", __func__, condVal.vlanId, condVal.vlanIdMask);
#endif /* DEBUG */
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_INSTANCE_VLAN_OUTER, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_IPV4:
			switch (matches[i].field) {
			case HEADER_IPV4_SRC_IP:
				cond |= FM_FLOW_MATCH_SRC_IP;
				condVal.srcIp.addr[0] = matches[i].v.u32.value_u32;
				condVal.srcIp.isIPv6 = FALSE;
				condVal.srcIpMask.addr[0] = matches[i].v.u32.mask_u32;
				condVal.srcIpMask.isIPv6 = FALSE;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match SRC_IP(0x%08x:0x%08x)\n", __func__, condVal.srcIp.addr[0], condVal.srcIpMask.addr[0]);
#endif /* DEBUG */

				break;
			case HEADER_IPV4_DST_IP:
				cond |= FM_FLOW_MATCH_DST_IP;
				condVal.dstIp.addr[0] = matches[i].v.u32.value_u32;
				condVal.dstIp.isIPv6 = FALSE;
				condVal.dstIpMask.addr[0] = matches[i].v.u32.mask_u32;
				condVal.dstIpMask.isIPv6 = FALSE;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match DST_IP(0x%08x:0x%08x)\n", __func__, condVal.dstIp.addr[0], condVal.dstIpMask.addr[0]);
#endif /* DEBUG */

				break;
			case HEADER_IPV4_PROTOCOL:
				cond |= FM_FLOW_MATCH_PROTOCOL;
				condVal.protocol = (fm_byte)matches[i].v.u16.value_u16;
				condVal.protocolMask = (fm_byte)matches[i].v.u16.mask_u16;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match PROTOCOL(0x%08x:0x%08x)\n", __func__, condVal.protocol, condVal.protocolMask);
#endif /* DEBUG */
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_INSTANCE_IPV4, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_TCP:
		case HEADER_INSTANCE_UDP:
			/* Configure protocool as required by fmAPI */
			cond |= FM_FLOW_MATCH_PROTOCOL;
			condVal.protocolMask = 0xff;
			if (matches[i].instance == HEADER_INSTANCE_TCP)
				condVal.protocol = 0x06;
			else
				condVal.protocol = 0x11;

			switch (matches[i].field) {
			case HEADER_TCP_SRC_PORT:
				cond |= FM_FLOW_MATCH_L4_SRC_PORT;
				condVal.L4SrcStart = matches[i].v.u16.value_u16;
				condVal.L4SrcMask = matches[i].v.u16.mask_u16;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match L4_SRC_PORT(%d/0x%04x)\n", __func__,
					condVal.L4SrcStart, condVal.L4SrcMask);
#endif /* DEBUG */
				break;
			case HEADER_TCP_DST_PORT:
				cond |= FM_FLOW_MATCH_L4_DST_PORT;
				condVal.L4DstStart = matches[i].v.u16.value_u16;
				condVal.L4DstMask = matches[i].v.u16.mask_u16;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match L4_DST_PORT(%d/0x%04x)\n", __func__,
                                        condVal.L4DstStart, condVal.L4DstMask);
#endif /* DEBUG */
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_INSTANCE_TCP/UDP, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_INGRESS_PORT_METADATA:
			switch (matches[i].field) {
			case HEADER_METADATA_INGRESS_PORT:
				cond |= FM_FLOW_MATCH_SRC_PORT;
				condVal.logicalPort = (fm_int)matches[i].v.u32.value_u32;
				if (fmMapCardinalPort(sw, condVal.logicalPort,
				                      NULL, NULL) != FM_OK) {
					MAT_LOG(ERR, "Invalid ingress port (%d)\n",
					        condVal.logicalPort);
					err = -EINVAL;
				}
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match SRC_PORT(%d)\n", __func__, condVal.logicalPort);
#endif /* DEBUG */
				break;
			case HEADER_METADATA_INGRESS_LPORT:
#ifdef FM_FLOW_MATCH_LOGICAL_PORT
				cond |= FM_FLOW_MATCH_LOGICAL_PORT;
				condVal.logicalPort = (fm_int)matches[i].v.u32.value_u32;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match LOGICAL_PORT(%d)\n", __func__, condVal.logicalPort);
#endif /* DEBUG */
#else
				MAT_LOG(ERR, "Please update your IES software to match on logical port\n");
				err = -EINVAL;
#endif /* FM_FLOW_MATCH_LOGICAL_PORT */
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_INSTANCE_INGRESS_PORT_METADATA, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_VXLAN:
			switch (matches[i].field) {
			case HEADER_VXLAN_VNI:
				vni = matches[i].v.u32.value_u32;
				vni_mask = matches[i].v.u32.mask_u32;

				err = set_vni_cond(vni, vni_mask, &cond, &condVal);

#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match VNI/MASK (%u/0x%x)\n",
					__func__, vni, vni_mask);
#endif
				break;
			default:
				MAT_LOG(ERR, "match error in HEADER_INSTANCE_VXLAN, field=%d\n", matches[i].field);
				err = -EINVAL;
			}
			break;
		case HEADER_INSTANCE_NSH:
			switch (matches[i].field) {
			case HEADER_NSH_SERVICE_PATH_ID:
				spi = matches[i].v.u32.value_u32;
				spi_mask = matches[i].v.u32.mask_u32;

				err = set_nsh_spi_cond(spi, spi_mask, &cond, &condVal);

#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match service_path_id/MASK (%u/0x%x)\n",
					__func__, spi, spi_mask);
#endif
				break;
			case HEADER_NSH_SERVICE_INDEX:
				si = matches[i].v.u8.value_u8;
				si_mask = matches[i].v.u8.mask_u8;

				cond |= FM_FLOW_MATCH_L4_DEEP_INSPECTION;
				condVal.L4DeepInspection[si_off] = si;
				condVal.L4DeepInspectionMask[si_off] = si_mask;
#ifdef DEBUG
				MAT_LOG(ERR, "%s: match service_index/MASK (%u/0x%x)\n",
					__func__, si, si_mask);
#endif
				break;
			default:
				MAT_LOG(ERR, "match error in HEADER_INSTANCE_NSH, field=%d\n", matches[i].field);
				err = -EINVAL;
			}
			break;
		default:
			MAT_LOG(ERR, "%s: match error unsupported instance %d\n", __func__, matches[i].instance);
			err = -EINVAL;
			break;
		}
	}

	for (i = 0; actions && actions[i].uid; i++) {
		switch (actions[i].uid) {
		case ACTION_FORWARD_VSI:
			act |= FM_FLOW_ACTION_FORWARD;

			memset(&port, 0, sizeof(port));
			port.pci.bus = actions[i].args[0].v.value_u8;
			port.pci.device = actions[i].args[1].v.value_u8;
			port.pci.function = actions[i].args[2].v.value_u8;

			err = ies_port_get_lport(&port,
			                         (__u32 *)&param.logicalPort,
			                         NULL);
			if (err) {
				MAT_LOG(ERR, "Error: pci to log port\n");
				err = -EINVAL;
				break;
			}
#ifdef VXLAN_MCAST
			if (num_mcast_listeners >= MAX_LISTENERS_PER_GROUP) {
				MAT_LOG(ERR, "%s: too many destinations\n", __func__);
				err = -EINVAL;
				break;
			}

			mcast_listeners[num_mcast_listeners].t = FLOW_MCAST_LISTENER_PORT_VLAN;
			mcast_listeners[num_mcast_listeners].l.p.vlan = FM_DEFAULT_VLAN; // FIXME: need VLAN management
			mcast_listeners[num_mcast_listeners].l.p.port = param.logicalPort;

			num_mcast_listeners++;
#endif /* VXLAN_MCAST */
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action FORWARD_VSI(%d)\n", __func__, param.logicalPort);
#endif
			break;
		case ACTION_SET_EGRESS_PORT:
			act |= FM_FLOW_ACTION_FORWARD;
			param.logicalPort = (fm_int)actions[i].args[0].v.value_u32;
#ifdef VXLAN_MCAST
			if (num_mcast_listeners >= MAX_LISTENERS_PER_GROUP) {
				MAT_LOG(ERR, "%s: too many destinations\n", __func__);
				err = -EINVAL;
				break;
			}

			mcast_listeners[num_mcast_listeners].t = FLOW_MCAST_LISTENER_PORT_VLAN;
			mcast_listeners[num_mcast_listeners].l.p.vlan = FM_DEFAULT_VLAN; // FIXME: need VLAN management
			mcast_listeners[num_mcast_listeners].l.p.port = param.logicalPort;

			num_mcast_listeners++;
#endif /* VXLAN_MCAST */
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action FORWARD(%d)\n", __func__, param.logicalPort);
#endif /* DEBUG */
			break;
		case ACTION_SET_DST_MAC:
			act |= FM_FLOW_ACTION_SET_DMAC;
			param.dmac = actions[i].args[0].v.value_u64;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action SET_DMAC(0x%012llx)\n", __func__, param.dmac);
#endif /* DEBUG */
			break;
		case ACTION_SET_SRC_MAC:
			act |= FM_FLOW_ACTION_SET_SMAC;
			param.smac = actions[i].args[0].v.value_u64;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action SET_SMAC(0x%012llx)\n", __func__, param.smac);
#endif /* DEBUG */
			break;
		case ACTION_SET_VLAN:
			act |= FM_FLOW_ACTION_SET_VLAN;
			param.vlan = actions[i].args[0].v.value_u16;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action SET_VLAN(%d)\n", __func__, param.vlan);
#endif /* DEBUG */
			break;
		case ACTION_NORMAL:
			act |= FM_FLOW_ACTION_FORWARD_NORMAL;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action FORWARD_NORMAL\n", __func__);
#endif /* DEBUG */
			break;
		case ACTION_TRAP:
			act |= FM_FLOW_ACTION_TRAP;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action TRAP\n", __func__);
#endif /* DEBUG */
			break;
		case ACTION_DROP_PACKET:
			act |= FM_FLOW_ACTION_DROP;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action DROP\n", __func__);
#endif /* DEBUG */
			break;
		case ACTION_PERMIT:
			act |= FM_FLOW_ACTION_PERMIT;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action PERMIT\n", __func__);
#endif /* DEBUG */
			break;
		case ACTION_COUNT:
			act |= FM_FLOW_ACTION_COUNT;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action COUNT\n", __func__);
#endif /* DEBUG */
			break;
		case ACTION_ROUTE_VIA_ECMP:
			act |= FM_FLOW_ACTION_ROUTE;
			group_id = actions[i].args[0].v.value_u32;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action ROUTE(%d)\n", __func__, group_id);
#endif /* DEBUG */
			if (group_id >= TABLE_NEXTHOP_SIZE) {
				MAT_LOG(ERR, "%s: action route_via_ecmp ecmp group id %d out of range\n",
					__func__, group_id);
				err = -EINVAL;
			} else if (ecmp_group[group_id].hw_group_id == -1) {
				MAT_LOG(ERR, "%s: no nexthop entry for ecmp group %d\n",
					__func__, group_id);
				err = -EINVAL;
			} else {
				param.ecmpGroup = ecmp_group[group_id].hw_group_id;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: action ROUTE(%d) hw_group_id %d\n",
					__func__, group_id, param.ecmpGroup);
#endif /* DEBUG */
			}

			break;
		case ACTION_FORWARD_TO_TE_A:
		case ACTION_FORWARD_TO_TE_B:
			act |= FM_FLOW_ACTION_REDIRECT_TUNNEL;
			param.tableIndex = (fm_int)actions[i].args[0].v.value_u16 - TABLE_DYN_START + 1;
			param.flowId = 0;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action FORWARD_TO_TE(%d)\n", __func__, param.tableIndex);
#endif /* DEBUG */
			break;
		case ACTION_FORWARD_DIRECT_TO_TE_A:
		case ACTION_FORWARD_DIRECT_TO_TE_B:
			act |= FM_FLOW_ACTION_REDIRECT_TUNNEL;
			param.tableIndex = (fm_int)actions[i].args[0].v.value_u16 - TABLE_DYN_START + 1;
			param.flowId = (fm_int)actions[i].args[1].v.value_u16;
#ifdef VXLAN_MCAST
			if (num_mcast_listeners >= MAX_LISTENERS_PER_GROUP) {
				MAT_LOG(ERR, "%s: too many destinations\n", __func__);
				err = -EINVAL;
				break;
			}

			mcast_listeners[num_mcast_listeners].t = FLOW_MCAST_LISTENER_FLOW_TUNNEL;
			mcast_listeners[num_mcast_listeners].l.f.table = param.tableIndex;
			mcast_listeners[num_mcast_listeners].l.f.flow = param.flowId;

			num_mcast_listeners++;
#endif /* VXLAN_MCAST */
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action FORWARD_DIRECT_TO_TE(%d, %d)\n", __func__, param.tableIndex, param.flowId);
#endif /* DEBUG */
			break;
		default:
			MAT_LOG(ERR, "%s: unsupported action %d\n", __func__, actions[i].uid);
			err = -EINVAL;
			break;
		}
	}

	if (err < 0)
		return err;

#ifdef VXLAN_MCAST
	if (num_mcast_listeners > 1) {
		err = switch_construct_mcast_group(&mcast_lport, &mcast_group, num_mcast_listeners, mcast_listeners);
		if (err < 0) {
			MAT_LOG(ERR, "%s: error constructing multicast group %d\n", __func__, err);
			return err;
		}

		act &= ~FM_FLOW_ACTION_REDIRECT_TUNNEL;
		act |= FM_FLOW_ACTION_FORWARD;

		param.logicalPort = mcast_lport;
	}
#endif /* VXLAN_MCAST */
#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: add flow : table %d, cond 0x%llx, act 0x%llx\n",
		__func__, table_id, cond, act);
#endif /* DEBUG */
	err = fmAddFlow(sw, (fm_int)table_id, (fm_uint16)priority, 0,
			cond, &condVal, act, &param, FM_FLOW_STATE_ENABLED,
			(int *)flowid);
	if (err != FM_OK)
		return cleanup("fmAddFlow", err);
#ifdef DEBUG
	else
		MAT_LOG(DEBUG, "%s: flow flowid %d added to table %d\n", __func__, *flowid, table_id);
#endif /* DEBUG */

#ifdef VXLAN_MCAST
	if (num_mcast_listeners > 1 && mcast_group != -1)
		match_mcast_group[*flowid] = mcast_group;
#endif /* VXLAN_MCAST */

	return 0;
}

int switch_del_TCAM_rule_entry(__u32 flowid, __u32 switch_table_id)
{
	fm_status err = 0;
#ifdef VXLAN_MCAST
	fm_int mcast_group = -1;
#endif /* VXLAN_MCAST */

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: deleting flow entry (switch %d, flowid %d)\n", __func__, switch_table_id, flowid);
#endif /* DEBUG */
	err = fmDeleteFlow(sw, (int)switch_table_id, (int)flowid);
	if (err != FM_OK)
		return cleanup("fmDeleteFlow", err);

#ifdef VXLAN_MCAST
	if (match_mcast_group[flowid] != -1) {
		mcast_group = match_mcast_group[flowid];

		match_mcast_group[flowid] = -1;

		err = fmDeactivateMcastGroup(sw, mcast_group);
		if (err != FM_OK)
			return cleanup("fmDeactivateMcastGroup", err);

		err = fmDeleteMcastGroup(sw, mcast_group);
		if (err != FM_OK)
			return cleanup("fmDeleteMcastGroup", err);
	}
#endif /* VXLAN_MCAST */

	return 0;
}

int switch_create_TE_table(int te, __u32 table_id, struct net_mat_field_ref *matches, __u32 *actions, __u32 size, int max_actions)
{
	fm_status err = 0;
	fm_flowCondition condition = 0;
	int te_direct = FALSE;
	int te_encap = FALSE;
	int te_decap = FALSE;
	int i;
	for (i = 0; matches && matches[i].instance; i++) {
		switch (matches[i].instance) {
		case HEADER_INSTANCE_VXLAN:
			switch (matches[i].field) {
			case HEADER_VXLAN_VNI:
				condition |= FM_FLOW_MATCH_VNI;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_VXLAN, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_ETHERNET:
			switch (matches[i].field) {
			case HEADER_ETHERNET_SRC_MAC:
				condition |= FM_FLOW_MATCH_SRC_MAC;
				break;
			case HEADER_ETHERNET_DST_MAC:
				condition |= FM_FLOW_MATCH_DST_MAC;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_ETHERNET, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_IPV4:
			switch (matches[i].field) {
			case HEADER_IPV4_SRC_IP:
				condition |= FM_FLOW_MATCH_SRC_IP;
				break;
			case HEADER_IPV4_DST_IP:
				condition |= FM_FLOW_MATCH_DST_IP;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_IPV4, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_UDP:
			switch (matches[i].field) {
			case HEADER_UDP_SRC_PORT:
				condition |= FM_FLOW_MATCH_L4_SRC_PORT;
				break;
			case HEADER_UDP_DST_PORT:
				condition |= FM_FLOW_MATCH_L4_DST_PORT;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_UDP, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_TCP:
			switch (matches[i].field) {
			case HEADER_TCP_SRC_PORT:
				condition |= FM_FLOW_MATCH_L4_SRC_PORT;
				break;
			case HEADER_TCP_DST_PORT:
				condition |= FM_FLOW_MATCH_L4_DST_PORT;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_TCP, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_DIRECT_INDEX_METADATA:
			switch (matches[i].field) {
			case HEADER_METADATA_DIRECT_INDEX:
				te_direct = TRUE;
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_DIRECT_INDEX_METADATA, field=%d\n",
					__func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		default:
			MAT_LOG(ERR, "%s: match error in INSTANCE, instance=%d\n", __func__, matches[i].field);
			err = -EINVAL;
			break;
		}
	}

	if (te_direct && (condition != 0)) {
		MAT_LOG(ERR, "%s: direct flow table can not have match conditions\n", __func__);
		err = -EINVAL;
	}

	if (err == -EINVAL)
		return err;

	for (i = 0; actions && actions[i]; i++) {
		MAT_LOG(DEBUG, "actions[%d] = %d\n", i, actions[i]);
		switch (actions[i]) {
		case ACTION_TUNNEL_DECAP:
		case ACTION_TUNNEL_DECAP_NSH:
			te_decap = TRUE;
			break;
		case ACTION_TUNNEL_ENCAP:
		case ACTION_TUNNEL_ENCAP_NSH:
			te_encap = TRUE;
			break;
		}
	}

	if (te_encap && te_decap) {
		MAT_LOG(ERR, "%s: a te flow table can not have both encap and decap actions\n", __func__);
		err = -EINVAL;
	}

	if (!te_encap && !te_decap) {
#ifdef DEBUG
		MAT_LOG(DEBUG, "%s: TE table has neither encap nor decap action, default to encap\n", __func__);
#endif /* DEBUG */
		te_encap = TRUE;
	}

	if (err == -EINVAL)
		return err;

	/* condition = FM_FLOW_TABLE_COND_ALL_12_TUPLE; */

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: setting flow table attribute FM_FLOW_TABLE_TUNNEL_ENGINE %d\n", __func__, te);
#endif /* DEBUG */
	err = fmSetFlowAttribute(sw, (fm_int)table_id, FM_FLOW_TABLE_TUNNEL_ENGINE, &te);
	if (err != FM_OK)
		return cleanup("fmSetFlowAttribute", err);

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: setting flow table attribute FM_FLOW_TABLE_TUNNEL_ENCAP %d\n", __func__, te_encap);
#endif /* DEBUG */
	err = fmSetFlowAttribute(sw, (fm_int)table_id, FM_FLOW_TABLE_TUNNEL_ENCAP, &te_encap);
	if (err != FM_OK)
		return cleanup("fmSetFlowAttribute", err);

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: creating flow TE table: table %d, direct %d, condition 0x%llx, maxEntries %d, maxActions %d\n",
		__func__, table_id, te_direct, condition, size, max_actions);
#endif /* DEBUG */

	err = fmCreateFlowTETable(sw, (fm_int)table_id, condition, size, (fm_uint32)max_actions);
	if (err != FM_OK)
		return cleanup("fmCreateFlowTETable", err);

	/**
	 * @todo - Each time a table is created the tunnel engine
	 * configuration is overwritten. Until this is fixed we need
	 * to explicitely set the destination port to support NSH.
	 */
	err = switch_tunnel_engine_set_default_nge_port(te, MATCH_NSH_PORT);
	if (err != FM_OK)
		return -EINVAL;

	return 0;
}

int switch_del_TE_table(__u32 table_id)
{
	fm_status err = 0;

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: deleting flow TE table %d\n", __func__, table_id);
#endif /* DEBUG */
	err = fmDeleteFlowTETable(sw, (int)table_id);
	if (err != FM_OK)
		return cleanup("fmDeleteFlowTETable", err);

	return 0;
}

static void
set_nsh_encap_action(__u32 dst_ip, __u32 src_ip, __u32 vni, __u16 src_port,
		     __u16 dst_port, __u32 service_index, __u8 service_path_id,
		     fm_flowAction *act, fm_flowParam *param)
{
	*act |= FM_FLOW_ACTION_ENCAP_SIP |
	  FM_FLOW_ACTION_ENCAP_L4SRC |
	  FM_FLOW_ACTION_ENCAP_L4DST |
	  FM_FLOW_ACTION_ENCAP_VNI |
	  FM_FLOW_ACTION_ENCAP_NGE;

	param->tunnelType = FM_TUNNEL_TYPE_NGE;
	param->outerDip.addr[0] = dst_ip;
	param->outerSip.addr[0] = src_ip;
	param->outerVni = vni;
	param->outerL4Src = src_port;
	param->outerL4Dst = dst_port;

	/* 6 NgeData words are valid */
	param->outerNgeMask = 0x3f;

	/*
	 * NSH Base Header is NgeData[0]
	 *  Version = 0, O and C bits are unset.
	 *  Length = 6 DWORDS, MD Type = 1, Next Protocol = 0x3 (Ethernet)
	 */
	param->outerNgeData[0] = 0x00060103;

	/* NSH Service Path Header is NgeData[1] */
	param->outerNgeData[1] = (service_index << 8) | service_path_id;

	/* remaining fields are zero */
	param->outerNgeData[2] = 0x0;
	param->outerNgeData[3] = 0x0;
	param->outerNgeData[4] = 0x0;
	param->outerNgeData[5] = 0x0;

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: action TUNNEL_ENCAP_NSH(0x%08x,0x%08x,%d,%d,%d,%d,%d)\n",
		__func__, dst_ip, src_ip, vni, src_port, dst_port,
		service_index, service_path_id);
#endif
}

int switch_add_TE_rule_entry(__u32 *flowid, __u32 table_id, __u32 priority, struct net_mat_field_ref *matches, struct net_mat_action *actions)
{
	int i;
	fm_status err = 0;
	fm_flowCondition cond = 0;
	fm_flowValue condVal;
	fm_flowAction act = 0;
	fm_flowParam param;
#ifdef DEBUG
	__u16 direct_idx = 0;
#endif

	memset(&condVal, 0, sizeof(condVal));
	memset(&param, 0, sizeof(param));

	for (i = 0; matches && matches[i].instance; i++) {
		switch (matches[i].instance) {
		case HEADER_INSTANCE_VXLAN:
			switch (matches[i].field) {
			case HEADER_VXLAN_VNI:
				cond |= FM_FLOW_MATCH_VNI;
				condVal.vni = matches[i].v.u32.value_u32;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match VNI(%d)\n", __func__, condVal.vni);
#endif /* DEBUG */
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_VXLAN, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_ETHERNET:
			switch (matches[i].field) {
			case HEADER_ETHERNET_SRC_MAC:
				cond |= FM_FLOW_MATCH_SRC_MAC;
				condVal.src = matches[i].v.u64.value_u64;
				condVal.srcMask = matches[i].v.u64.mask_u64;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match SRC_MAC(0x%016llx:0x%016llx)\n", __func__, condVal.src, condVal.srcMask);
#endif /* DEBUG */
				break;
			case HEADER_ETHERNET_DST_MAC:
				cond |= FM_FLOW_MATCH_DST_MAC;
				condVal.dst = matches[i].v.u64.value_u64;
				condVal.dstMask = matches[i].v.u64.mask_u64;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match DST_MAC(0x%016llx:0x%016llx)\n", __func__, condVal.dst, condVal.dstMask);
#endif /* DEBUG */
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_INSTANCE_ETHERNET, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_IPV4:
			switch (matches[i].field) {
			case HEADER_IPV4_SRC_IP:
				cond |= FM_FLOW_MATCH_SRC_IP;
				condVal.srcIp.addr[0] = matches[i].v.u32.value_u32;
				condVal.srcIp.isIPv6 = FALSE;
				condVal.srcIpMask.addr[0] = matches[i].v.u32.mask_u32;
				condVal.srcIpMask.isIPv6 = FALSE;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match SRC_IP(0x%08x:0x%08x)\n", __func__, condVal.srcIp.addr[0], condVal.srcIpMask.addr[0]);
#endif /* DEBUG */

				break;
			case HEADER_IPV4_DST_IP:
				cond |= FM_FLOW_MATCH_DST_IP;
				condVal.dstIp.addr[0] = matches[i].v.u32.value_u32;
				condVal.dstIp.isIPv6 = FALSE;
				condVal.dstIpMask.addr[0] = matches[i].v.u32.mask_u32;
				condVal.dstIpMask.isIPv6 = FALSE;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match DST_IP(0x%08x:0x%08x)\n", __func__, condVal.dstIp.addr[0], condVal.dstIpMask.addr[0]);
#endif /* DEBUG */

				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_INSTANCE_IPV4, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_TCP:
		case HEADER_INSTANCE_UDP:
			switch (matches[i].field) {
			case HEADER_TCP_SRC_PORT:
				cond |= FM_FLOW_MATCH_L4_SRC_PORT;
				condVal.L4SrcStart = matches[i].v.u16.value_u16;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match L4_SRC_PORT(%d)\n", __func__, condVal.L4SrcStart);
#endif /* DEBUG */
				break;
			case HEADER_TCP_DST_PORT:
				cond |= FM_FLOW_MATCH_L4_DST_PORT;
				condVal.L4DstStart = matches[i].v.u16.value_u16;
#ifdef DEBUG
				MAT_LOG(DEBUG, "%s: match L4_DST_PORT(%d)\n", __func__, condVal.L4DstStart);
#endif /* DEBUG */
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_INSTANCE_TCP/UDP, field=%d\n", __func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		case HEADER_INSTANCE_DIRECT_INDEX_METADATA:
			switch (matches[i].field) {
			case HEADER_METADATA_DIRECT_INDEX:
#ifdef DEBUG
				direct_idx = matches[i].v.u16.value_u16;
				MAT_LOG(DEBUG, "%s: match HEADER_METADATA_DIRECT_INDEX(%d)\n", __func__, direct_idx);
#endif /* DEBUG */
				break;
			default:
				MAT_LOG(ERR, "%s: match error in HEADER_DIRECT_INDEX_METADATA, field=%d\n",
					__func__, matches[i].field);
				err = -EINVAL;
				break;
			}

			break;
		default:
			MAT_LOG(ERR, "%s: match error unsupported instance %d\n", __func__, matches[i].instance);
			err = -EINVAL;
			break;
		}
	}

	for (i = 0; actions && actions[i].uid; i++) {
		switch (actions[i].uid) {
		case ACTION_TUNNEL_ENCAP_NSH:
			set_nsh_encap_action(actions[i].args[0].v.value_u32,
					     actions[i].args[1].v.value_u32,
					     actions[i].args[2].v.value_u32,
					     actions[i].args[3].v.value_u16,
					     actions[i].args[4].v.value_u16,
					     actions[i].args[5].v.value_u32,
					     actions[i].args[6].v.value_u8,
					     &act, &param);
			break;
		case ACTION_TUNNEL_DECAP_NSH:
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action TUNNEL_DECAP_NSH\n", __func__);
#endif
			break;
		case ACTION_TUNNEL_ENCAP:
			act |= FM_FLOW_ACTION_ENCAP_SIP |
#if 0
			       FM_FLOW_ACTION_ENCAP_TTL |
#endif /* 0 */
			       FM_FLOW_ACTION_ENCAP_L4SRC |
			       FM_FLOW_ACTION_ENCAP_L4DST |
			       FM_FLOW_ACTION_ENCAP_VNI;

			param.tunnelType = FM_TUNNEL_TYPE_VXLAN;
			param.outerDip.addr[0] = actions[i].args[0].v.value_u32;
			param.outerSip.addr[0] = actions[i].args[1].v.value_u32;
			param.outerVni = actions[i].args[2].v.value_u32;
			param.outerL4Src = actions[i].args[3].v.value_u16;
			param.outerL4Dst = actions[i].args[4].v.value_u16;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action TUNNEL_ENCAP(0x%08x,0x%08x,%d,%d,%d)\n", __func__,
				param.outerDip.addr[0],
				param.outerSip.addr[0],
				param.outerVni,
				param.outerL4Src,
				param.outerL4Dst);
#endif /* DEBUG */
			break;
		case ACTION_TUNNEL_DECAP:
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action TUNNEL_DECAP\n", __func__);
#endif /* DEBUG */
			break;
		case ACTION_SET_EGRESS_PORT:
			act |= FM_FLOW_ACTION_FORWARD;
			param.logicalPort = (fm_int)actions[i].args[0].v.value_u32;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action FORWARD(%d)\n", __func__, param.logicalPort);
#endif /* DEBUG */
			break;
		case ACTION_SET_DST_MAC:
			act |= FM_FLOW_ACTION_SET_DMAC;
			param.dmac = actions[i].args[0].v.value_u64;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action SET_DMAC(0x%012llx)\n", __func__, param.dmac);
#endif /* DEBUG */
			break;
		case ACTION_SET_SRC_MAC:
			act |= FM_FLOW_ACTION_SET_SMAC;
			param.smac = actions[i].args[0].v.value_u64;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action SET_SMAC(0x%012llx)\n", __func__, param.smac);
#endif /* DEBUG */
			break;
		case ACTION_SET_IPV4_DST_IP:
			act |= FM_FLOW_ACTION_SET_DIP;
			param.dip.addr[0] = actions[i].args[0].v.value_u32;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action SET_DIP(0x%08x)\n", __func__, param.dip.addr[0]);
#endif /* DEBUG */
			break;
		case ACTION_SET_IPV4_SRC_IP:
			act |= FM_FLOW_ACTION_SET_SIP;
			param.sip.addr[0] = actions[i].args[0].v.value_u32;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action SET_SIP(0x%08x)\n", __func__, param.sip.addr[0]);
#endif /* DEBUG */
			break;
		case ACTION_SET_TCP_DST_PORT:
		case ACTION_SET_UDP_DST_PORT:
			act |= FM_FLOW_ACTION_SET_L4DST;
			param.l4Dst = actions[i].args[0].v.value_u16;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action SET_L4DST(%d)\n", __func__, param.l4Dst);
#endif /* DEBUG */
			break;
		case ACTION_SET_TCP_SRC_PORT:
		case ACTION_SET_UDP_SRC_PORT:
			act |= FM_FLOW_ACTION_SET_L4SRC;
			param.l4Src = actions[i].args[0].v.value_u16;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action SET_L4SRC(%d)\n", __func__, param.l4Src);
#endif /* DEBUG */
			break;
		case ACTION_COUNT:
			act |= FM_FLOW_ACTION_COUNT;
#ifdef DEBUG
			MAT_LOG(DEBUG, "%s: action COUNT\n", __func__);
#endif /* DEBUG */
			break;
		default:
			MAT_LOG(ERR, "%s: unsupported action %d\n", __func__, actions[i].uid);
			err = -EINVAL;
			break;
		}
	}

	if (err == -EINVAL)
		return err;

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: add TE flow : table %d, cond 0x%llx, act 0x%llx\n",
		__func__, table_id, cond, act);
#endif /* DEBUG */
	err = fmAddFlow(sw, (fm_int)table_id, (fm_uint16)priority, 0,
			cond, &condVal, act, &param, FM_FLOW_STATE_ENABLED,
			(int *)flowid);
	if (err != FM_OK)
		return cleanup("fmAddFlow", err);
#ifdef DEBUG
	else
		MAT_LOG(DEBUG, "%s: flow flowid %d added to table %d\n", __func__, *flowid, table_id);
#endif /* DEBUG */

	return 0;
}

int switch_del_TE_rule_entry(__u32 flowid, __u32 switch_table_id)
{
	fm_status err = 0;

#ifdef DEBUG
	MAT_LOG(DEBUG, "%s: deleting TE flow entry (switch %d, flowid %d)\n", __func__, switch_table_id, flowid);
#endif /* DEBUG */
	err = fmDeleteFlow(sw, (int)switch_table_id, (int)flowid);
	if (err != FM_OK)
		return cleanup("fmDeleteFlow", err);

	return 0;
}

int switch_add_L2MP_rule_entry(struct net_mat_field_ref *matches,
			       struct net_mat_action *actions)
{
	fm_LBGDistributionMapRange range;
	fm_int lbg, state, i;
	fm_LBGParams params;
	fm_status err;
	fm_int *ports;
	fm_int bins = 0;
	__u32 group;

	switch (matches[0].instance) {
	case HEADER_INSTANCE_L2_MP_METADATA:
			group = matches[0].v.u32.value_u32;
			break;
	default:
		return -EINVAL;
	}

	if (group >=  TABLE_L2_MP_SIZE)
		return -EINVAL;

	if (l2mp_group[group] != -1)
		return -EEXIST;

	for (i = 0; actions[0].args[i].type; i++)
		bins++;

	memset(&params, 0, sizeof(params));
	params.numberOfBins = bins;
	params.mode = FM_LBG_MODE_MAPPED_L234HASH;

	err = fmCreateLBGExt(sw, &lbg, &params);
	if (err != FM_OK)
		return cleanup("fmCreateLBGExt", err);

	ports = calloc((size_t)bins, sizeof(fm_int));
	if (!ports)
		return -ENOMEM;

	for (i = 0; actions[0].args && actions[0].args[i].type; i++)
		ports[i] = (int)actions[0].args[i].v.value_u32;

	range.ports = ports;
	range.firstBin = 0;
	range.numberOfBins = bins;

	err = fmSetLBGAttribute(sw, lbg, FM_LBG_DISTRIBUTION_MAP_RANGE, &range);
	free(ports);
	if (err != FM_OK)
		return cleanup("fmSetLBGAttribute", err);

	state = FM_LBG_STATE_ACTIVE;
	err = fmSetLBGAttribute(sw, lbg, FM_LBG_STATE, &state);
	if (err != FM_OK)
		return cleanup("fmSetLBGAttribute", err);

	l2mp_group[group] = lbg;
	return 0;
}

int switch_del_L2MP_rule_entry(struct net_mat_field_ref *matches)
{
	fm_status err;
	__u32 group;
	fm_int lbg;

	switch (matches[0].instance) {
	case HEADER_INSTANCE_L2_MP_METADATA:
			group = matches[0].v.u32.value_u32;
			break;
	default:
		return -EINVAL;
	}

	if (group >=  TABLE_L2_MP_SIZE)
		return -EINVAL;

	if (l2mp_group[group] == -1)
		return -EINVAL;

	lbg = l2mp_group[group];
	err = fmDeleteLBG(sw, lbg);
	if (err != FM_OK)
		return cleanup("fmDeleteLBG", err);

	l2mp_group[group] = -1;
	return 0;
}
