/*******************************************************************************
  Implementation of the IES (Intel Ethernet Switch) backend
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
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <fcntl.h>

#include "models/bpf_match.h" /* Pipeline model */
#include "matchlib.h"
#include "backend.h"
#include "matlog.h"
#include "if_match.h"

/* At most support one counter table per match table this is a bit
 * arbitrary but it simplifies the code some and I've not had a reason
 * to add more. At some point we can do this dynamically.
 */
#define BPF_MATCH_MAX_TABLES (BPF_MAX_TABLES * 2)

static int fds[BPF_MATCH_MAX_TABLES] = {0};
static char bpf_filename[] = "/tmp/bpf_match";

struct bpf_elf_st {
	dev_t st_dev;
	ino_t st_ino;
};

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 id;
};

struct bpf_map_aux {
	unsigned short uds_ver;
	unsigned short num_ent;
	char obj_name[64];
	struct bpf_elf_st obj_st;
	struct bpf_elf_map ent[BPF_MATCH_MAX_TABLES];
};

struct bpf_map_set_msg {
	struct msghdr hdr;
	struct iovec iov;
	char msg_buf[1024];
	struct bpf_map_aux aux;
};

static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
	return  (__u64) (unsigned long) ptr;
}

#ifdef __NR_bpf
static inline int bpf_map_update_elem(__u32 fd, void *key, void *value)
{
	union bpf_attr attr = {.map_type = 0}; /* initialize to zero */

	attr.map_fd = fd;
	attr.key = bpf_ptr_to_u64(key);
	attr.value = bpf_ptr_to_u64(value);

	return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
#else
static inline int bpf_map_update_elem(__u32 fd __unused, void *key __unused, void *value __unused)
{
	return 0;
}
#endif

/* table cache is used to have a software representation of the maps
 * data structure. This allows reads to avoid going to kernel via
 * syscalls to rebuild the rules. Trading memory for ease of use here.
 */
char *table_cache[BPF_MATCH_MAX_TABLES];
struct bpf_elf_map table_aux[BPF_MATCH_MAX_TABLES];
int table_fds[BPF_MATCH_MAX_TABLES];

static int bpf_pipeline_open(void *arg __unused)
{
	struct sockaddr_un bpf_addr;
	int err, fd;
	long unsigned int i, num_fds;
	struct bpf_map_aux aux = {0};
	struct bpf_map_set_msg bpf_msg;
	ssize_t ret;
	char filename[1024];

 	memset(&bpf_msg, 0, sizeof (struct bpf_map_set_msg));

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd < 0) {
		MAT_LOG(ERR, "bpf af_unix socket failed: abort!\n");
		exit(-1);
	}

	memset(&bpf_addr, 0, sizeof(bpf_addr));
	bpf_addr.sun_family = AF_UNIX;

	for (i = 100; i < 200; i++) {
		sprintf(filename, "%s%lu", bpf_filename, i);
		strncpy(bpf_addr.sun_path, filename, sizeof bpf_addr.sun_path);

		err = bind(fd, (struct sockaddr *)&bpf_addr, sizeof bpf_addr);
		if (err < 0) {
			MAT_LOG(ERR, "bpf bind socket %s failed(%i): continue!\n", filename, err); 
			continue;
		}

		printf("%s: using filename: %s\n", __func__, filename);
		break;
	}

	if (err) {
		MAT_LOG(ERR, "last bpf bind socket %s failed(%i): abort!\n", filename, err); 
		exit(-1);
	}

	for (i = 0; i < BPF_MATCH_MAX_TABLES; i += num_fds) {
		struct cmsghdr *cmsg;

		bpf_msg.iov.iov_base = &bpf_msg.aux;	
		bpf_msg.iov.iov_len = sizeof bpf_msg.aux;

		bpf_msg.hdr.msg_iov = &bpf_msg.iov;
		bpf_msg.hdr.msg_iovlen = 1;

		bpf_msg.hdr.msg_control = &bpf_msg.msg_buf;
		bpf_msg.hdr.msg_controllen = (10 * sizeof(int)); //(sizeof (int));

		cmsg = CMSG_FIRSTHDR(&bpf_msg.hdr);
		cmsg->cmsg_len = bpf_msg.hdr.msg_controllen;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;

		printf("%s: waiting for filter (tbd replace with fuse)\n", __func__);

		ret = recvmsg(fd, &bpf_msg.hdr, 0);
		if (ret <= 0)
			break;
		printf("%s: received maps (%lu)\n", __func__, ret);

		cmsg = CMSG_FIRSTHDR(&bpf_msg.hdr);

		num_fds = (cmsg->cmsg_len - sizeof(*cmsg)) / sizeof(int);
		assert(num_fds < BPF_MATCH_MAX_TABLES);

		memcpy(&fds[i], CMSG_DATA(cmsg), sizeof(int) * num_fds);
		memcpy(&aux.ent[i], &bpf_msg.aux.ent[i], sizeof(bpf_msg.aux.ent[0]) * num_fds);
		memcpy(&aux, &bpf_msg.aux, offsetof(struct bpf_map_aux, ent));

		printf("%s: i %lu num_fds %lu num_ent %i\n", __func__, i, num_fds, aux.num_ent);
		if ((i + num_fds) == (long unsigned) (aux.num_ent <= 0 ? 0 : aux.num_ent))
			break;
	}

	for (i = 0; i < BPF_MATCH_MAX_TABLES; i++) {
		const char *unknown = "Unknown-Table";
		const char *str_label = unknown;
		int j;

		for (j = 0; j < BPF_MAX_TABLES; j++) {
			if (bpf_table_list[j]->uid == aux.ent[i].id) {
				int index = bpf_table_list[j]->uid;

				str_label = bpf_table_list[j]->name;

				/* If the table_id is larger then the max table this is a code
				 * generator bug most likely in bpf_match.h or the actual bpf
				 * program being loaded. In this case do a hard abort and let
				 * the user sort the mess out.
				 */
				assert(aux.ent[i].id < BPF_MATCH_MAX_TABLES);
				table_cache[index] = calloc(aux.ent[i].max_elem, aux.ent[i].size_value);
				table_aux[index] = aux.ent[i];
				table_fds[index] = fds[i];
				break;
			}
		}

		printf("%s: @ %lu:fd(%i)\n", __func__, i, fds[i]);
		printf("\t label: %u -> %s\n", aux.ent[i].id, str_label);
		printf("\t type: %u\n", aux.ent[i].type);
		printf("\t max_elem: %u\n", aux.ent[i].max_elem);
		printf("\t key_size: %u\n", aux.ent[i].size_key);
		printf("\t size val: %u\n", aux.ent[i].size_value);
	}

	return 0;
}

static void bpf_pipeline_close(void)
{
	int i;

	for (i = 0; i < BPF_MATCH_MAX_TABLES; i++)
		free(table_cache[i]);

	return;
}

static void bpf_pipeline_get_rule_counters(struct net_mat_rule *rule __unused)
{
	MAT_LOG(ERR, "bpf get_counters unsupported\n");
	return;
}

static int bpf_pipeline_del_rules(struct net_mat_rule *rule __unused)
{
	return -EOPNOTSUPP; 
}

static struct net_mat_tbl *bpf_get_table(__u32 table)
{
	int i;

	for (i = 0; bpf_table_list[i]; i++) {
		if (bpf_table_list[i]->uid == table)
			return bpf_table_list[i];
	}

	return NULL;
}

static
struct net_mat_field_ref *bpf_find_field_ref(struct net_mat_field_ref find,
					     struct net_mat_field_ref *list)
{
	int i;

	for (i = 0; list[i].instance ; i++) {
		if (find.instance == list[i].instance &&
		    find.header == list[i].header &&
		    find.field == list[i].field)
			return &list[i];
	}

	printf("%s: missing: find.instance %i find.header %i find.field %i\n", __func__, find.instance, find.header, find.field);
	return NULL;
}

static int bpf_match_to_key(__u32 table,
			    struct net_mat_field_ref *matches,
			    __u8 *key)
{
	struct net_mat_tbl *tbl = bpf_get_table(table);
	unsigned int i, offset = 0;

	assert(tbl);

	/* BPF keys for exact match tables (the only kind currently supported)
	 * are packed in the order defined by the table. So we can walk the
	 * table list and pack with the assumption that this is the correct
	 * order because we also generated the BPF program lookup to use the
	 * same scheme.
	 *
	 * Also assume that matchlib gives us fully qualified match entries.
	 * This assumption is tested with an assert for now.
	 */
	for (i = 0; tbl->matches[i].instance; i++) {
		struct net_mat_field_ref *ref = bpf_find_field_ref(tbl->matches[i], matches);
		int bitdiff = 0, j;

		assert(ref);

		for (j = 0; bpf_header_list[j] && !bitdiff; j++) {
			struct net_mat_hdr *hdr = bpf_header_list[j];
			unsigned int k;

			if (ref->header == hdr->uid) {
				for (k = 0; k < hdr->field_sz; k++) {
					struct net_mat_field *f = &hdr->fields[k];

					if (ref->field == f->uid) {
						bitdiff = f->bitwidth;
						break;
					}
				}
			}
		}

		switch (ref->type) {
		case NET_MAT_FIELD_REF_ATTR_TYPE_U8:
			ref->v.u8.value_u8 <<= (8 - bitdiff);
			memcpy(&key[offset], &ref->v.u8.value_u8, sizeof(__u8));
			offset+=1;
			break;
		case NET_MAT_FIELD_REF_ATTR_TYPE_U16:
			ref->v.u16.value_u16 <<= (16 - bitdiff);
			memcpy(&key[offset], &ref->v.u16.value_u16, sizeof(__u16));
			offset+=2;
			break;
		case NET_MAT_FIELD_REF_ATTR_TYPE_U32:
			ref->v.u32.value_u32 <<= (32 - bitdiff);
			memcpy(&key[offset], &ref->v.u32.value_u32, sizeof(__u32));
			offset+=4;
			break;
		case NET_MAT_FIELD_REF_ATTR_TYPE_U64:
			ref->v.u64.value_u64 <<= (64 - bitdiff);
			memcpy(&key[offset], &ref->v.u64.value_u64, sizeof(__u64));
			offset+=8;
			break;
		}
	}

	printf("%s: using key: ", __func__);
	for (i = 0; i < offset; i++)
		printf("%02x\n", key[i]);
	printf("\n");

	return 0;
}

static int bpf_match_to_value(struct net_mat_action *actions, __u8 *value)
{
	long unsigned int offset, i;

	for (offset = 0, i = 0; actions[i].uid; i++) {
		unsigned long j;

		memcpy(&value[offset], &actions[i].uid, sizeof(__u32));
		offset += sizeof(__u32);

		for (j = 0; actions[i].args && actions[i].args[j].type; j++) {
			switch (actions[i].args[j].type) {
			case NET_MAT_ACTION_ARG_TYPE_U8:
				memcpy(&value[offset],
				       &actions[i].args[j].v.value_u8,
				       sizeof(__u8));
				offset += sizeof(__u8);
				break;
			case NET_MAT_ACTION_ARG_TYPE_U16:
				memcpy(&value[offset],
				       &actions[i].args[j].v.value_u16,
				       sizeof(__u16));
				offset += sizeof(__u16);
				break;
			case NET_MAT_ACTION_ARG_TYPE_U32:
				memcpy(&value[offset],
				       &actions[i].args[j].v.value_u32,
				       sizeof(__u32));
				offset += sizeof(__u32);
				break;
			case NET_MAT_ACTION_ARG_TYPE_U64:
				memcpy(&value[offset],
				       &actions[i].args[j].v.value_u64,
				       sizeof(__u64));
				offset += sizeof(__u64);
				break;
			case NET_MAT_ACTION_ARG_TYPE_NULL:
			case NET_MAT_ACTION_ARG_TYPE_UNSPEC:
			case NET_MAT_ACTION_ARG_TYPE_VARIADIC:
			case __NET_MAT_ACTION_ARG_TYPE_VAL_MAX:
				break;
			}
		}
	}

	printf("%s: using value: ", __func__);
	for (i = 0; i < offset; i++)
		printf("%02x\n", value[i]);
	printf("\n");


	return 0;
}

static int bpf_pipeline_set_rules(struct net_mat_rule *rule __unused)
{
	__u8 *key, *value;
	int err;

	/* Assert on these because we expect matchlib should never pass us
	 * ill-formed rules. Added assert in the interim because I'm using
	 * this to fuzz-test the middle layer and want hard errors in lower
	 * layer when something goes wrong.
	 */
	assert(rule->table_id < BPF_MATCH_MAX_TABLES);

	/* BPF backend uses a linear reference scheme where uid maps
	 * 1:1 with hw_rule_ids. So when the user ids greater than
	 * the map size drop them.
	 *
	 * Should middle layer catch this?
	 */
	printf("%s: rule %i max %i\n", __func__, rule->uid, table_aux[rule->table_id].max_elem);
	assert(rule->uid < table_aux[rule->table_id].max_elem);
	/*
	if (uid  > table_aux[rule.table_id].max_elem) {
		MAT_LOG(DEBUG, "set_rule rule uid greater than table size!\n";
		return -EINVAL;
	}
	*/

	key = calloc(1, table_aux[rule->table_id].size_key);
	if (!key)
		return -ENOMEM;

	value = calloc(1, table_aux[rule->table_id].size_value);
	if (!value) {
		free(key);
		return -ENOMEM;
	}

	err = bpf_match_to_key(rule->table_id, rule->matches, key);
	if (err)
		return err;

	err = bpf_match_to_value(rule->actions, value);
	if (err)
		return err;

	bpf_map_update_elem((__u32)table_fds[rule->table_id],
			    (__u8 *) key,
			    value);

	return 0;
}

static int bpf_pipeline_create_table(struct net_mat_tbl *tbl __unused)
{
#if 0
        static char buf[4096];
        ssize_t sz;
        int trace_fd;

        trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
        if (trace_fd < 0)
                return -EINVAL;
       
	sz = read(trace_fd, buf, sizeof(buf));
	if (sz > 0) {
		buf[sz] = 0;
		puts(buf);
	}

	printf("buf: %s\n", buf);
#endif

	return -EINVAL;
}

static int bpf_pipeline_destroy_table(struct net_mat_tbl *tbl __unused)
{
	return -EINVAL;
}

static int bpf_pipeline_update_table(struct net_mat_tbl *tbl __unused)
{
	return -EINVAL;
}

static int bpf_ports_get(struct net_mat_port **ports __unused)
{
	return -EINVAL;
}

static int bpf_ports_set(struct net_mat_port *ports __unused)
{
	return -EINVAL;
}

static int bpf_port_get_lport(struct net_mat_port *port __unused,
                              unsigned int *lport __unused, unsigned int *glort __unused)
{
	return -EINVAL;
}

static int bpf_port_get_phys_port(struct net_mat_port *port __unused,
                                  unsigned int *phys_port __unused, unsigned int *glort __unused)
{
	return -EINVAL;
}

struct match_backend bpf_pipeline_backend = {
	.name = "bpf_pipeline",
	.hdrs = bpf_header_list,
	.actions = bpf_action_list,
	.tbls = bpf_table_list,
	.hdr_nodes = bpf_hdr_nodes,
	.tbl_nodes = bpf_tbl_nodes,
	.open = bpf_pipeline_open,
	.close = bpf_pipeline_close,
	.get_rule_counters = bpf_pipeline_get_rule_counters,
	.del_rules = bpf_pipeline_del_rules,
	.set_rules = bpf_pipeline_set_rules,
	.create_table = bpf_pipeline_create_table,
	.destroy_table = bpf_pipeline_destroy_table,
	.update_table = bpf_pipeline_update_table,
	.get_ports = bpf_ports_get,
	.set_ports = bpf_ports_set,
	.get_lport = bpf_port_get_lport,
	.get_phys_port = bpf_port_get_phys_port,
};

MATCH_BACKEND_REGISTER(bpf_pipeline_backend)
