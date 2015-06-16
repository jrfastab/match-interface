/*******************************************************************************
  Backend framework for MATCH Interface

  Author: Jeff Shaw <jeffrey.b.shaw@intel.com>
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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "backend.h"
#include "matchlib.h"
#include "if_match.h"

/**
 * @internal
 * @struct match_backend_head
 * @brief Defines the head of a backend tailq
 */
TAILQ_HEAD(match_backend_head, match_backend);

/** list of backends */
static struct match_backend_head backend_list =
		TAILQ_HEAD_INITIALIZER(backend_list);

void match_backend_register(struct match_backend *backend)
{
	TAILQ_INSERT_TAIL(&backend_list, backend, next);
}

const char *match_backend_get_next(void **cookie)
{
	struct match_backend *backend = NULL;

	if (cookie == NULL)
		return NULL;

	if (*cookie == NULL) {
		backend = TAILQ_FIRST(&backend_list);
		*cookie = backend;
		return backend->name;
	}

	backend = TAILQ_NEXT((struct match_backend *)*cookie, next);
	if (backend) {
		*cookie = backend;
		return backend->name;
	}

	return NULL;
}

void match_backend_list_all(void)
{
	const char *name = NULL;
	void *cookie = NULL;

	while ((name = match_backend_get_next(&cookie)))
		fprintf(stdout, "%s\n", name);
}

static bool backend_is_sane(struct match_backend *be)
{
	uint32_t max;
	int i;

	if (!be->name || !be->hdrs || !be->actions || !be->tbls ||
	    !be->hdr_nodes || !be->tbl_nodes || !be->open)
		return false;

	for (i = 0, max = 0; be->hdrs[i]; ++i)
		if (be->hdrs[i]->uid > max)
			max = be->hdrs[i]->uid;
	be->max_header_id = max;

	for (i = 0, max = 0; be->actions[i]; ++i)
		if (be->actions[i]->uid > max)
			max = be->actions[i]->uid;
	be->max_action_id = max;

	for (i = 0, max = 0; be->tbls[i]; ++i)
		if (be->tbls[i]->uid > max)
			max = be->tbls[i]->uid;
	be->max_table_id = max;

	/**
	 * @todo: validate table matches (instance, header, field),
	 * table actions, header nodes, table nodes, etc.
	 */

	return true;
}

static int backend_open_internal(struct match_backend *be, void *init_arg)
{
	int err;

	if (!backend_is_sane(be))
		return -ENOSYS;

	match_push_headers(be->hdrs);
	match_push_header_fields(be->hdrs);
	match_push_actions(be->actions);
	match_push_tables(be->tbls);
	match_push_graph_nodes(be->hdr_nodes);

	err = be->open(init_arg);
	if (err)
		return err;

	be->is_open = true;
	return 0;
}

struct match_backend *match_backend_open(const char *name, void *init_arg)
{
	struct match_backend *backend = NULL;

	if (!name)
		return NULL;

	TAILQ_FOREACH(backend, &backend_list, next) {
		if (!strcmp(backend->name, name)) {
			if (backend_open_internal(backend, init_arg))
				return NULL;
			break;
		}
	}

	return backend;
}

void match_backend_close(struct match_backend *backend)
{
	if (backend) {
		if (backend->is_open && backend->close)
			backend->close();
		backend->is_open = false;
	}
}
