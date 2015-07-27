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

#ifndef _BACKEND_H
#define _BACKEND_H

#include <inttypes.h>
#include <stdbool.h>
#include <sys/queue.h>
#include "if_match.h"

/**
 * @file
 * Backend framework for MATCH Interface.
 */

struct match_backend {
	/** Next backend in a list of backends */
	TAILQ_ENTRY(match_backend) next;

	/** Flag to indicate if a backend is open */
	bool is_open;

	/** Maximum header ID, used by frontend for sanity check */
	uint32_t max_header_id;

	/** Maximum header ID, used by frontend for sanity check */
	uint32_t max_action_id;

	/** Maximum table ID, used by frontend for sanity check */
	uint32_t max_table_id;

	/** Name of this backend */
	const char *name;

	/** Headers supported by the backend */
	struct net_mat_hdr **hdrs;

	/** Actions supported by the backend */
	struct net_mat_action **actions;

	/** Tables supported by the backend */
	struct net_mat_tbl **tbls;

	/** Header graph */
	struct net_mat_hdr_node **hdr_nodes;

	/** Table graph */
	struct net_mat_tbl_node **tbl_nodes;

	/** Function to call when the backend is opened */
	int (*open)(void *);

	/** Function to call when the backend is closed */
	void (*close)(void);

	/** Function to call to get rule byte/packet counters */
	void (*get_rule_counters)(struct net_mat_rule *);

	/** Function to call to delete a list of rules */
	int (*del_rules)(struct net_mat_rule *);

	/** Function to call to set a list of rules */
	int (*set_rules)(struct net_mat_rule *);

	/** Function to call to create a list of tables */
	int (*create_table)(struct net_mat_tbl *);

	/** Function to call to destroy a list of tables */
	int (*destroy_table)(struct net_mat_tbl *);

	/** Function to update an existing table */
	int (*update_table)(struct net_mat_tbl *);

	/* Generate a  port list and hold reference */
	int (*get_ports)(struct net_mat_port **ports);

	/* Release reference to ports */
	int (*set_ports)(struct net_mat_port *ports);

	/* Lookup PCI/MAC function logical port identifier */
	int (*get_lport)(struct net_mat_port *port, unsigned int *lport);
};

/**
 * Register a backend with the backend framework.
 *
 * Before a backend can be opened and used, it must be added to the list
 * of backends using this register function. Backends are typically
 * registered at compile-time using the @ref MATCH_BACKEND_REGISTER macro.
 *
 * @param backend
 *   The backend to register.
 */
void match_backend_register(struct match_backend *backend);

/**
 * Macro to register a backend with the backend framework.
 *
 * Use this macro to avoid having to call the @ref backend_register()
 * function during runtime.
 *
 * An example to use this macro is provided below.
 *
 * @code
 * struct match_backend my_backend = {
 *	.name = "my_backend",
 *	.hdrs = my_hdr_list,
 *	.actions = my_action_list,
 *	.tbls = my_tbl_list,
 *	.hdr_nodes = my_hdr_node_list,
 *	.tbl_nodes = my_tbl_node_list,
 *	.open = my_backend_open,
 *	.close = my_backend_close,
 *	.del_rules = my_backend_del_rules,
 *	.set_rules = my_backend_set_rules,
 *	.create_table = my_backend_create_table,
 *	.destroy_table = my_backend_destroy_table,
 * };
 *
 * MATCH_BACKEND_REGISTER(my_backend)
 * @endcode
 *
 */
#define MATCH_BACKEND_REGISTER(b)                                       \
void matchbackendinitfunc_ ##b(void);                                   \
void __attribute__((constructor, used)) matchbackendinitfunc_ ##b(void) \
{                                                                      \
	match_backend_register(&b);                                        \
}                                                                      \

/**
 * Open and initialize a backend.
 *
 * @param name
 *   The name of the backend to open.
 * @param init_arg
 *   An opaque pointer to pass to the backend.
 *
 * @return
 *   A pointer to the backend on success, or NULL on failure.
 */
struct match_backend *match_backend_open(const char *name, void *init_arg);

/**
 * Close a backend.
 *
 * @param backend
 *   A pointer to the backend to close.
 */
void match_backend_close(struct match_backend *backend);

/**
 * Print names of all available backends.
 */
void match_backend_list_all(void);

/**
 * Iterate through available backends.
 *
 * This function can be used to programmatically discover and iterate
 * through the list of available backend names.
 *
 * @param cookie
 *   A placeholder to store the previous backend. Initially the value of
 *   cookie should be NULL. This function will store a pointer to the
 *   backend in cookie. Subsequent calls should pass the same cookie so
 *   so this function knows to get the next backend after the one which
 *   is referenced by cookie.
 * @return
 *   The name of the next backend, or NULL if there are no more backends.
 */
const char *match_backend_get_next(void **cookie);

#endif /* _BACKEND_H */
