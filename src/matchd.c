/*******************************************************************************
  matchd - match action table daemon
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
#include <sys/stat.h>
#include <fcntl.h>

#include <getopt.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/cli/utils.h>

#include <unistd.h>

#include "if_match.h"
#include "ieslib.h" /* ies interface */
#include "matchd_lib.h"
#include "backend.h"
#include "matlog.h"

#define DEFAULT_BACKEND_NAME "ies_pipeline"

static void matchd_usage(void)
{
	MAT_LOG(ERR, "matchd [-b backend] [-f family_id] [-h] [-l] [-s]\n");
	MAT_LOG(ERR, "Options:\n");
	MAT_LOG(ERR, "  -b backend    name of backend to load (default: %s)\n", DEFAULT_BACKEND_NAME);
	MAT_LOG(ERR, "  -d            run as a daemon\n");
	MAT_LOG(ERR, "  -f family_id  netlink family id\n");
	MAT_LOG(ERR, "  -h            display this help and exit\n");
	MAT_LOG(ERR, "  -l            list available backends and exit\n");
	MAT_LOG(ERR, "  -s            add all ports to default vlan (ies_pipeline only)\n");
	MAT_LOG(ERR, "  -v            be verbose (enable info messages)\n");
	MAT_LOG(ERR, "  -vv           be very verbose (enable info+debug messages)\n");
}

static int matchd_create_pid(void)
{
	pid_t pid = getpid();
	char buf[1024];
	int err, fd;
	ssize_t ret;
	char pidfile[1024] = MATCHLIB_PID_FILE;
	struct flock fl = { .l_type = F_WRLCK,
			    .l_whence = SEEK_SET,
			    .l_start = 0,
			    .l_len = 0};

	errno = 0;
	fd = open(pidfile, O_CLOEXEC | O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		perror("Cannot create pidfile\n");
		return errno;
	}

	errno = 0;
	err = fcntl(fd, F_SETLKW, &fl);
	if (err) {
		perror("Error setting F_SETLKW\n");
		close(fd);
		return errno;
	}

	errno = 0;
	err = ftruncate(fd, 0);
	if (err) {
		perror("ftruncate pidfile error\n");
		close(fd);
		return errno;
	}

	snprintf(buf, sizeof(buf), "%ld\n", (long) pid);
	errno = 0;
	ret = write(fd, buf, strlen(buf));
	if (ret < 0) {
		perror("Write pidfile error\n");
		close(fd);
		return errno;
	}

	close(fd);
	return 0;
}

static void matchd_int_handler(int sig __unused)
{
	MAT_LOG(DEBUG, "\nmatchd exiting...\n");

	matchd_uninit();

	if (remove(MATCHLIB_PID_FILE)) {
		MAT_LOG(ERR, "Cannot remove %s, exiting anyway\n",
		        MATCHLIB_PID_FILE);
	}

	exit(0);
}

int main(int argc, char **argv)
{
	struct nl_sock *nsd;
	int family = NET_MAT_DFLT_FAMILY;
	struct sockaddr_nl dest_addr;
	size_t rcv_size = 2048;
	unsigned char *buf;
	int rc = EXIT_SUCCESS;
	int err, opt;
	const char *backend = NULL;
	struct switch_args sw_args;
	struct sigaction sig_act;
	int verbose = 0;

	memset(&sw_args, 0, sizeof(sw_args));

	while ((opt = getopt(argc, argv, "b:f:vhls")) != -1) {
		switch (opt) {
		case 'b':
			backend = optarg;
			break;
		case 'f':
			family = atoi(optarg);
			break;
		case 'h':
			matchd_usage();
			exit(-1);
		case 'l':
			match_backend_list_all();
			exit(0);
		case 's':
			sw_args.single_vlan = true;
			break;
		case 'v':
			++verbose;
			break;
		default:
			matchd_usage();
			exit(-1);
		}
	}

	if (verbose > 1)
		mat_setlogmask(MAT_LOG_UPTO(MAT_LOG_DEBUG));
	else if (verbose > 0)
		mat_setlogmask(MAT_LOG_UPTO(MAT_LOG_INFO));
	else
		mat_setlogmask(MAT_LOG_UPTO(MAT_LOG_ERR));

	nsd = nl_socket_alloc();
	nl_socket_set_local_port(nsd, (uint32_t)getpid());
	nl_connect(nsd, NETLINK_GENERIC);

	if (backend == NULL)
		backend = DEFAULT_BACKEND_NAME;

	rc = matchd_init(nsd, family, backend, &sw_args);
	if (rc) {
		MAT_LOG(ERR, "Error: cannot init matchd\n");
		exit(-1);
	}

	err = matchd_create_pid();
	if (err) {
		MAT_LOG(ERR, "matchd create pid failed\n");
		exit(-1);
	}

	sig_act.sa_handler = matchd_int_handler;
	sigaction(SIGINT, &sig_act, NULL);
	sigaction(SIGTERM, &sig_act, NULL);

	while (1) {
		MAT_LOG(DEBUG, "Waiting for message\n");
		rc = nl_recv(nsd, &dest_addr, &buf, NULL);
		if(rc < 0) {
			printf("%s:receive error on netlink socket:%d\n",
				__func__, errno);
			rc = EXIT_FAILURE;
			break;
		}
		/*printf("%s:recvfrom received %d bytes from pid %d\n",
			__func__, rc, dest_addr.nl_pid); */

		err = matchd_rx_process((struct nlmsghdr *)buf);
		if (err < 0)
			MAT_LOG(ERR, "%s: Warning: parsing error\n",
					__func__);
		memset(buf, 0, rcv_size);
	}
	
	matchd_uninit();

	nl_close(nsd);
	nl_socket_free(nsd);
	return rc;
}
