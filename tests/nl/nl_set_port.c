#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "if_match.h"
#include "matchlib.h"
#include "matchlib_nl.h"

static int set_port_id_too_big(void)
{
	struct net_mat_port port;

	memset(&port, 0, sizeof(port));
	port.port_id = 600;

	return match_nl_set_port(match_nl_get_socket(), match_pid_lookup(), 0,
	                         NET_MAT_DFLT_FAMILY, &port);
}

static int set_port_id_unspec(void)
{
	struct net_mat_port port;

	memset(&port, 0, sizeof(port));
	port.port_id = NET_MAT_PORT_ID_UNSPEC;

	return match_nl_set_port(match_nl_get_socket(), match_pid_lookup(), 0,
	                         NET_MAT_DFLT_FAMILY, &port);
}

struct set_port_test {
	const char *fname;
	int (*func)(void);
	int expected;
	int actual;
};

#define _stringify(x) stringify(x)
#define stringify(x) #x
#define TEST(func, e) { stringify(func), func, e, -1 }

struct set_port_test tests[] = {
	TEST(set_port_id_too_big, -EINVAL),
	TEST(set_port_id_unspec, 0),
};

static int run_test(struct set_port_test *test)
{
	test->actual = test->func();

	if (test->actual != test->expected)
		fprintf(stderr,
		        "FAIL: %s(), expected %d, actual %d\n",
		        test->fname, test->expected, test->actual);
	else
		fprintf(stderr,
		        "PASS: %s(), expected %d, actual %d\n",
		        test->fname, test->expected, test->actual);

	return !(test->actual == test->expected);
}

int main(void)
{
	int i;
	int count = 0;

	for (i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); ++i)
		count += run_test(&tests[i]);

	if (count)
		fprintf(stderr,
		        "%d out of %d tests failed\n", count,
		        (int)(sizeof(tests) / sizeof(tests[0])));
	else
		fprintf(stderr,
		        "All %d tests passed\n",
		        (int)(sizeof(tests) / sizeof(tests[0])));

	return 0;
}
