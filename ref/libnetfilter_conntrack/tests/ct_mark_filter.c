#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "nssocket.h"

static void tcp_echo_before_fin(const struct mnl_socket *nl,
			       const char *pre, const char *post)
{
	uint8_t proto = IPPROTO_TCP;

	sync_fifo(pre);
	timeout.tv_sec = INIT_TIMEOUT;
	handle_qacb(nl, true, cb_tcp_new, &proto);
	handle_qacb(nl, true, cb_tcp_syn_recv, &proto);
	handle_qacb(nl, true, cb_tcp_established, &proto);
	handle_qacb(nl, false, NULL, NULL);
	sync_fifo(post);
}

static void tcp_echo_after_fin(const struct mnl_socket *nl,
			       const char *pre, const char *post)
{
	uint8_t proto = IPPROTO_TCP;

	sync_fifo(pre);
	timeout.tv_sec = INIT_TIMEOUT;
	handle_qacb(nl, true, cb_tcp_fin_wait, &proto);
	handle_qacb(nl, true, cb_tcp_close_wait, &proto);
	handle_qacb(nl, true, cb_tcp_close, &proto);
	handle_qacb(nl, true, cb_tcp_destroy, &proto);
	handle_qacb(nl, false, NULL, NULL);
	sync_fifo(post);
}

static void filter_mark_zero(const struct mnl_socket *nl,
			     const char *pre, const char *post)
{
	struct nfct_filter *filter = nfct_filter_create();
	struct nfct_filter_dump_mark mark = {val: 0, mask: 0};

	nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &mark);
	assert(nfct_filter_attach(mnl_socket_get_fd(nl), filter) != -1);
	nfct_filter_destroy(filter);
	tcp_echo(nl, pre, post);
	assert(nfct_filter_detach(mnl_socket_get_fd(nl)) != -1);
}

static void filter_mark_1_1(const struct mnl_socket *nl,
			    const char *pre, const char *post)
{
	struct nfct_filter *filter = nfct_filter_create();
	struct nfct_filter_dump_mark mark = {val: 1, mask: 1};

	nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &mark);
	assert(nfct_filter_attach(mnl_socket_get_fd(nl), filter) != -1);
	nfct_filter_destroy(filter);
	tcp_echo_after_fin(nl, pre, post);
	assert(nfct_filter_detach(mnl_socket_get_fd(nl)) != -1);
}

static void filter_mark_neg_1_1(const struct mnl_socket *nl,
				const char *pre, const char *post)
{
	struct nfct_filter *filter = nfct_filter_create();
	struct nfct_filter_dump_mark mark = {val: 1, mask: 1};

	nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &mark);
	assert(nfct_filter_set_logic(filter, NFCT_FILTER_MARK,
				     NFCT_FILTER_LOGIC_NEGATIVE) != -1);
	assert(nfct_filter_attach(mnl_socket_get_fd(nl), filter) != -1);
	nfct_filter_destroy(filter);
	tcp_echo_before_fin(nl, pre, post);
	assert(nfct_filter_detach(mnl_socket_get_fd(nl)) != -1);
}

static void filter_mark_neg_0_fffffffd(const struct mnl_socket *nl,
				       const char *pre, const char *post)
{
	struct nfct_filter *filter = nfct_filter_create();
	struct nfct_filter_dump_mark mark = {val: 0, mask: 0xfffffffd};

	nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &mark);
	assert(nfct_filter_set_logic(filter, NFCT_FILTER_MARK,
				     NFCT_FILTER_LOGIC_NEGATIVE) != -1);
	assert(nfct_filter_attach(mnl_socket_get_fd(nl), filter) != -1);
	nfct_filter_destroy(filter);
	tcp_echo_after_fin(nl, pre, post);
	assert(nfct_filter_detach(mnl_socket_get_fd(nl)) != -1);
}

static void filter_mark_max(const struct mnl_socket *nl,
			    const char *pre, const char *post)
{
	struct nfct_filter *filter = nfct_filter_create();
	struct nfct_filter_dump_mark mark;
	int i;

	for (i = 0; i < 126; i++) {
		/* does not match to mark value 3 */
		mark = (struct nfct_filter_dump_mark){val: 0, mask: 3};
		nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &mark);
	}

	/* __FILTER_MARK_MAX      127, should be added */
	mark = (struct nfct_filter_dump_mark){val: 1, mask: 1};
	nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &mark);

	/* over __FILTER_MARK_MAX, should be ignored */
	mark = (struct nfct_filter_dump_mark){val: 0, mask: 0};
	nfct_filter_add_attr(filter, NFCT_FILTER_MARK, &mark);

	assert(nfct_filter_attach(mnl_socket_get_fd(nl), filter) != -1);
	nfct_filter_destroy(filter);
	tcp_echo_after_fin(nl, pre, post);
	assert(nfct_filter_detach(mnl_socket_get_fd(nl)) != -1);
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char *pre, *post;

	if (argc != 4) {
		fprintf(stderr, "usage: %s <netns> <pre_fifo> <post_fifo>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	pre = argv[2];
	post = argv[3];

	nl = mnl_event_nssocket(argv[1]);
	if (nl == NULL) {
		perror("init_mnl_socket");
		exit(EXIT_FAILURE);
	}

	filter_mark_zero(nl, pre, post);
	filter_mark_1_1(nl, pre, post);
	filter_mark_neg_1_1(nl, pre, post);
	filter_mark_neg_0_fffffffd(nl, pre, post);
	filter_mark_max(nl, pre, post);

	return fini_nssocket();
}
