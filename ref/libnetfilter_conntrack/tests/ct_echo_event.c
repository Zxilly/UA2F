#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>

#include <libmnl/libmnl.h>

#include "nssocket.h"

static void udp_echo(const struct mnl_socket *nl,
		     const char *pre, const char *post)
{
	uint8_t proto = IPPROTO_UDP;

	sync_fifo(pre);
	timeout.tv_sec = INIT_TIMEOUT;
	handle_qacb(nl, true, cb_udp_new, &proto);
	handle_qacb(nl, true, cb_udp_update, &proto);
	handle_qacb(nl, true, cb_udp_destroy, &proto);
	handle_qacb(nl, false, NULL, NULL);
	sync_fifo(post);
}

static void icmp_echo(const struct mnl_socket *nl,
		      const char *pre, const char *post)
{
	uint8_t proto = IPPROTO_ICMP;

	sync_fifo(pre);
	timeout.tv_sec = INIT_TIMEOUT;
	handle_qacb(nl, true, cb_icmp_new, &proto);
	handle_qacb(nl, true, cb_icmp_update, &proto);
	handle_qacb(nl, true, cb_icmp_destroy, &proto);
	handle_qacb(nl, false, NULL, NULL);
	sync_fifo(post);
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

	tcp_echo(nl, pre, post);
	udp_echo(nl, pre, post);
	icmp_echo(nl, pre, post);

	return fini_nssocket();
}
