#ifndef _QA_NSSOCKET_H_
#define _QA_NSSOCKET_H_

#include <libmnl/libmnl.h>

/* ipc command */
enum {
	CMD_SYNC,
	CMD_SOCKET, /* int domain, int type, int protocol */
	CMD_DONE,
	CMD_ERREXIT,
};

int init_nssocket(const char *nsname);
int fini_nssocket(void);
int nssocket(int domain, int type, int protocol);
struct mnl_socket *mnl_nssocket_open(int bus);

ssize_t tx(int fd, int *cmd, uint8_t cmdlen, int cdata);
ssize_t rx(int fd, int *cmd, uint8_t cmdlen, int *cdata);
int tx_cmd(int fd, int cmd);
int rx_cmd(int fd);
int tx_fd(int fd1, int fd2, int e);
int rx_fd(int fd1);
int debug_nfct_cb(const struct nlmsghdr *nlh, void *data);

/* assert utilities */
struct nf_conntrack *author_new(const struct nlmsghdr *nlh, void *data);
struct nf_conntrack *author_update(const struct nlmsghdr *nlh, void *data);
struct nf_conntrack *author_destroy(const struct nlmsghdr *nlh, void *data);
void assert_proto(const struct nf_conntrack *ct,
		  uint8_t l3proto, uint8_t l4proto);
void assert_inaddr(const struct nf_conntrack *ct,
		   const char *src, const char *dst);
void assert_port(const struct nf_conntrack *ct,
		 uint16_t src, uint16_t dst);
void assert_typecode(const struct nf_conntrack *ct,
		     uint8_t type, uint8_t code);
int cb_icmp_new(const struct nlmsghdr *nlh, void *data);
int cb_icmp_update(const struct nlmsghdr *nlh, void *data);
int cb_icmp_destroy(const struct nlmsghdr *nlh, void *data);
int cb_udp_new(const struct nlmsghdr *nlh, void *data);
int cb_udp_update(const struct nlmsghdr *nlh, void *data);
int cb_udp_destroy(const struct nlmsghdr *nlh, void *data);
int cb_tcp_new(const struct nlmsghdr *nlh, void *data);
int cb_tcp_syn_recv(const struct nlmsghdr *nlh, void *data);
int cb_tcp_established(const struct nlmsghdr *nlh, void *data);
int cb_tcp_fin_wait(const struct nlmsghdr *nlh, void *data);
int cb_tcp_close_wait(const struct nlmsghdr *nlh, void *data);
int cb_tcp_close(const struct nlmsghdr *nlh, void *data);
int cb_tcp_destroy(const struct nlmsghdr *nlh, void *data);
void tcp_echo(const struct mnl_socket *nl,
	      const char *pre, const char *post);
int handle_qacb(const struct mnl_socket *nl, bool should_receive,
		int(*cb)(const struct nlmsghdr *nlh, void *data), void *data);
struct mnl_socket *mnl_event_nssocket(const char *nsname);
void sync_fifo(const char *name);


#define MAX_CHILD 64
pid_t children[MAX_CHILD]; /* kill if not 0 */
int nchild;
void add_child(pid_t pid);

/* tv_sec will update every cb */
struct timeval timeout;

#define parent_fail(msg) do {						\
	int i;								\
	fprintf(stderr, "parent fail - %s:%d %s() %s: %s\n",		\
		__FILE__, __LINE__, __func__, (msg), strerror(errno));	\
	for (i = 0; i < nchild; i++)					\
		if (children[i])					\
			kill(children[i], SIGKILL);			\
	} while (0)

#define child_exit(msg, code)						\
	do {								\
		if (code)						\
			fprintf(stderr, "child exiting - %s:%d %s() %s: %s\n", \
				__FILE__, __LINE__, __func__, (msg), strerror(errno)); \
		_exit((code));						\
	} while (0)

/* #define DEBUG_NS */
#define DEBUG

#ifdef DEBUG
#include <stdarg.h>
#define debug(...) do { fprintf(stderr, ##__VA_ARGS__); } while (0)
#else
#define debug(...)
#endif

#ifdef DEBUG_NS
#include <stdarg.h>
#define debug_ns(...) do { fprintf(stderr, ##__VA_ARGS__); } while (0)
#else
#define debug_ns(...)
#endif

#endif /* _QA_NSSOCKET_H_ */
