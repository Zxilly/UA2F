#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include "config.h"
#include "nssocket.h"

int fdpair[2];
#define PARENT_FD (fdpair[0])
#define CHILD_FD (fdpair[1])

pid_t child_pid;

void add_child(pid_t pid)
{
	/* XXX: check excess MAX_CHILD */
	children[nchild++] = pid;
}

static int get_unaligned_int(const void *s)
{
	int x;
	memcpy(&x, s, sizeof(x));
	return x;
}

static void put_unaligned_int(void *d, int x)
{
	memcpy(d, &x, sizeof(x));
}

/*
 * message exchange via socketpair using send/recv msg()
 *
 * - use cdata:
 *   cdata represents a file descriptor
 *   cmd[0] means -errno
 *
 * - without cdata:
 *   cmd[0] means:
 *   > 0:  command
 *   == 0: sync, echo
 *   < 0:  -errno
 *
 * it's an given fact that tx() and rx() never fail.
 */
ssize_t tx(int fd, int *cmd, uint8_t cmdlen, int cdata)
{
	struct msghdr msg;
	struct iovec iov[cmdlen];
	size_t cmsglen = CMSG_SPACE(sizeof(int));
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	int i;

	memset(&msg, 0, sizeof(struct msghdr));
	memset(iov, 0, sizeof(struct iovec) * cmdlen);

	msg.msg_iov = iov;
	msg.msg_iovlen = cmdlen;
	for (i = 0; i < cmdlen; i++) {
		iov[i].iov_len = sizeof(int);
		iov[i].iov_base = &cmd[i];
	}
	if (cdata) {
		msg.msg_control = control;
		msg.msg_controllen = cmsglen;
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		put_unaligned_int(CMSG_DATA(cmsg), cdata);
	}

	return sendmsg(fd, &msg, 0);
}

ssize_t rx(int fd, int *cmd, uint8_t cmdlen, int *cdata)
{
	struct msghdr msg;
	struct iovec iov[cmdlen];
	size_t cmsglen = CMSG_SPACE(sizeof(int));
	char control[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	ssize_t ret;
	int i;

	memset(&msg, 0, sizeof(struct msghdr));
	memset(iov, 0, sizeof(struct iovec));

	msg.msg_iov = iov;
	msg.msg_iovlen = cmdlen;
	for (i = 0; i < cmdlen; i++) {
		iov[i].iov_len = sizeof(int);
		iov[i].iov_base = &cmd[i];
	}
	if (cdata != NULL) {
		msg.msg_control = control;
		msg.msg_controllen = cmsglen;
	}

	ret = recvmsg(fd, &msg, 0);
	if (ret == -1) {
		perror("recvmsg");
		return ret;
	}

	if (cdata == NULL)
		return ret;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(int))
	    || cmsg->cmsg_level != SOL_SOCKET
	    || cmsg->cmsg_type != SCM_RIGHTS) {
		errno = EBADMSG;
		return -1;
	}
	*cdata = get_unaligned_int(CMSG_DATA(cmsg));

	return ret;
}

int tx_cmd(int fd, int cmd)
{
	return tx(fd, &cmd, 1, 0);
}

int rx_cmd(int fd)
{
	int cmd;
	if (rx((fd), &cmd, 1, NULL) == -1)
		return -1;
	return cmd;
}

int tx_fd(int fd1, int fd2, int e)
{
	return tx(fd1, &e, 1, fd2);
}

int rx_fd(int fd1)
{
	int e, fd2;

	if (rx(fd1, &e, 1, &fd2) == -1)
		return -1;

	errno = -e;
	return fd2;
}

/*
 * copy from ip/ipnetns.c::iproute2
 */
#ifndef HAVE_SETNS
#include <sys/syscall.h>
static int setns(int fd, int nstype)
{
#ifdef __NR_setns
	return syscall(__NR_setns, fd, nstype);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif /* HAVE_SETNS */

#define NETNS_RUN_DIR "/var/run/netns"
static int netns_setup(const char *name)
{
	/* Setup the proper environment for apps that are not netns
	 * aware, and execute a program in that environment.
	 */
	char net_path[MAXPATHLEN];
	int netns;

	snprintf(net_path, sizeof(net_path), "%s/%s", NETNS_RUN_DIR, name);
	netns = open(net_path, O_RDONLY | O_CLOEXEC);
	if (netns < 0) {
		fprintf(stderr, "Cannot open network namespace \"%s\": %s\n",
			name, strerror(errno));
		return -1;
	}

	if (setns(netns, CLONE_NEWNET) < 0) {
		fprintf(stderr, "setting the network namespace \"%s\" failed: %s\n",
			name, strerror(errno));
		return -1;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		fprintf(stderr, "unshare failed: %s\n", strerror(errno));
		return -1;
	}
	/* Don't let any mounts propagate back to the parent */
	if (mount("", "/", "none", MS_SLAVE | MS_REC, NULL)) {
		fprintf(stderr, "\"mount --make-rslave /\" failed: %s\n",
			strerror(errno));
		return -1;
	}
	/* Mount a version of /sys that describes the network namespace */
	if (umount2("/sys", MNT_DETACH) < 0) {
		fprintf(stderr, "umount of /sys failed: %s\n", strerror(errno));
		return -1;
	}
	if (mount(name, "/sys", "sysfs", 0, NULL) < 0) {
		fprintf(stderr, "mount of /sys failed: %s\n",strerror(errno));
		return -1;
	}

	return 0;
}

static void child(const char *nsname)
{
	int cmd = CMD_SYNC;
	int params[3]; /* XXX: magic number, see enum CALL_ */
	int sockfd;

	if (netns_setup(nsname) == -1)
		child_exit("netns_setup", EXIT_FAILURE);

	/* sync with parent */
	if (tx_cmd(CHILD_FD, CMD_SYNC) == -1)
		child_exit("tx_cmd", EXIT_FAILURE);

	/* waiting cmd */
	while (1) {
		debug_ns("child waiting for cmd...\n");
		cmd = rx_cmd(CHILD_FD);
		switch (cmd) {
		case CMD_DONE:
			debug_ns("child received CMD_DONE - exiting\n");
			close(CHILD_FD);
			child_exit("receive CMD_DONE", EXIT_SUCCESS);
			break;
		case CMD_SOCKET:
			if (rx(CHILD_FD, params, 3, NULL) == -1)
				child_exit("rx", EXIT_FAILURE);
			debug_ns("child received CMD_SOCKET -"
				 " domain: %d, type: %d, protocol: %d\n",
				 params[0], params[1], params[2]);
			sockfd = socket(params[0], params[1], params[2]);
			if (tx_fd(CHILD_FD, sockfd, -errno) == -1)
				child_exit("tx_fd", EXIT_FAILURE);
			break;
		default:
			debug_ns("child received unknown cmd: %d\n", cmd);
			child_exit("receive unknown cmd", EXIT_FAILURE);
			break;
		}
	}
}

/*
 * kill all the other registered child by SIGKILL
 *
 * SIGCHLD will not be raised if child has killed in SIGABRT handler
 */
static void sigchld_handler(int signum)
{
	pid_t pid;
	int status, i, fail = 0;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		debug_ns("receive SIGCHLD - pid: %d\n", pid);
		if (WIFEXITED(status))
			fail |= WEXITSTATUS(status);
		else if (WIFSIGNALED(status) || WCOREDUMP(status))
			fail |= status;
		if (pid == child_pid)
			child_pid = 0;
		for (i = 0; i < nchild; i++)
			if (children[i] == pid)
				children[i] = 0;
			else
				kill(children[i], SIGKILL);
	}
	if (pid == -1 && errno != ECHILD)
		fail |= errno;

	/* overdoing? kill myself
	 * if (fail) kill(0, SIGKILL);
	 */
}

/*
 * core public API
 */
int init_nssocket(const char *nsname)
{
	pid_t pid;
	struct sigaction sa;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fdpair) == -1)
		return -1;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sigchld_handler;
	sa.sa_flags = SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		return -1;

	fflush(stdout);
	pid = fork();
	switch (pid) {
	case -1:
		return -1;
		break;
	case 0:
		child(nsname); /* not return */
		break;
	default:
		child_pid = pid;
		add_child(pid);
		if (rx_cmd(PARENT_FD) < 0) {
			parent_fail("rx_cmd");
			return -1;
		}
		break;
	}

	return 0;
}

int fini_nssocket(void)
{
	int status;
	sigset_t block_mask;
	pid_t pid;

	sigemptyset(&block_mask);
	sigaddset(&block_mask, SIGCHLD);
	if (sigprocmask(SIG_SETMASK, &block_mask, NULL) == -1)
		return -1;
	tx_cmd(PARENT_FD, CMD_DONE);
	close(PARENT_FD);
	pid = waitpid(child_pid, &status, 0);
	child_pid = 0;
	if (pid < 0)
		return -1;
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;

	return status;
}

int nssocket(int domain, int type, int protocol)
{
	int cmd[] = {CMD_SOCKET, domain, type, protocol};

	if (child_pid == 0 || kill(child_pid, 0) == -1) {
		errno = ECHILD;
		return -1;
	}
	tx(PARENT_FD, cmd, 4, 0);
	return rx_fd(PARENT_FD);
}

/*
 * utils API
 */
int debug_nfct_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct;
	uint32_t type = NFCT_T_UNKNOWN;
	char buf[4096];

	switch(nlh->nlmsg_type & 0xFF) {
	case IPCTNL_MSG_CT_NEW:
		if (nlh->nlmsg_flags & (NLM_F_CREATE|NLM_F_EXCL))
			type = NFCT_T_NEW;
		else
			type = NFCT_T_UPDATE;
		break;
	case IPCTNL_MSG_CT_DELETE:
		type = NFCT_T_DESTROY;
		break;
	}

	ct = nfct_new();
	if (ct == NULL)
		return MNL_CB_OK;

	nfct_nlmsg_parse(nlh, ct);
	nfct_snprintf(buf, sizeof(buf), ct, type, NFCT_O_DEFAULT, 0);
	debug("%s\n", buf);
	nfct_destroy(ct);

	return MNL_CB_OK;
}

struct mnl_socket *mnl_nssocket_open(int bus)
{
	int fd;
	struct mnl_socket *nl;

	fd = nssocket(AF_NETLINK, SOCK_RAW, bus);
	if (fd == -1)
		return NULL;

	nl = mnl_socket_fdopen(fd);
	if (nl == NULL) {
		close(fd);
		return NULL;
	}
	return nl;
}

/*
 * assert utilities
 */
struct nf_conntrack *author_new(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct;

	assert((nlh->nlmsg_type & 0xFF) == IPCTNL_MSG_CT_NEW);
	assert(nlh->nlmsg_flags == (NLM_F_CREATE | NLM_F_EXCL));
	ct = nfct_new();
	assert(ct != NULL);
	assert(nfct_nlmsg_parse((nlh), ct) == 0);
	assert_proto(ct, AF_INET, *(uint8_t *) data);
	assert_inaddr(ct, VETH_PARENT_ADDR, VETH_CHILD_ADDR);
	assert((nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_SEEN_REPLY) == 0);
	timeout.tv_sec = nfct_get_attr_u32(ct, ATTR_TIMEOUT) + 1;

	return ct;
}

struct nf_conntrack *author_update(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct;

	assert((nlh->nlmsg_type & 0xFF) == IPCTNL_MSG_CT_NEW);
	assert(nlh->nlmsg_flags == 0);
	ct = nfct_new();
	assert(ct != NULL);
	assert(nfct_nlmsg_parse((nlh), ct) == 0);
	assert_proto(ct, AF_INET, *(uint8_t *) data);
	assert_inaddr(ct, VETH_PARENT_ADDR, VETH_CHILD_ADDR);
	assert((nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_SEEN_REPLY));
	timeout.tv_sec = nfct_get_attr_u32(ct, ATTR_TIMEOUT) + 1;

	return ct;
}

struct nf_conntrack *author_destroy(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct;

	assert((nlh->nlmsg_type & 0xFF) == IPCTNL_MSG_CT_DELETE);
	assert(nlh->nlmsg_flags == 0);
	ct = nfct_new();
	assert(ct != NULL);
	assert(nfct_nlmsg_parse((nlh), ct) == 0);
	assert_proto(ct, AF_INET, *(uint8_t *) data);
	assert_inaddr(ct, VETH_PARENT_ADDR, VETH_CHILD_ADDR);
	assert((nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_SEEN_REPLY));

	return ct;
}

void assert_proto(const struct nf_conntrack *ct,
		  uint8_t l3proto, uint8_t l4proto)
{
	assert(nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) == l3proto);
	assert(nfct_get_attr_u8(ct, ATTR_REPL_L3PROTO) == l3proto);
	assert(nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO) == l4proto);
	assert(nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO) == l4proto);
}

void assert_inaddr(const struct nf_conntrack *ct,
		   const char *src, const char *dst)
{
	struct in_addr addr;
	assert(inet_aton((src), &addr) != 0);
	assert(nfct_get_attr_u32((ct), ATTR_ORIG_IPV4_SRC) == addr.s_addr);
	assert(nfct_get_attr_u32((ct), ATTR_REPL_IPV4_DST) == addr.s_addr);
	assert(inet_aton((dst), &addr) != 0);
	assert(nfct_get_attr_u32((ct), ATTR_ORIG_IPV4_DST) == addr.s_addr);
	assert(nfct_get_attr_u32((ct), ATTR_REPL_IPV4_SRC) == addr.s_addr);
}

void assert_port(const struct nf_conntrack *ct,
		 uint16_t src, uint16_t dst)
{
	if ((src)) {
		assert(nfct_get_attr_u16((ct), ATTR_ORIG_PORT_SRC) == htons((src)));
		assert(nfct_get_attr_u16((ct), ATTR_REPL_PORT_DST) == htons((src)));
	}
	if ((dst)) {
		assert(nfct_get_attr_u16((ct), ATTR_ORIG_PORT_DST) == htons((dst)));
		assert(nfct_get_attr_u16((ct), ATTR_REPL_PORT_SRC) == htons((dst)));
	}
}

void assert_typecode(const struct nf_conntrack *ct,
		     uint8_t type, uint8_t code)
{
	assert(nfct_get_attr_u8((ct), ATTR_ICMP_TYPE) == type);
	assert(nfct_get_attr_u8((ct), ATTR_ICMP_CODE) == code);
}

int cb_icmp_new(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_new(nlh, data);
	assert_typecode(ct, ICMP_TYPE, ICMP_CODE);
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_icmp_update(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_update(nlh, data);
	assert_typecode(ct, ICMP_TYPE, ICMP_CODE);
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_icmp_destroy(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_destroy(nlh, data);
	assert_typecode(ct, ICMP_TYPE, ICMP_CODE);
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_udp_new(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_new(nlh, data);
	assert_port(ct, 0, DSTPORT);
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_udp_update(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_update(nlh, data);
	assert_port(ct, 0, DSTPORT);
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_udp_destroy(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_destroy(nlh, data);
	assert_port(ct, 0, DSTPORT);
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_tcp_new(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_new(nlh, data);
	assert_port(ct, 0, DSTPORT);
	assert(nfct_get_attr_u8(ct, ATTR_TCP_STATE) == TCP_CONNTRACK_SYN_SENT);
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_tcp_syn_recv(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_update(nlh, data);
	assert_port(ct, 0, DSTPORT);
	assert(nfct_get_attr_u8(ct, ATTR_TCP_STATE) == TCP_CONNTRACK_SYN_RECV);
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_tcp_established(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_update(nlh, data);
	assert_port(ct, 0, DSTPORT);
	assert(nfct_get_attr_u8(ct, ATTR_TCP_STATE) == TCP_CONNTRACK_ESTABLISHED);
	assert((nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_ASSURED));
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_tcp_fin_wait(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_update(nlh, data);
	assert_port(ct, 0, DSTPORT);
	assert(nfct_get_attr_u8(ct, ATTR_TCP_STATE) == TCP_CONNTRACK_FIN_WAIT);
	assert((nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_ASSURED));
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_tcp_close_wait(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_update(nlh, data);
	assert_port(ct, 0, DSTPORT);
	assert(nfct_get_attr_u8(ct, ATTR_TCP_STATE) == TCP_CONNTRACK_CLOSE_WAIT);
	assert((nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_ASSURED));
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_tcp_close(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_update(nlh, data);
	assert_port(ct, 0, DSTPORT);
	assert(nfct_get_attr_u8(ct, ATTR_TCP_STATE) == TCP_CONNTRACK_CLOSE);
	assert((nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_ASSURED));
	nfct_destroy(ct);
	return MNL_CB_OK;
}

int cb_tcp_destroy(const struct nlmsghdr *nlh, void *data)
{
	struct nf_conntrack *ct = author_destroy(nlh, data);
	assert_port(ct, 0, DSTPORT);
	assert(nfct_attr_is_set(ct, ATTR_TCP_STATE) == 0);
	assert((nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_ASSURED));
	nfct_destroy(ct);
	return MNL_CB_OK;
}

void tcp_echo(const struct mnl_socket *nl,
	      const char *pre, const char *post)
{
	uint8_t proto = IPPROTO_TCP;

	sync_fifo(pre);
	timeout.tv_sec = INIT_TIMEOUT;
	handle_qacb(nl, true, cb_tcp_new, &proto);
	handle_qacb(nl, true, cb_tcp_syn_recv, &proto);
	handle_qacb(nl, true, cb_tcp_established, &proto);
	handle_qacb(nl, true, cb_tcp_fin_wait, &proto);
	handle_qacb(nl, true, cb_tcp_close_wait, &proto);
	handle_qacb(nl, true, cb_tcp_close, &proto);
	handle_qacb(nl, true, cb_tcp_destroy, &proto);
	handle_qacb(nl, false, NULL, NULL);
	sync_fifo(post);
}

int handle_qacb(const struct mnl_socket *nl, bool should_receive,
		int(*cb)(const struct nlmsghdr *nlh, void *data), void *data)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	fd_set rfds;
	int ret, fd = mnl_socket_get_fd(nl);
	bool receive_nfnl;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	if (select(fd + 1, &rfds, NULL, NULL, &timeout) < 0)
		child_exit("select", EXIT_FAILURE);
	receive_nfnl = FD_ISSET(fd, &rfds);
	if (should_receive) {
		assert(receive_nfnl == true);
	} else {
		assert(receive_nfnl == false);
		return MNL_CB_ERROR;
	}

	ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	if (ret == -1)
		child_exit("mnl_socket_recvfrom", EXIT_FAILURE);
	mnl_cb_run(buf, ret, 0, 0, debug_nfct_cb, NULL);
	if (cb != NULL) {
		ret = mnl_cb_run(buf, ret, 0, 0, cb, data);
		if (ret == -1)
			child_exit("mnl_cb_run", EXIT_FAILURE);
		return ret;
	}

	return MNL_CB_OK;
}

static void sigabrt_handler(int signum)
{
	fini_nssocket();
}

struct mnl_socket *mnl_event_nssocket(const char *nsname)
{
	struct mnl_socket *nl;
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = sigabrt_handler;
	if (sigaction(SIGABRT, &sa, NULL) == -1)
		return NULL;

	if (init_nssocket(nsname) == -1)
		return NULL;

	nl = mnl_nssocket_open(NETLINK_NETFILTER);
	if (nl == NULL)
		return NULL;
	if (mnl_socket_bind(nl, NF_NETLINK_CONNTRACK_NEW |
			    NF_NETLINK_CONNTRACK_UPDATE |
			    NF_NETLINK_CONNTRACK_DESTROY,
			    MNL_SOCKET_AUTOPID) < 0) {
		parent_fail("mnl_socket_bind");
		mnl_socket_close(nl);
		return NULL;
	}

	return nl;
}

void sync_fifo(const char *name)
{
	struct stat statbuf;
	int fd = open(name, O_WRONLY);
	if (fd == -1) {
		parent_fail("open fifo");
		exit(EXIT_FAILURE);
	}
	if (fstat(fd, &statbuf) == -1) {
		parent_fail("fstat fifo");
		exit(EXIT_FAILURE);
	}
	if (!S_ISFIFO(statbuf.st_mode)) {
		parent_fail("S_ISFIFO");
		exit(EXIT_FAILURE);
	}
	close(fd);
}
