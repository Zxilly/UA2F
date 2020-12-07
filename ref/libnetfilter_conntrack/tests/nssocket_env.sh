#!/bin/sh

NETNS="lnfct_qa"
VETH_NAME="veth_qa0"
VETH_PEER="veth_qa1"
DUMMY_DEV="dummy_qa0"
VETH_PARENT_ADDR="10.255.255.249"
VETH_CHILD_ADDR="10.255.255.250"
VETH_MASK="30"
DSTPORT="7"
ICMP_TYPE="8"
ICMP_CODE="0"
NF_TIMEOUT=2
INIT_TIMEOUT=8

dname=`dirname $0`
bname=`basename $0`
qname=${bname%.sh}

PRE_FIFO="$dname/qa_pre_fifo"
POST_FIFO="$dname/qa_post_fifo"

[ -z `which ip` ]       && echo "ip(8) required"    >&2 && exit 1
[ -z `which inetd` ]    && echo "inetd required"    >&2 && exit 1
[ -z `which nc` ]       && echo "nc required"       >&2 && exit 1
[ -z `which iptables` ] && echo "iptables required" >&2 && exit 1
modprobe nf_conntrack_ipv4	|| exit 1
modprobe nfnetlink_cttimeout	|| exit 1

make -C $dname \
    CFLAGS="-DVETH_PARENT_ADDR=\\\"$VETH_PARENT_ADDR\\\" \
            -DVETH_CHILD_ADDR=\\\"$VETH_CHILD_ADDR\\\" \
            -DDSTPORT=$DSTPORT -DICMP_TYPE=$ICMP_TYPE -DICMP_CODE=$ICMP_CODE \
            -DINIT_TIMEOUT=$INIT_TIMEOUT" \
    $qname || exit 1

# parent / client
ip netns add $NETNS
trap "ip netns del $NETNS; exit 1" 1 2 15
ip link ls $VETH_NAME > /dev/null 2>&1 && ip link del $VETH_NAME
ip link add $VETH_NAME type veth peer name $VETH_PEER
ip link set $VETH_PEER netns $NETNS
ip link set $VETH_NAME up
ip addr add ${VETH_PARENT_ADDR}/${VETH_MASK} dev $VETH_NAME

# child / server
ip netns exec $NETNS sh <<EOF
echo 1 > /proc/sys/net/ipv4/ip_forward
for f in /proc/sys/net/netfilter/*timeout*; do echo $NF_TIMEOUT > "\$f"; done
ip link set lo up
ip link set $VETH_PEER up
ip addr add ${VETH_CHILD_ADDR}/${VETH_MASK} dev $VETH_PEER
ip link add ${DUMMY_DEV} up type dummy
ip route add default dev ${DUMMY_DEV}
EOF
ip netns exec $NETNS inetd -d $dname/inetd.conf > /dev/null 2>&1 &
server_pid=$!

rm -f $PRE_FIFO $POST_FIFO
mkfifo $PRE_FIFO  || exit 1
mkfifo $POST_FIFO || exit 1

${dname}/${qname} $NETNS $PRE_FIFO $POST_FIFO &
qa_pid=$!

trap_handle() {
    rm -f $PRE_FIFO $POST_FIFO
    kill $server_pid > /dev/null 2>&1
    kill -6 $qa_pid > /dev/null 2>&1
    ip netns del $NETNS > /dev/null 2>&1
}
trap "trap_handle; exit 1" 1 2 15

fin() {
    wait $qa_pid
    trap_handle
}

pre_sync() {
    8< $PRE_FIFO || kill $$
    8>&-
}

post_sync() {
    8< $POST_FIFO || kill $$
    8>&-
}
