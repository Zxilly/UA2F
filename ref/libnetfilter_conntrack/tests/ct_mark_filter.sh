#!/bin/sh

. `dirname $0`/nssocket_env.sh

echo "---- TCP echo with ctmark 0/0 [filter_mark_zero]"
pre_sync
echo | nc -q 0 $VETH_CHILD_ADDR $DSTPORT
post_sync

echo "---- iptables CONNMARK settings - ctmark tcp 2/2, tcp fin 1/1"
ip netns exec $NETNS sh <<EOF
    iptables -t mangle -I PREROUTING -p tcp -m tcp -j CONNMARK --set-mark 2/2
    iptables -t mangle -I PREROUTING -p tcp -m tcp --tcp-flags FIN FIN -j CONNMARK --set-mark 1/1
EOF

echo "---- TCP echo with mark filter 1/1 [filter_mark_1_1]"
pre_sync
echo | nc -q 0 $VETH_CHILD_ADDR $DSTPORT
post_sync

echo "---- TCP echo with mark filter ! 1/1 [filter_mark_neg_1_1]"
pre_sync
echo | nc -q 0 $VETH_CHILD_ADDR $DSTPORT
post_sync

echo "---- TCP echo with mark filter !0/fffffffd [filter_mark_neg_0_fffffffd]"
pre_sync
echo | nc -q 0 $VETH_CHILD_ADDR $DSTPORT
post_sync

echo "---- max mark filter entry [filter_mark_max]"
pre_sync
echo | nc -q 0 $VETH_CHILD_ADDR $DSTPORT
post_sync

fin
