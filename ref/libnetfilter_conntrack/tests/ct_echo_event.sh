#!/bin/sh

. `dirname $0`/nssocket_env.sh

echo "---- TCP echo"
pre_sync
echo | nc -q 0 $VETH_CHILD_ADDR $DSTPORT
post_sync

echo "---- UDP echo"
pre_sync
echo | nc -q 0 -u $VETH_CHILD_ADDR $DSTPORT
post_sync

echo "---- ICMP echo"
pre_sync
ping -c 1 $VETH_CHILD_ADDR > /dev/null 2>&1
post_sync

fin
