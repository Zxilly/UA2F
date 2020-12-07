#!/bin/sh -e

include ()
{
    # If we keep a copy of the kernel header in the SVN tree, we'll have
    # to worry about synchronization issues forever. Instead, we just copy 
    # the headers that we need from the lastest kernel version at autogen
    # stage.

    INCLUDEDIR=${KERNEL_DIR:-/lib/modules/`uname -r`/build}/include/linux
    if [ -f $INCLUDEDIR/netfilter/nfnetlink_conntrack.h ]
    then
    	TARGET=include/libnetfilter_conntrack/linux_nfnetlink_conntrack.h
    	echo "Copying nfnetlink_conntrack.h to linux_nfnetlink_conntrack.h"
    	cp $INCLUDEDIR/netfilter/nfnetlink_conntrack.h $TARGET
	TEMP=`tempfile`
	sed 's/linux\/netfilter\/nfnetlink.h/libnfnetlink\/linux_nfnetlink.h/g' $TARGET > $TEMP
	mv $TEMP $TARGET
    else
    	echo "can't find nfnetlink_conntrack.h kernel file in $INCLUDEDIR"
    	exit 1
    fi
}

run ()
{
    echo "running: $*"
    eval $*

    if test $? != 0 ; then
	echo "error: while running '$*'"
	exit 1
    fi
}

[ "x$1" = "xdistrib" ] && include
autoreconf -fi
rm -Rf autom4te.cache
