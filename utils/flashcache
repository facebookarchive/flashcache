#!/bin/bash
#
# flashcache	Init Script to manage cachedev loads
#
# chkconfig: 345 9 98
# description: Flashcache Management

# Flashcache options
# modify this before using this init script

SSD_DISK=
BACKEND_DISK=
CACHEDEV_NAME=
MOUNTPOINT=
FLASHCACHE_NAME=

# Just a check, to validate the above params are set
[ -z "$SSD_DISK" ] && exit 10
[ -z "$BACKEND_DISK" ] && exit 11
[ -z "$CACHEDEV_NAME" ] && exit 12
[ -z "$MOUNTPOINT" ] && exit 13
[ -z "$FLASHCACHE_NAME" ] && exit 14

# Source function library.
. /etc/rc.d/init.d/functions

#globals
DMSETUP=`/usr/bin/which dmsetup`
SERVICE=flashcache
FLASHCACHE_LOAD=/sbin/flashcache_load
SUBSYS_LOCK=/var/lock/subsys/$SERVICE

RETVAL=0

start() {
    echo "Starting Flashcache..."
    #Load the module
    /sbin/modprobe flashcache
    RETVAL=$?
    if [ $RETVAL -ne 0 ]; then
	echo "Module Load Error: flashcache. Exited with status - $RETVAL"
	exit $RETVAL
    fi
    #flashcache_load the cachedev
    $FLASHCACHE_LOAD $SSD_DISK $CACHEDEV_NAME
    RETVAL=$?
    if [ $RETVAL -ne 0 ]; then
	echo "Failed: flashcache_load $SSD_DISK $CACHEDEV_NAME"
	exit $RETVAL;
    fi
    #mount
    if [ -L /dev/mapper/$CACHEDEV_NAME ]; then
	/bin/mount /dev/mapper/$CACHEDEV_NAME $MOUNTPOINT
	RETVAL=$?
	if [ $RETVAL -ne 0 ]; then
	    echo "Mount Failed: /dev/mapper/$CACHEDEV_NAME to $MOUNTPOINT"
	    exit $RETVAL
	fi
    else
	echo "Not Found: /dev/mapper/$CACHEDEV_NAME"
	exit 1
    fi
    #lock subsys
    touch $SUBSYS_LOCK
}

stop() {
    #unmount
    /bin/umount $MOUNTPOINT
    #check for force flag
    FLAG=0
    [ "$1" == '--force' ] && FLAG=1
    /sbin/sysctl -w dev.flashcache.$FLASHCACHE_NAME.fast_remove=$FLAG
    echo "Flushing flashcache: Flushes to $BACKEND_DISK"
    $DMSETUP remove $CACHEDEV_NAME
    #unlock subsys
    rm -f $SUBSYS_LOCK
}

status() {
    [ -f $SUBSYS_LOCK ] && echo "Flashcache status: loaded" || echo "Flashcache status: NOT loaded";
    $DMSETUP status $CACHEDEV_NAME
    exit $?
}

case $1 in
    start)
	start
	;;
    stop)
	stop
	;;
    status)
	status
	;;
    forcestop)
	stop --force
	;;
    *)
	echo "Usage: $0 {start|stop|status}"
	exit 1
esac

exit 0
