#!/bin/sh
PREREQ="mdadm udev"
prereqs()
{
	echo "$PREREQ"
}

case $1 in
prereqs)
	prereqs
	exit 0
	;;
esac

. /scripts/functions

log_begin_msg	"Scanning for flashcache devices"
echo "Waiting for udev to settle..."
/sbin/udevadm settle --timeout=30

PARTITIONS=`cat /proc/partitions | awk '{ print $NF; }' | grep -v name`
for P in $PARTITIONS; do
	if /sbin/flashcache_load "/dev/$P"  2> /dev/null; then
		echo "Loaded flashcache device from /dev/$P"
	fi
done

log_end_msg "Flashcache scanning done."

exit 0
