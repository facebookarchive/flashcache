#!/bin/sh -e
# mkinitramfs hook for flashcache

PREREQ="mdadm"

prereqs () {
	echo "$PREREQ"
}

case $1 in
prereqs)
	prereqs
	exit 0
	;;
esac

. /usr/share/initramfs-tools/hook-functions

manual_add_modules flashcache
copy_exec /sbin/flashcache_load /sbin
copy_exec /sbin/flashcache_create /sbin
copy_exec /sbin/flashcache_destroy /sbin

exit 0
