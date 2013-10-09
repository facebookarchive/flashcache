# We need to make a (temporary) config file so the
# udev half can do something when it finds the right
# devices

# real_device:ssd_device:name[:mode]
# /dev/vda2:/dev/vdb:fc_vda2:thru
# if mode is not specified, 'thru' is used
# although back knows which real_device and name to use
# we still want to know so we can make sure the device is availale
# but has not already been started
for fc_conf in $(getargs rd_FLASHCACHE=); do

    #echo "FLASHCACHE for $conf"
    fc_dev="${fc_conf%%:*}"
    fc_conf="${fc_conf#*:}"
    fc_ssd="${fc_conf%%:*}"
    fc_conf="${fc_conf#*:}"
    fc_name="${fc_conf%%:*}"
    fc_conf="${fc_conf#*:}"
    if [ "$fc_conf" = "back" ] ; then
        fc_mode=back
    elif [ "$fc_conf" = "around" ] ; then
        fc_mode=around
    elif [ "$fc_conf" = "none" ] ; then
        fc_mode=none
    else
        fc_mode=thru
    fi

    echo "$fc_dev:$fc_ssd:$fc_name:$fc_mode" >> /etc/flashcache.conf

done
unset fc_dev
unset fc_ssd
unset fc_name
unset fc_mode
unset fc_conf

