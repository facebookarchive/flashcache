#!/bin/sh
#
# License:      GNU General Public License (GPL)
#
#   Resource Agent for highly available flashcache devices.
#   Requires installed flashcache kernel module and utilities.
#
#   (c) 2011 Florian Haas

# Initialization:
: ${OCF_FUNCTIONS_DIR=${OCF_ROOT}/resource.d/heartbeat}
. ${OCF_FUNCTIONS_DIR}/.ocf-shellfuncs

# Defaults
OCF_RESKEY_name_default="flashcache"
: ${OCF_RESKEY_name=${OCF_RESKEY_name_default}}

flashcache_usage() {
  echo "usage: $0 {start|stop|status|monitor|meta-data|validate-all}"
}

flashcache_meta_data() {
    cat <<EOF
<?xml version="1.0"?>
<!DOCTYPE resource-agent SYSTEM "ra-api-1.dtd">
<resource-agent name="flashcache" version="0.1">
  <version>0.1</version>
  <longdesc lang="en">
This resource agent manages a flashcache device, loading any existing
cache from the flash device on startup and flushing the cache to the
disk on graceful shutdown.
  </longdesc>
  <shortdesc lang="en">Manages a flashcache device map</shortdesc>
  <parameters>
    <parameter name="name" unique="1" required="0">
      <longdesc lang="en">
      The name of the flashcache device. This is the device map name
      that the agent instructs device-mapper to create, and must hence
      follow device-mapper naming restrictions.
      </longdesc>
      <shortdesc lang="en">Flashcache device name</shortdesc>
      <content type="string" default="${OCF_RESKEY_name_default}"/>
    </parameter>
    <parameter name="device" unique="0" required="1">
      <longdesc lang="en">
      The backing device to be used by flashcache. This is typically a
      comparatively high-latency but high-capacity block device, such
      as a rotational disk.
      </longdesc>
      <shortdesc lang="en">Backing device (typically a rotational
      disk)</shortdesc>
      <content type="string"/>
    </parameter>
    <parameter name="cache_device" unique="0" required="1">
      <longdesc lang="en">
      The cache device to be used by flashcache. This is typically a
      low-latency but limited-capacity block device, such
      as a solid-state disk.
      </longdesc>
      <shortdesc lang="en">Cache device (typically a solid state disk)</shortdesc>
      <content type="string"/>
    </parameter>
  </parameters>
  <actions>
    <action name="start"        timeout="60" />
    <action name="stop"         timeout="120" />
    <action name="monitor"      timeout="20"
                                interval="10" depth="0" />
    <action name="reload"       timeout="20" />
    <action name="meta-data"    timeout="5" />
    <action name="validate-all"   timeout="20" />
  </actions>
</resource-agent>
EOF
}

flashcache_start() {
    # exit immediately if configuration is not valid
    flashcache_validate_all || exit $?

    # if resource is already running, bail out early
    if flashcache_monitor; then
        ocf_log info "Resource is already running"
        return $OCF_SUCCESS
    fi

    # If the file exists here, but flashcache_monitor has determined
    # the resource isn't already running, then the file probably is
    # owned by something else. Bail out to avoid breaking things.
    if [ -e /dev/mapper/${OCF_RESKEY_name} ]; then
	ocf_log err "Existing file /dev/mapper/${OCF_RESKEY_name} would be overwritten by ${OCF_RESOURCE_INSTANCE}. Bailing out."
	exit $OCF_ERR_INSTALLED
    fi

    if [ ! -e /proc/flashcache/flashcache_version ]; then
	ocf_log debug "Flashcache support not loaded, loading module"
	ocf_run modprobe -v flashcache || exit $OCF_ERR_INSTALLED
    fi

    ocf_log debug "Flashcache module information obtained from kernel: `cat /proc/flashcache/flashcache_version`"

    # actually start up the resource here (make sure to immediately
    # exit with an $OCF_ERR_ error code if anything goes seriously
    # wrong)
    ocf_run flashcache_load ${OCF_RESKEY_cache_device} \
	 || exit $OCF_ERR_GENERIC

    # After the resource has been started, check whether it started up
    # correctly. If the resource starts asynchronously, the agent may
    # spin on the monitor function here -- if the resource does not
    # start up within the defined timeout, the cluster manager will
    # consider the start action failed
    while ! flashcache_monitor; do
        ocf_log debug "Resource has not started yet, waiting"
        sleep 1
    done

    # only return $OCF_SUCCESS if _everything_ succeeded as expected
    return $OCF_SUCCESS
}

flashcache_stop() {
    local rc

    # exit immediately if configuration is not valid
    flashcache_validate_all || exit $?

    flashcache_monitor
    rc=$?
    case "$rc" in
        "$OCF_SUCCESS")
            # Currently running. Normal, expected behavior.
            ocf_log debug "Resource is currently running"
            ;;
        "$OCF_NOT_RUNNING")
            # Currently not running. Nothing to do.
            ocf_log info "Resource is already stopped"
            return $OCF_SUCCESS
            ;;
    esac

    # actually shut down the resource here (make sure to immediately
    # exit with an $OCF_ERR_ error code if anything goes seriously
    # wrong)
    ocf_run dmsetup remove ${OCF_RESKEY_name} || exit $OCF_ERR_GENERIC

    # After the resource has been stopped, check whether it shut down
    # correctly. If the resource stops asynchronously, the agent may
    # spin on the monitor function here -- if the resource does not
    # shut down within the defined timeout, the cluster manager will
    # consider the stop action failed
    while flashcache_monitor; do
        ocf_log debug "Resource has not stopped yet, waiting"
        sleep 1
    done

    # only return $OCF_SUCCESS if _everything_ succeeded as expected
    return $OCF_SUCCESS

}

flashcache_monitor() {
    local rc
    local blockdev
    local device_present
    local map_present

    # exit immediately if configuration is not valid
    flashcache_validate_all || exit $?

    # First, see if a block device exists in /dev/mapper
    blockdev=/dev/mapper/${OCF_RESKEY_name}
    if [ -e ${blockdev} ]; then
	if [ -b ${blockdev} ]; then
	    case "`stat -L -c "%t" ${blockdev}`" in
		"fc"|"fd")
		    ocf_log debug "Block device ${blockdev} exists and is a device-mapper device"
		    ;;
		*)
		    ocf_log warn "Existing block device ${blockdev} is not a device-mapper device!"
		    return $OCF_NOT_RUNNING
	    esac
	else
	    ocf_log warn "File ${blockdev} exists, but is not a block device!"
	fi
    fi

    # OK, we have a block device and it has the correct major
    # number. Now, check if there is an entry in the DM table for the
    # device.
    dmsetup ls | grep -Eq "^${OCF_RESKEY_name}[[:space:]]+"
    if [ $? -eq 0 ]; then
	ocf_log debug "Device map \"${OCF_RESKEY_name}\" is present"
	# So we have a block device, and we have a device mapper table
	# entry. Good enough for now.
	#
	# TODO: For an added paranoia check, test whether the minor
	# number in the table matches the one stat() returns on the
	# device.
	return $OCF_SUCCESS
    fi
    
    return $OCF_NOT_RUNNING
}

flashcache_validate_all() {
    # Check required parameters
    if [ -z "${OCF_RESKEY_device}" ]; then
	ocf_log err "Required parameter \"device\" not configured!"
	exit $OCF_ERR_CONFIGURED
    fi
    if [ -z "${OCF_RESKEY_cache_device}" ]; then
	ocf_log err "Required parameter \"cache_device\" not configured!"
	exit $OCF_ERR_CONFIGURED
    fi

    # Test for required binaries
    check_binary flashcache_load
    check_binary dmsetup
    check_binary stat
    check_binary grep

    if ! ocf_is_probe; then
	for dev in ${OCF_RESKEY_device} ${OCF_RESKEY_cache_device}; do
	    if [ ! -b ${dev} ]; then
		ocf_log err "${dev} does not exist or is not a block device!"
		exit $OCF_ERR_INSTALLED
	    fi
	done
    fi

    return $OCF_SUCCESS
}

# Make sure meta-data and usage always succeed
case $__OCF_ACTION in
meta-data)      flashcache_meta_data
                exit $OCF_SUCCESS
                ;;
usage|help)     flashcache_usage
                exit $OCF_SUCCESS
                ;;
esac

# Anything other than meta-data and usage must pass validation
flashcache_validate_all || exit $?

# Translate each action into the appropriate function call
case $__OCF_ACTION in
start)          flashcache_start;;
stop)           flashcache_stop;;
status|monitor) flashcache_monitor;;
reload)         ocf_log info "Reloading..."
                flashcache_start
                ;;
validate-all)   ;;
*)              flashcache_usage
                exit $OCF_ERR_UNIMPLEMENTED
                ;;
esac
rc=$?

ocf_log debug "${OCF_RESOURCE_INSTANCE} $__OCF_ACTION returned $rc"
exit $rc
