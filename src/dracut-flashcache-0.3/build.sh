mkinitrd -f /boot/initramfs-$(uname -r).img $(uname -r)
zcat /boot/initramfs-$(uname -r).img | cpio -it
