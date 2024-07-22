name = comfyui

# File system restrictions
blacklist /usr/local/bin
blacklist /usr/local/sbin
blacklist /boot
private-tmp
read-only /tmp/.X11-unix
private-dev
nodvd
nosound
notv
nou2f
novideo
disable-mnt
private-opt emp
private-srv emp

# Sandbox hardening
seccomp
seccomp.block-secondary
noroot
caps.drop all
apparmor
nonewprivs
ipc-namespace
machine-id
nodbus
memory-deny-write-execute
allow-debuggers
private-lib

# Block network access completely
protocol unix,inet,inet6

# Prevent execution from certain directories
noexec ${HOME}
noexec /tmp
noexec ${RUNUSER}
