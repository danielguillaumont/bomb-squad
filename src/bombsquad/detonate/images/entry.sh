#!/bin/sh
# Runs as root. strace pipes the trace to a root process whose output is the container's
# standard output, and runs the stage as the user detonate, which cannot write to it.
set -eu
# Every name resolves through the sink, not through Docker's own resolver.
echo "nameserver $BS_SINK" > /etc/resolv.conf
exec strace -f -tt -q -s 256 -o '|cat' \
  -e trace=execve,clone,clone3,fork,vfork,chdir,open,openat,openat2,creat,connect,sendto,sendmsg \
  -u detonate /opt/detonate/stage.sh
