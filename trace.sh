#!/bin/sh

echo pid: $$ "$@"
# cat /proc/slabinfo > /dev/null
echo "bytes_alloc == 8192 && common_pid == $$" >> /sys/kernel/debug/tracing/events/kmem/filter
exec "$@"
