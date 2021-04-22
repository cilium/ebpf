#!/bin/sh

echo pid: $$ "$@"
slabtop -o
echo "bytes_alloc == 8192 && common_pid == $$" >> /sys/kernel/debug/tracing/events/kmem/filter
exec "$@"
