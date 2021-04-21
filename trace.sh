#!/bin/sh

echo "common_pid == $$" > /sys/kernel/debug/tracing/events/kmem/filter
echo pid: $$ "$@"
exec "$@"
