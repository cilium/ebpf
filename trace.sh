#!/bin/sh

echo pid: $$ "$@"
echo $$ >> /sys/kernel/debug/tracing/set_event_pid
exec "$@"
