#!/bin/sh
# Healthy = the main loop touched /tmp/heartbeat within the last 60 s. The loop keeps beating
# while Pi-hole is down (that case is reported by the detector itself), so this only catches a
# wedged or dead detector.
#
# Docker never restarts an unhealthy container on its own (restart: only reacts to exit), so
# after 3 consecutive failures kill the detector; with `init: true` the init process then exits
# and `restart: unless-stopped` brings the container back.
f=/tmp/hc_fail

# /tmp survives a container restart: drop a counter left over from the previous process.
[ -f "$f" ] && [ /proc/1 -nt "$f" ] && rm -f "$f"

beat=$(stat -c %Y /tmp/heartbeat 2>/dev/null || echo 0)
if [ $(( $(date +%s) - beat )) -lt 60 ]; then
    rm -f "$f"
    exit 0
fi

n=$(( $(cat "$f" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$f"
if [ "$n" -ge 3 ]; then
    pid=$(pgrep -f "pihole_detector run")
    if [ -n "$pid" ]; then
        kill -TERM $pid
        sleep 3
        kill -KILL $pid 2>/dev/null
    fi
fi
exit 1
