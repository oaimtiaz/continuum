#!/bin/bash
# Infinite echo loop for testing streaming output / tailing
# Run: continuum run test-scripts/echo-loop.sh
# Then: continuum show -t <id> to watch live output
# Cancel with: continuum cancel <id>

counter=0
while true; do
    echo "[$(date '+%H:%M:%S')] Tick $counter"
    counter=$((counter + 1))
    sleep 1
done
