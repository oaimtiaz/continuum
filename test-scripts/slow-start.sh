#!/bin/bash
# Slow start - delayed initial output
# Run: continuum run test-scripts/slow-start.sh [delay]
# Then: continuum attach <id> to test attaching to "quiet" task

delay=${1:-5}

# No output for initial delay
sleep $delay

echo "Starting output after ${delay}s delay..."

for i in {1..10}; do
    echo "Output line $i"
    sleep 0.5
done

echo "Done!"
exit 0
