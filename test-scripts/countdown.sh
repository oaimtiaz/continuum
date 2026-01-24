#!/bin/bash
# Countdown timer - finite streaming with clean exit
# Run: continuum run test-scripts/countdown.sh [seconds]
# Default: 10 seconds

seconds=${1:-10}

echo "Starting countdown from $seconds..."
echo ""

for ((i=seconds; i>0; i--)); do
    echo "$i..."
    sleep 1
done

echo ""
echo "Liftoff! 🚀"
exit 0
