#!/bin/bash
# Signal handler test - captures SIGINT (Ctrl+C)
# Run: continuum run -i test-scripts/signal-handler.sh
# Press Ctrl+C to test signal handling
# Press Ctrl+C twice to exit

sigint_count=0

handle_sigint() {
    sigint_count=$((sigint_count + 1))
    echo ""
    echo "Caught SIGINT (#$sigint_count)"

    if [ $sigint_count -ge 2 ]; then
        echo "Second SIGINT - exiting gracefully"
        exit 130
    else
        echo "Press Ctrl+C again to exit"
    fi
}

trap handle_sigint SIGINT

echo "Signal handler test - press Ctrl+C"
echo "First Ctrl+C: shows message"
echo "Second Ctrl+C: exits"
echo ""

counter=0
while true; do
    echo "Running... (tick $counter)"
    counter=$((counter + 1))
    sleep 1
done
