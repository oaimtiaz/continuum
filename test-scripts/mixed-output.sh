#!/bin/bash
# Interleaved stdout and stderr output
# Run: continuum run test-scripts/mixed-output.sh
# Verify both streams are visible

for i in {1..5}; do
    echo "stdout: message $i"
    echo "stderr: warning $i" >&2
    sleep 0.5
done

echo "stdout: Done with normal output"
echo "stderr: Final warning" >&2
exit 0
