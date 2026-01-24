#!/bin/bash
# Interactive cat - echoes back whatever you type
# Run: continuum run -i test-scripts/interactive-cat.sh
# Or: continuum attach -i <task-id>
# Exit with Ctrl+D

echo "Interactive cat - type something and press Enter (Ctrl+D to exit)"
echo "---"

while IFS= read -r line; do
    echo "You typed: $line"
done

echo "---"
echo "Goodbye!"
