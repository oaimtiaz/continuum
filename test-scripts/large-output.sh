#!/bin/bash
# Large output buffer stress test
# Run: continuum run test-scripts/large-output.sh [lines] [line_length]
# Verify no truncation in output

lines=${1:-1000}
line_length=${2:-100}

echo "Generating $lines lines of $line_length characters each..."
echo "---"

# Generate a line of specific length
generate_line() {
    local len=$1
    local num=$2
    local prefix="Line $num: "
    local padding_len=$((len - ${#prefix}))

    if [ $padding_len -gt 0 ]; then
        printf "%s%0${padding_len}d\n" "$prefix" 0 | tr '0' 'X'
    else
        echo "$prefix"
    fi
}

for ((i=1; i<=lines; i++)); do
    generate_line $line_length $i
done

echo "---"
echo "Generated $lines lines"
echo "Total approximate bytes: $((lines * line_length))"
exit 0
