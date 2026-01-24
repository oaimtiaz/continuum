#!/bin/bash
# Interactive prompt loop - tests full interactive session
# Run: continuum run -i test-scripts/prompt-loop.sh
# Or: continuum attach -i <task-id>

echo "Interactive Prompt Loop"
echo "======================="
echo "Commands: name, greet, count, quit"
echo ""

username=""

while true; do
    printf "> "
    read -r cmd args

    case "$cmd" in
        name)
            if [ -n "$args" ]; then
                username="$args"
                echo "Name set to: $username"
            else
                printf "Enter your name: "
                read -r username
                echo "Hello, $username!"
            fi
            ;;
        greet)
            if [ -n "$username" ]; then
                echo "Hello again, $username!"
            else
                echo "I don't know your name. Use 'name' command first."
            fi
            ;;
        count)
            n=${args:-5}
            for ((i=1; i<=n; i++)); do
                echo "$i"
                sleep 0.2
            done
            ;;
        quit|exit|q)
            echo "Goodbye${username:+, $username}!"
            exit 0
            ;;
        "")
            # Empty input, just continue
            ;;
        *)
            echo "Unknown command: $cmd"
            echo "Commands: name, greet, count, quit"
            ;;
    esac
done
