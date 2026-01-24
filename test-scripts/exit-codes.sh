#!/bin/bash
# Exit with specific code - test exit status propagation
# Run: continuum run test-scripts/exit-codes.sh [exit_code]
# Then: continuum show <id> to verify exit code

exit_code=${1:-0}

echo "Will exit with code: $exit_code"
sleep 1

case $exit_code in
    0)   echo "Exiting successfully" ;;
    1)   echo "Exiting with general error" ;;
    2)   echo "Exiting with misuse of shell builtin" ;;
    126) echo "Exiting: command not executable" ;;
    127) echo "Exiting: command not found" ;;
    128) echo "Exiting: invalid exit argument" ;;
    130) echo "Exiting: terminated by Ctrl+C" ;;
    *)   echo "Exiting with custom code" ;;
esac

exit $exit_code
