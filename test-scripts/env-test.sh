#!/bin/bash
# Environment variable test
# Run: continuum run -e FOO=bar -e DEBUG=1 test-scripts/env-test.sh
# Verify environment variables are passed correctly

echo "Environment Variable Test"
echo "========================="
echo ""

# Check for specific test variables
if [ -n "$FOO" ]; then
    echo "FOO=$FOO"
else
    echo "FOO is not set"
fi

if [ -n "$DEBUG" ]; then
    echo "DEBUG=$DEBUG"
else
    echo "DEBUG is not set"
fi

if [ -n "$CUSTOM_VAR" ]; then
    echo "CUSTOM_VAR=$CUSTOM_VAR"
else
    echo "CUSTOM_VAR is not set"
fi

echo ""
echo "All environment variables:"
echo "--------------------------"
env | sort

exit 0
