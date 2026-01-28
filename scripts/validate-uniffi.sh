#!/bin/bash
# validate-uniffi.sh - Run once before building Expo module
# Validates that UniFFI bindings generate correctly for continuum-mobile
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$WORKSPACE_ROOT"

echo "=== UniFFI Bindings Validation ==="
echo ""

# Step 1: Build the library
echo "[1/4] Building continuum-mobile..."
cargo build --package continuum-mobile --release

# Step 2: Generate and validate Swift bindings
# Uses uniffi's built-in bindgen via the library's scaffolding
echo "[2/4] Generating and validating Swift bindings..."
SWIFT_OUT=$(mktemp -d)
cargo run -p uniffi-bindgen --release -- generate \
    --library target/release/libcontinuum_mobile.dylib \
    --language swift \
    --out-dir "$SWIFT_OUT"

# Validate Swift syntax compiles
SWIFT_FILE=$(find "$SWIFT_OUT" -name "*.swift" | head -1)
if [ -z "$SWIFT_FILE" ]; then
    echo "    ERROR: No Swift file generated"
    exit 1
fi
swiftc -parse "$SWIFT_FILE"
echo "    Swift bindings: OK ($(basename "$SWIFT_FILE"))"

# Step 3: Generate Kotlin bindings
echo "[3/4] Generating Kotlin bindings..."
KOTLIN_OUT=$(mktemp -d)
cargo run -p uniffi-bindgen --release -- generate \
    --library target/release/libcontinuum_mobile.dylib \
    --language kotlin \
    --out-dir "$KOTLIN_OUT"

KOTLIN_FILE=$(find "$KOTLIN_OUT" -name "*.kt" | head -1)
if [ -z "$KOTLIN_FILE" ]; then
    echo "    ERROR: No Kotlin file generated"
    exit 1
fi
echo "    Kotlin bindings: OK ($(basename "$KOTLIN_FILE"))"

# Step 4: Cross-compile for iOS simulator
echo "[4/4] Cross-compiling for iOS simulator..."
rustup target add aarch64-apple-ios-sim 2>/dev/null || true
cargo build --package continuum-mobile --target aarch64-apple-ios-sim --release
echo "    iOS build: OK"

echo ""
echo "=== All validations passed! ==="
echo ""
echo "Generated files (temporary):"
echo "  Swift:  $SWIFT_FILE"
echo "  Kotlin: $KOTLIN_FILE"
echo ""
echo "Next step: Build the Expo module (modules/continuum-core/)"
