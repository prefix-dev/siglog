#!/bin/bash
#
# Wrapper script to make litewitness CLI compatible with witness conformance tests.
#
# This script adapts litewitness's CLI (which uses SSH agent and different flags)
# to match the expected CLI format of our conformance tests.

set -e

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Parse arguments
DATABASE_URL=""
LISTEN=""
PRIVATE_KEY=""
LOG_CONFIG=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --database-url)
            DATABASE_URL="$2"
            shift 2
            ;;
        --listen)
            LISTEN="$2"
            shift 2
            ;;
        --private-key)
            PRIVATE_KEY="$2"
            shift 2
            ;;
        --log)
            LOG_CONFIG="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create temp directory for this instance
TEMP_DIR=$(mktemp -d)

cleanup() {
    # Kill background processes gracefully
    if [[ -n "${LITEWITNESS_PID:-}" ]]; then
        kill $LITEWITNESS_PID 2>/dev/null || true
        wait $LITEWITNESS_PID 2>/dev/null || true
    fi
    rm -rf "$TEMP_DIR"
    exit 0
}

trap cleanup EXIT TERM INT

# Convert database URL to litewitness format
if [[ $DATABASE_URL == sqlite::memory: ]]; then
    DB_PATH="$TEMP_DIR/witness.db"
elif [[ $DATABASE_URL == sqlite:* ]]; then
    DB_PATH="${DATABASE_URL#sqlite:}"
    # Handle sqlite://path format
    DB_PATH="${DB_PATH#//}"
else
    echo "Unsupported database URL: $DATABASE_URL"
    exit 1
fi

# Extract port from listen address
PORT="${LISTEN##*:}"
LISTEN_ADDR="localhost:${PORT}"

# Generate SSH key for witness signing
ssh-keygen -t ed25519 -N "" -f "$TEMP_DIR/witness_key" -C "witness-conformance" >/dev/null 2>&1

# Get SSH fingerprint
KEY_FINGERPRINT=$(ssh-keygen -lf "$TEMP_DIR/witness_key.pub" | awk '{print $2}')

# Start ssh-agent
export SSH_AUTH_SOCK="$TEMP_DIR/agent.sock"
ssh-agent -a "$SSH_AUTH_SOCK" >/dev/null 2>&1 &
sleep 0.5

# Add key to agent
SSH_AUTH_SOCK="$TEMP_DIR/agent.sock" ssh-add "$TEMP_DIR/witness_key" >/dev/null 2>&1

# Find litewitness binary
LITEWITNESS_BIN=""
if [[ -f "$SCRIPT_DIR/litewitness" ]]; then
    LITEWITNESS_BIN="$SCRIPT_DIR/litewitness"
elif command -v litewitness &> /dev/null; then
    LITEWITNESS_BIN="litewitness"
else
    echo "Error: litewitness binary not found"
    exit 1
fi

# Find witnessctl binary
WITNESSCTL_BIN=""
if [[ -f "$SCRIPT_DIR/witnessctl" ]]; then
    WITNESSCTL_BIN="$SCRIPT_DIR/witnessctl"
elif command -v witnessctl &> /dev/null; then
    WITNESSCTL_BIN="witnessctl"
else
    echo "Warning: witnessctl not found, logs may not be registered"
fi

# Witness name
WITNESS_NAME="example.com/witness"

# Register the test log BEFORE starting litewitness (it loads DB at startup)
LOG_INFO_FILE="$SCRIPT_DIR/.test_log_info"
if [[ -n "$WITNESSCTL_BIN" ]] && [[ -f "$LOG_INFO_FILE" ]]; then
    # Read log origin and public key from file
    LOG_ORIGIN=$(sed -n '1p' "$LOG_INFO_FILE")
    LOG_PUBKEY_HEX=$(sed -n '2p' "$LOG_INFO_FILE")

    if [[ -n "$LOG_ORIGIN" ]] && [[ -n "$LOG_PUBKEY_HEX" ]]; then
        # Build the verifier key in Note format: origin+hash+base64(0x01+pubkey)
        # First decode hex to binary, prepend 0x01, then base64 encode
        PUBKEY_BINARY=$(echo -n "$LOG_PUBKEY_HEX" | xxd -r -p)
        ALG_AND_PUBKEY=$(printf '\x01%s' "$PUBKEY_BINARY")
        PUBKEY_B64=$(echo -n "$ALG_AND_PUBKEY" | base64)

        # Compute hash: first 4 bytes of SHA256(origin + "\n" + alg_and_pubkey)
        HASH_INPUT=$(printf '%s\n%s' "$LOG_ORIGIN" "$ALG_AND_PUBKEY")
        HASH_HEX=$(echo -n "$HASH_INPUT" | shasum -a 256 | cut -c1-8)

        VKEY="${LOG_ORIGIN}+${HASH_HEX}+${PUBKEY_B64}"

        # Register the log with witnessctl
        # First create the log entry, then add the verification key
        "$WITNESSCTL_BIN" add-log -db "$DB_PATH" -origin "$LOG_ORIGIN" >/dev/null 2>&1 || true
        "$WITNESSCTL_BIN" add-key -db "$DB_PATH" -origin "$LOG_ORIGIN" -key "$VKEY" >/dev/null 2>&1 || true
    fi
fi

# Start litewitness in background
"$LITEWITNESS_BIN" \
    -db "$DB_PATH" \
    -listen "$LISTEN_ADDR" \
    -name "$WITNESS_NAME" \
    -key "$KEY_FINGERPRINT" \
    -ssh-agent "$SSH_AUTH_SOCK" &
LITEWITNESS_PID=$!

# Wait for litewitness to start
sleep 0.5

# Check if litewitness is running
if ! kill -0 $LITEWITNESS_PID 2>/dev/null; then
    echo "Error: litewitness failed to start"
    exit 1
fi

# Wait for litewitness to exit
wait $LITEWITNESS_PID
