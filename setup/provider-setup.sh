#!/bin/bash

set -e

LOG_LEVEL=warn
export RUST_LOG=${LOG_LEVEL}

PROVIDER_GLOBAL_CMD="ya-provider"
PROVIDER_CARGO_CMD="cargo run -p ya-provider --"

PRESET_NAME="gateway-default"

# Choose if you want to install for global Provider installed from binaries
# or local Provider compiled from source
PROVIDER_CMD=${PROVIDER_GLOBAL_CMD}
#PROVIDER_CMD=${PROVIDER_CARGO_CMD}

echo "Creating and activating Provider preset:"

${PROVIDER_CMD} preset create --no-interactive --preset-name ${PRESET_NAME} --pricing linear --exe-unit "outbound" --price "out-network-traffic=0.000001" --price "in-network-traffic=0.000001" --price "duration=0.0001"
${PROVIDER_CMD} preset activate "${PRESET_NAME}"

# Print presets to verify
echo "Active presets:"
${PROVIDER_CMD} preset active
