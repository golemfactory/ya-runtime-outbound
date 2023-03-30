#!/bin/bash

set -e

DEFAULT_INSTALL_DIR=~/.local/lib/yagna/plugins

cargo build --release -p ya-runtime-outbound

mkdir -p ${DEFAULT_INSTALL_DIR}/ya-runtime-outbound

echo "Installing in ${DEFAULT_INSTALL_DIR}"

cp target/release/ya-runtime-outbound ${DEFAULT_INSTALL_DIR}/ya-runtime-outbound/ya-runtime-outbound
cp conf/ya-runtime-outbound.json ${DEFAULT_INSTALL_DIR}/ya-runtime-outbound.json
