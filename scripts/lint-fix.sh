#!/bin/bash
# 一键修复所有 Rust lint + 格式化问题
# 用法: ./scripts/lint-fix.sh
set -e
cd "$(dirname "$0")/.."
cargo clippy --fix --all-targets --all-features --allow-dirty
cargo fmt --all
echo "✅ lint-fix done"
