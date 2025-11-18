#!/usr/bin/env bash
# Helpful setup script (optional). This script does not modify system files by default.
# Usage: bash scripts/setup.sh

set -euo pipefail

echo "Creating media and tmp folders"
mkdir -p "$PWD/media/screenshots"

echo "Done. Add any tool installs manually (this script is intentionally minimal)."
