#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# build.sh — produce sdist + wheel for foundation-sdk into ./dist/
#
# Uses Poetry (the project's declared build-backend) so the output exactly
# matches what CI ships. Version can be overridden by the caller, which is
# how the GitHub Actions release job stamps tagged builds:
#
#     FOUNDATION_SDK_VERSION=0.2.1 ./build.sh
#
# Without an override the version declared in pyproject.toml is used.
# -----------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

if [[ -n "${FOUNDATION_SDK_VERSION:-}" ]]; then
  echo ">> Pinning version to ${FOUNDATION_SDK_VERSION} (overridden via env)"
  poetry version "${FOUNDATION_SDK_VERSION}"
fi

rm -rf dist/
poetry build --format sdist
poetry build --format wheel

echo ""
echo ">> Build artifacts:"
ls -la dist/
