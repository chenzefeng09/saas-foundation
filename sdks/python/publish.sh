#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# publish.sh — upload ./dist/* to the internal PyPI via twine
#
# Required env:
#   FOUNDATION_PYPI_URL    e.g. https://pypi.internal.example/repository/pypi-hosted/
#   FOUNDATION_PYPI_TOKEN  upload token (username defaults to __token__)
#
# Flags:
#   --dry-run   run `twine check dist/*` only; do not upload
#
# We deliberately use twine rather than `poetry publish` so credential handling
# is identical to every other internal Python package release pipeline (Nexus
# / devpi both speak the standard PyPI upload protocol).
# -----------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    *) echo "Unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if [[ ! -d dist || -z "$(ls -A dist/ 2>/dev/null)" ]]; then
  echo "ERROR: dist/ is empty. Run ./build.sh first." >&2
  exit 1
fi

# twine ships in its own venv so we don't pollute the project's poetry env.
if ! command -v twine >/dev/null 2>&1; then
  echo ">> Installing twine in an ephemeral venv"
  python3 -m venv .publish-venv
  # shellcheck source=/dev/null
  source .publish-venv/bin/activate
  pip install --quiet "twine>=5.0,<6"
fi

echo ">> twine check"
twine check dist/*

if [[ $DRY_RUN -eq 1 ]]; then
  echo ">> --dry-run set, skipping upload."
  exit 0
fi

: "${FOUNDATION_PYPI_URL:?FOUNDATION_PYPI_URL must be set}"
: "${FOUNDATION_PYPI_TOKEN:?FOUNDATION_PYPI_TOKEN must be set}"

echo ">> Uploading to ${FOUNDATION_PYPI_URL}"
TWINE_USERNAME="${FOUNDATION_PYPI_USERNAME:-__token__}" \
TWINE_PASSWORD="${FOUNDATION_PYPI_TOKEN}" \
  twine upload --repository-url "${FOUNDATION_PYPI_URL}" --non-interactive dist/*
