#!/bin/sh
# Run the official tempoxyz/mpp-tools conformance runner against Transponder.
# Used by CI and runnable locally. Needs git, make, a C compiler and uv.
#
#   sh scripts/conformance.sh
#
# MPP_TOOLS_REF pins the vectors; bump it on purpose and regenerate
# tests/conformance_vectors.h with tools/gen_conformance.py at the same time.
set -eu

MPP_TOOLS_REF="${MPP_TOOLS_REF:-7ff233894e3c73eaeb81bf4ab8754795362ed8d6}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${MPP_TOOLS_DIR:-$ROOT/build/mpp-tools}"

make -C "$ROOT" conformance-adapter

if [ ! -d "$DIR/.git" ]; then
    git clone --quiet https://github.com/tempoxyz/mpp-tools "$DIR"
fi
git -C "$DIR" fetch --quiet --depth 1 origin "$MPP_TOOLS_REF"
git -C "$DIR" checkout --quiet FETCH_HEAD

mkdir -p "$DIR/conformance/adapters/transponder"
python3 - "$ROOT/tools/conformance/adapter.json" "$ROOT/build/trp-conformance-adapter" \
    "$DIR/conformance/adapters/transponder/adapter.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
manifest["command"] = [sys.argv[2]]
manifest.pop("build", None)
json.dump(manifest, open(sys.argv[3], "w"), indent=2)
PY

cd "$DIR/conformance"
uv run --quiet --python 3.12 python scripts/vector_runner.py --adapter transponder
