#!/usr/bin/env sh
# One-command demonstration against the local mock responder.
#
# Contacts no provider and consumes no quota anywhere. Starts a mock RFC 3161
# responder on loopback, runs a rate ladder against it, verifies every response
# through the full acceptance chain, and writes a report.
set -eu

BIN=${BIN:-./bin/tsa-bench}
OUT=${OUT:-./demo-results}
ADDR=${ADDR:-127.0.0.1:8319}

[ -x "$BIN" ] || { echo "$BIN not built; run: make build" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true' EXIT

rm -rf "$OUT"

echo "==> starting the local mock responder on $ADDR"
"$BIN" mock --addr "$ADDR" --write-ca "$WORK/mock-ca.pem" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!

# The CA file is written before the listener is bound, so its appearance says
# nothing about readiness; the "listening on" line is printed once the port is
# open.
i=0
while ! grep -q "listening on" "$WORK/mock.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 100 ] && { echo "mock did not start"; cat "$WORK/mock.log"; exit 1; }
    sleep 0.1
done

sed -e "s|tsa_ca_file: .*|tsa_ca_file: \"$WORK/mock-ca.pem\"|" \
    -e "s|endpoint: .*|endpoint: \"http://$ADDR/\"|" \
    configs/mock.example.yaml > "$WORK/demo.yaml"

echo "==> validate (sends nothing)"
"$BIN" validate --config "$WORK/demo.yaml" --profile profiles/demo.yaml --quiet
echo "    configuration and profile are consistent"

echo "==> run the demo profile (~20 s)"
"$BIN" run --config "$WORK/demo.yaml" --profile profiles/demo.yaml \
    --max-requests 3000 --authorized-load-test \
    --redact-host --output "$OUT" 2>&1 | tail -16

RUN_DIR=$(find "$OUT" -mindepth 2 -maxdepth 2 -type d | head -1)

echo "==> build the comparison report"
"$BIN" report "$RUN_DIR" --output "$OUT" >/dev/null

echo
echo "Done. Nothing left this machine."
echo
echo "  run report      $RUN_DIR/report.html"
echo "  comparison      $OUT/comparison.html"
echo "  metrics         $RUN_DIR/summary.json"
echo "  per-attempt     $RUN_DIR/requests.csv"
echo
echo "A committed copy of this output is in examples/sample-run/, so the same"
echo "files can be read without running anything."
