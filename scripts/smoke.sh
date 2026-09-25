#!/usr/bin/env sh
# End-to-end smoke test against the local mock responder.
#
# Contacts no provider. Proves that the binary can build a request, verify a
# real RFC 3161 response, hold its schedule and write a complete report.
set -eu

BIN=${BIN:-./bin/tsa-bench}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true' EXIT

echo "==> starting mock responder"
"$BIN" mock --addr 127.0.0.1:8318 --write-ca "$WORK/mock-ca.pem" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!

# Wait for the socket. The CA file is written before the listener is bound, so
# its appearance says nothing about readiness; the "listening on" line is
# printed only after the port is open.
i=0
while ! grep -q "listening on" "$WORK/mock.log" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -gt 100 ] && { echo "mock did not start"; cat "$WORK/mock.log"; exit 1; }
    sleep 0.1
done

sed "s|tsa_ca_file: .*|tsa_ca_file: \"$WORK/mock-ca.pem\"|" \
    configs/mock.example.yaml > "$WORK/mock.yaml"

echo "==> validate (no network traffic)"
"$BIN" validate --config "$WORK/mock.yaml" --profile profiles/smoke.yaml --quiet

echo "==> doctor --send-one"
"$BIN" doctor --config "$WORK/mock.yaml" --send-one

echo "==> run smoke profile"
"$BIN" run --config "$WORK/mock.yaml" --profile profiles/smoke.yaml \
    --max-requests 200 --authorized-load-test --output "$WORK/results" 2>&1 | tail -12

RUN_DIR=$(find "$WORK/results" -mindepth 2 -maxdepth 2 -type d | head -1)
echo "==> report"
"$BIN" report "$RUN_DIR" --output "$WORK/results"

echo
echo "==> outputs"
ls -1 "$RUN_DIR"
echo "smoke test passed"
