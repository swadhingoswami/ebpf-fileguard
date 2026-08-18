#!/usr/bin/env bash
# setup-demo.sh — create the demo environment from section 26 of the spec.
#
# Requires root (writes to /protected and /usr/local/bin).
#
#   /protected/secret.txt                    the protected resource
#   /usr/local/bin/backup-agent              the ALLOWed process
#   /usr/local/bin/test-reader               an unauthorized process
#
# Usage: sudo ./scripts/setup-demo.sh
set -euo pipefail

PROTECTED_DIR=/protected
PROTECTED_FILE="$PROTECTED_DIR/secret.txt"
AGENT=/usr/local/bin/backup-agent
READER=/usr/local/bin/test-reader
FG_BIN=${FG_BIN:-build/guardctl}
AGENT_SRC=${AGENT_SRC:-build/backup-agent}
READER_SRC=${READER_SRC:-build/test-reader}

if [[ $EUID -ne 0 ]]; then
    echo "error: run as root (writes to $PROTECTED_DIR and /usr/local/bin)" >&2
    exit 1
fi

echo "[1/4] creating protected resource"
install -d -m 0700 "$PROTECTED_DIR"
printf 'launch-codes: alpha-9-foxtrot-1138\n' > "$PROTECTED_FILE"
chmod 0400 "$PROTECTED_FILE"

echo "[2/4] installing demo executables"
if [[ ! -x "$AGENT_SRC" || ! -x "$READER_SRC" ]]; then
    echo "error: build the project first (see scripts/build-linux.sh)" >&2
    exit 1
fi
install -m 0755 "$AGENT_SRC" "$AGENT"
install -m 0755 "$READER_SRC" "$READER"

echo "[3/4] policy:"
cat <<'POLICY' > /tmp/fileguard-demo-policy.json
{
    "version": 1,
    "defaults": { "action": "DENY" },
    "protected_resources": [ { "path": "/protected/secret.txt", "operation": "OPEN" } ],
    "rules": [
        {
            "id": "allow-backup-agent",
            "resource": "/protected/secret.txt",
            "operation": "OPEN",
            "process": { "type": "exe_path", "value": "/usr/local/bin/backup-agent" },
            "action": "ALLOW"
        }
    ]
}
POLICY

echo "[4/4] validating policy:"
"$FG_BIN" policy validate /tmp/fileguard-demo-policy.json

echo
echo "done. Next steps (run as root):"
echo "  $FG_BIN policy load /tmp/fileguard-demo-policy.json"
echo "  $FG_BIN status"
echo "  $AGENT $PROTECTED_FILE      # expect: Access allowed."
echo "  cat $PROTECTED_FILE         # expect: Permission denied."
echo "  $READER $PROTECTED_FILE     # expect: Permission denied."
