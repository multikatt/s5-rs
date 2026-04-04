#!/usr/bin/env bash
#
# Integration test for s5 group sharing with 3 nodes (alice, bob, charlie).
#
# Usage:
#   cd test/
#   ./run-group-test.sh             # build + run
#   ./run-group-test.sh --no-build  # skip build, reuse existing image
#
# Requires: podman-compose or docker compose
#
# Design: anything that touches redb/FS5 directly (config init, import,
# snapshots, group create, group share) runs BEFORE starting nodes.
# Commands that work via the network (invite, join, members, info, pin,
# leave) run AFTER nodes start and use remote-only registry access.
#
# Key constraint: a node with no bootstrap peers cannot do registry
# operations while running (redb lock + no remotes). Alice created the
# group so she starts with no peers. After bob joins, bob has alice as
# a peer and can do registry ops. So registry-reading commands (members,
# info) are run from bob's perspective where possible.
#
set -euo pipefail
export SUPPRESS_BOLTDB_WARNING=1

cd "$(dirname "$0")"

# Detect container tooling
if command -v podman-compose &>/dev/null; then
    COMPOSE="podman-compose"
elif command -v podman &>/dev/null && podman compose version &>/dev/null 2>&1; then
    COMPOSE="podman compose"
elif command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
else
    echo "ERROR: need podman-compose, podman compose, or docker compose"
    exit 1
fi

cleanup() {
    echo "=== cleaning up ==="
    $COMPOSE down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# Detect the container engine (podman or docker)
if command -v podman &>/dev/null; then
    ENGINE="podman"
elif command -v docker &>/dev/null; then
    ENGINE="docker"
else
    echo "ERROR: need podman or docker"
    exit 1
fi

# --- build (once) ---
if [[ "${1:-}" != "--no-build" ]]; then
    echo "=== building s5-test image (once) ==="
    $ENGINE build -t s5-test -f Containerfile ..
fi

# Helper: run a one-off s5 command in a service's volumes (node NOT running)
s5_run() {
    local svc="$1"; shift
    $COMPOSE run --rm -e SUPPRESS_BOLTDB_WARNING=1 "$svc" -qqq --node "$svc" "$@"
}

# Helper: exec s5 command inside a running service container
s5_exec() {
    local svc="$1"; shift
    $COMPOSE exec -T -e SUPPRESS_BOLTDB_WARNING=1 "$svc" s5 -qqq --node "$svc" "$@"
}

wait_for_node() {
    local svc="$1"
    echo "waiting for $svc to come online..."
    for _ in $(seq 1 30); do
        if $COMPOSE logs "$svc" 2>&1 | grep -q "s5_node online\|endpoint id"; then
            echo "  $svc is online"
            return 0
        fi
        sleep 1
    done
    echo "  ERROR: $svc did not come online in 30s"
    $COMPOSE logs "$svc" 2>&1 | tail -20
    return 1
}

# ============================================================
# Phase 1: everything that needs direct redb/FS5 access
#           (nodes NOT running — no lock conflicts)
# ============================================================

echo "=== initializing node configs ==="
for node in alice bob charlie; do
    s5_run "$node" config init 2>&1 | sed "s/^/  [$node] /"

    $COMPOSE run --rm --entrypoint sh -e SUPPRESS_BOLTDB_WARNING=1 "$node" -c \
        "grep -q peer_default /root/.config/s5/nodes/${node}.toml 2>/dev/null || cat >> /root/.config/s5/nodes/${node}.toml <<'TOML'

[peer_default.blobs]
readable_stores = [\"local_only_store\"]
skip_pin_check = true
TOML"
    echo "  [$node] peer_default configured"
done

echo ""
echo "=== test 1: alice creates a group ==="
s5_run alice group create "friends" --my-name "Alice" 2>&1 | sed 's/^/  /'
echo "  PASS"

echo ""
echo "=== preparing test content on alice ==="
# Create test files and import in one container run (shares /tmp)
$COMPOSE run --rm --entrypoint sh -e SUPPRESS_BOLTDB_WARNING=1 alice -c '
    mkdir -p /tmp/testdata
    echo "hello from alice" > /tmp/testdata/greeting.txt
    echo "some music" > /tmp/testdata/song.txt
    s5 -qqq --node alice import --target-store local_only_store local /tmp/testdata
' 2>&1 | sed 's/^/  /'

# Create snapshot (separate run, same volumes)
SNAP_OUTPUT=$(s5_run alice snapshots create-fs 2>&1)
echo "$SNAP_OUTPUT" | sed 's/^/  /'
SNAP=$(echo "$SNAP_OUTPUT" | grep -oP '[a-f0-9]{64}' | head -1)
if [[ -z "$SNAP" ]]; then
    echo "FAIL: could not extract snapshot hash"
    echo "full output was:"
    echo "$SNAP_OUTPUT"
    exit 1
fi
echo "  snapshot hash: $SNAP"

echo ""
echo "=== test 2: alice shares snapshot with group (before node start) ==="
s5_run alice group share friends "docs" "$SNAP" 2>&1 | sed 's/^/  /'
echo "  PASS"

# ============================================================
# Phase 2: start nodes
# ============================================================

echo ""
echo "=== starting nodes ==="
$COMPOSE up -d
sleep 2

wait_for_node "alice"
wait_for_node "bob"
wait_for_node "charlie"

# ============================================================
# Phase 3: network-based group operations (nodes running)
#
# Note: alice has no bootstrap peers (she created the group), so
# she can't do registry ops while her node holds the redb lock.
# invite doesn't need registry (reads local files only).
# Registry-reading commands run from bob/charlie who have alice
# as a bootstrap peer.
# ============================================================

echo ""
echo "=== test 3: alice generates invite ==="
# invite reads local group data files, no registry needed
INVITE=$(s5_exec alice group invite friends)
echo "  invite token: ${INVITE:0:40}..."

echo ""
echo "=== test 4: bob joins via invite ==="
# bob has alice as bootstrap peer from the invite token
s5_exec bob group join "$INVITE" --my-name "Bob" 2>&1 | sed 's/^/  /'
echo "  PASS"

echo ""
echo "=== test 5: check members (from bob) ==="
MEMBERS=$(s5_exec bob group members friends)
echo "$MEMBERS" | sed 's/^/  /'
echo "$MEMBERS" | grep -q "Alice" || { echo "FAIL: Alice not in members"; exit 1; }
echo "$MEMBERS" | grep -q "Bob"   || { echo "FAIL: Bob not in members"; exit 1; }
echo "  PASS"

echo ""
echo "=== test 6: bob sees the shared root ==="
INFO=$(s5_exec bob group info friends)
echo "$INFO" | sed 's/^/  /'
echo "$INFO" | grep -q "docs" || { echo "FAIL: docs not in group info"; exit 1; }
echo "  PASS"

echo ""
echo "=== test 7: bob pins the share (concurrent) ==="
s5_exec bob group pin friends docs --jobs 4 2>&1 | sed 's/^/  /'
echo "  PASS"

echo ""
echo "=== test 8: charlie joins with read-only invite ==="
# Generate read-only invite (no registry needed)
RO_INVITE=$(s5_exec alice group invite friends --read-only)
JOIN_OUTPUT=$(s5_exec charlie group join "$RO_INVITE" --my-name "Charlie" 2>&1)
echo "$JOIN_OUTPUT" | sed 's/^/  /'
# Read-only members can't publish state, so charlie won't appear in
# the member list for others. Just verify the join succeeded locally.
echo "$JOIN_OUTPUT" | grep -q "read-only" || { echo "FAIL: charlie didn't join as read-only"; exit 1; }
echo "  PASS"

echo ""
echo "=== test 9: bob leaves the group ==="
# bob can leave (has alice as remote peer for registry)
s5_exec bob group leave friends 2>&1 | sed 's/^/  /'
# Verify from charlie (charlie has alice as remote peer)
MEMBERS=$(s5_exec charlie group members friends)
echo "$MEMBERS" | sed 's/^/  /'
echo "$MEMBERS" | grep -q "Bob" && { echo "FAIL: Bob still in members after leave"; exit 1; }
echo "  PASS"

echo ""
echo "========================================="
echo "  ALL TESTS PASSED"
echo "========================================="
