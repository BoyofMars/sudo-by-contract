#!/usr/bin/env bash
# Real-OpenSSH integration test for Sudo by Contract host enforcement.
#
# Runs as root in a disposable Debian container (CI). Uses the sshd drop-in
# that `sbc-gate sshd-config` generates, the real sbc-gate binary, and a mock
# NEAR RPC (sandbox/ci/mock_rpc.py) standing in for the policy contract.
#
# The CA here is a throwaway key made by ssh-keygen *for this test only*; in
# the product the CA is derived by the NEAR MPC network and has no private key.
#
#   usage: sandbox/ci/sshd-integration.sh /path/to/sbc-gate
set -euo pipefail
GATE_BIN=${1:?path to sbc-gate}
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d)
PASS=0
FAIL=0

ok()   { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ✕ $1"; FAIL=$((FAIL+1)); }

install -m 0755 "$GATE_BIN" /usr/local/sbin/sbc-gate
id sbc-agent >/dev/null 2>&1 || { useradd --create-home --shell /bin/sh sbc-agent; usermod -p '*' sbc-agent; }
mkdir -p /etc/sbc/ssh/sbc_principals /run/sshd /etc/ssh/sshd_config.d

# --- fixtures: test CA (stand-in for the MPC-derived CA), mock chain, gate config
ssh-keygen -q -t ed25519 -N '' -C test-ca -f "$T/ca"
cp "$T/ca.pub" /etc/sbc/ssh/sbc_user_ca.pub
echo sbc-prod-web-02 > /etc/sbc/ssh/sbc_principals/sbc-agent
python3 "$HERE/mock_rpc.py" 18545 "$T/chain.log" &
MOCK=$!
trap 'kill $MOCK 2>/dev/null || true; pkill -f "sshd -p 2222" || true' EXIT

cat > /etc/sbc/gate.toml <<EOF
contract = "sbc.test"
rpc = "http://127.0.0.1:18545"
resource = "prod-web-02"
principal = "sbc-prod-web-02"
environment = "production"
key_file = "/etc/sbc/gate.key"
ca_file = "/etc/sbc/ssh/sbc_user_ca.pub"
krl_file = "/etc/sbc/ssh/sbc_revoked.krl"
backend = "dryrun"
services = ["checkout-api", "sshd"]
EOF
sbc-gate keygen --account sbc.test --out /etc/sbc/gate.key >/dev/null
chown sbc-agent:sbc-agent /etc/sbc/gate.key && chmod 0400 /etc/sbc/gate.key
: > "$T/empty.spec"
ssh-keygen -q -k -f /etc/sbc/ssh/sbc_revoked.krl -s "$T/ca.pub" "$T/empty.spec"
sbc-gate sshd-config > /etc/ssh/sshd_config.d/50-sbc.conf

ssh-keygen -q -t ed25519 -N '' -f "$T/hostkey"
cat > "$T/sshd_config" <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $T/hostkey
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
PermitUserEnvironment no
Include /etc/ssh/sshd_config.d/*.conf
EOF
/usr/sbin/sshd -t -f "$T/sshd_config"
/usr/sbin/sshd -f "$T/sshd_config" -p 2222 -E "$T/sshd.log"
sleep 1

# --- agent key and certificates
ssh-keygen -q -t ed25519 -N '' -f "$T/agent"
cert() { # name principal validity serial
  cp "$T/agent.pub" "$T/$1.pub"
  ssh-keygen -q -s "$T/ca" -I "sbc cap=$4 agent=deploy-agent res=prod-web-02" -n "$2" -z "$4" -V "$3" \
    -O clear -O force-command=/usr/local/sbin/sbc-gate "$T/$1.pub"
  cp "$T/agent" "$T/$1"; chmod 600 "$T/$1"
}
cert good sbc-prod-web-02 -1m:+10m 12
cert expired sbc-prod-web-02 -20m:-10m 12
cert otherhost sbc-prod-web-03 -1m:+10m 12
cert revoked sbc-prod-web-02 -1m:+10m 99

run() { # key-name, then ssh args... ; sets RC, OUT, ERR
  local k=$1; shift
  set +e
  OUT=$(ssh -i "$T/$k" -o CertificateFile="$T/$k-cert.pub" -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -p 2222 "$@" 2>"$T/err")
  RC=$?
  ERR=$(cat "$T/err")
  set -e
}

echo "sshd + sbc-gate enforcement"
run good sbc-agent@127.0.0.1 sudo systemctl restart checkout-api
[[ $RC -eq 0 && $OUT == *'"/usr/bin/systemctl","restart","checkout-api"'* ]] && ok "approved restart executes the fixed argv" || bad "approved restart (rc=$RC out=$OUT err=$ERR)"

run good sbc-agent@127.0.0.1 sudo cat /etc/shadow
[[ $RC -eq 126 && $ERR == *no_adapter* ]] && ok "sudo cat /etc/shadow → denied (no adapter)" || bad "cat /etc/shadow (rc=$RC err=$ERR)"

run good sbc-agent@127.0.0.1 sudo systemctl restart sshd
[[ $RC -eq 77 && $ERR == *out_of_scope* ]] && ok "restart sshd → denied (out of scope)" || bad "restart sshd (rc=$RC err=$ERR)"

run good sbc-agent@127.0.0.1 sudo systemctl restart checkout-api
[[ $RC -eq 77 && $ERR == *exhausted* ]] && ok "second restart → denied (single use)" || bad "second restart (rc=$RC err=$ERR)"

run good sbc-agent@127.0.0.1 'sudo systemctl restart checkout-api; id'
[[ $RC -eq 126 && $ERR == *shell_metacharacter* ]] && ok "command injection → denied before reaching the chain" || bad "injection (rc=$RC err=$ERR)"

run good -T sbc-agent@127.0.0.1
[[ $RC -eq 126 && $ERR == *interactive_session* ]] && ok "no interactive shell" || bad "interactive (rc=$RC err=$ERR)"

run good -tt sbc-agent@127.0.0.1 systemctl status checkout-api
[[ $ERR == *"PTY allocation request failed"* ]] && ok "PTY refused" || bad "pty (rc=$RC err=$ERR)"

run good -N -o ExitOnForwardFailure=yes -R 0:127.0.0.1:22 sbc-agent@127.0.0.1
[[ $RC -ne 0 ]] && ok "port forwarding refused" || bad "forwarding (rc=$RC err=$ERR)"

run expired sbc-agent@127.0.0.1 sudo systemctl restart checkout-api
[[ $RC -eq 255 && $ERR == *"Permission denied"* ]] && ok "expired certificate → refused by sshd itself" || bad "expired (rc=$RC err=$ERR)"

run otherhost sbc-agent@127.0.0.1 sudo systemctl restart checkout-api
[[ $RC -eq 255 ]] && ok "certificate for another host → refused by sshd" || bad "other host (rc=$RC err=$ERR)"

printf 'serial: 99\n' > "$T/rev.spec"
ssh-keygen -q -k -f /etc/sbc/ssh/sbc_revoked.krl -s "$T/ca.pub" "$T/rev.spec"
run revoked sbc-agent@127.0.0.1 sudo systemctl restart checkout-api
[[ $RC -eq 255 ]] && ok "revoked serial in KRL → refused by sshd" || bad "revoked (rc=$RC err=$ERR)"

set +e
# ($T/agent has no $T/agent-cert.pub next to it, so ssh offers the bare key)
ssh -i "$T/agent" -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p 2222 sbc-agent@127.0.0.1 id 2>/dev/null
RC=$?
set -e
[[ $RC -eq 255 ]] && ok "plain key without certificate → refused" || bad "plain key (rc=$RC)"

ALLOWED=$(grep -c '"allowed": true' "$T/chain.log" || true)
[[ $ALLOWED -eq 1 ]] && ok "exactly one consume() was allowed on the (mock) chain" || bad "allowed count $ALLOWED"
grep -q '"method": "report_denial"' "$T/chain.log" && ok "local denials were reported to the chain" || bad "no report_denial"

echo
echo "$PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
