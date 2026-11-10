#!/bin/sh
# Demo server entrypoint.
#
# First boot: enrolls this host with the policy contract using the one-time
# token created by `scripts/bootstrap-testnet.mjs` (or the console's
# "Add resource" flow), writing sshd + sudoers configuration. Later boots
# reuse the enrolled configuration in the /etc/sbc volume.
set -eu

: "${SBC_CONTRACT:?set SBC_CONTRACT}"
: "${SBC_RESOURCE:=prod-web-02}"
: "${SBC_RPC:=https://rpc.testnet.fastnear.com}"

mkdir -p /etc/ssh/keys /run/sshd /var/lib/checkout
if [ ! -f /etc/ssh/keys/ssh_host_ed25519_key ]; then
  ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/keys/ssh_host_ed25519_key
fi
# /etc/ssh/ssh_host_ed25519_key.pub is what enrollment fingerprints
cp /etc/ssh/keys/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ed25519_key.pub

if [ ! -f /etc/sbc/gate.toml ]; then
  : "${SBC_ENROLL_TOKEN:?first boot needs SBC_ENROLL_TOKEN (one-time gate enrollment token)}"
  echo "==> enrolling ${SBC_RESOURCE} with ${SBC_CONTRACT}"
  # CA pin, principals file and KRL live in the /etc/sbc volume (--ssh-dir)
  set -- --contract "$SBC_CONTRACT" --resource "$SBC_RESOURCE" --token "$SBC_ENROLL_TOKEN" \
         --rpc "$SBC_RPC" --backend supervisor --ssh-dir /etc/sbc/ssh --write-sshd --write-sudoers
  if [ -n "${SBC_RELAY:-}" ]; then set -- "$@" --relay "$SBC_RELAY"; fi
  /usr/local/sbin/sbc-gate enroll "$@"
fi

# Re-derive the sshd drop-in and sudoers rules from the persisted gate.toml
# whenever the container filesystem was recreated.
if [ ! -f /etc/ssh/sshd_config.d/50-sbc.conf ] || [ ! -f /etc/sudoers.d/sbc-gate ]; then
  echo "==> restoring sshd/sudoers configuration from /etc/sbc/gate.toml"
  mkdir -p /etc/ssh/sshd_config.d
  /usr/local/sbin/sbc-gate sshd-config > /etc/ssh/sshd_config.d/50-sbc.conf
  /usr/local/sbin/sbc-gate sudoers > /etc/sudoers.d/sbc-gate && chmod 0440 /etc/sudoers.d/sbc-gate
  visudo -cf /etc/sudoers.d/sbc-gate
fi
chown sbc-agent:sbc-agent /etc/sbc/gate.key && chmod 0400 /etc/sbc/gate.key

# The checkout service starts degraded, as if deployment #1842 wedged it.
if [ "${SBC_DEMO_DEGRADED:-1}" = "1" ] && [ ! -f /var/lib/checkout/.seeded ]; then
  echo 0 > /var/lib/checkout/checkout-api.degraded
  touch /var/lib/checkout/.seeded
fi

/usr/sbin/sshd -t
echo "==> sshd configuration valid; starting services"
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
