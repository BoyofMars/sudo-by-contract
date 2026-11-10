# Sudo by Contract — demo server.
#
# A Debian host running real OpenSSH with:
#   * TrustedUserCAKeys = the environment CA derived by the NEAR MPC network
#     for the policy contract (no CA private key exists anywhere),
#   * `Match User sbc-agent` → ForceCommand /usr/local/sbin/sbc-gate,
#   * sudoers rules for exactly the enrolled services,
#   * toy services (checkout-api, payments-api) under supervisord, because
#     containers do not run systemd. The gate's "supervisor" backend maps
#     `service.restart` onto `supervisorctl restart`; on real hosts use the
#     default "systemd" backend.

# ---- build the gate from this repository --------------------------------
FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY contracts ./contracts
RUN cargo build --release -p sbc-gate --locked

# ---- runtime -------------------------------------------------------------
FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server sudo supervisor python3 ca-certificates curl procps \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /var/log/supervisor /var/lib/checkout /etc/sbc /etc/ssh/sbc_principals

# The agent's login user: no usable password, no authorized_keys, certificates
# only. ('*' rather than a '!'-locked password: with UsePAM=no sshd refuses
# '!'-locked accounts outright, even for certificate logins.)
RUN useradd --create-home --shell /bin/sh sbc-agent && usermod -p '*' sbc-agent

COPY --from=build /src/target/release/sbc-gate /usr/local/sbin/sbc-gate
COPY sandbox/demo-server/sshd_config /etc/ssh/sshd_config
COPY sandbox/demo-server/supervisord.conf /etc/supervisor/conf.d/sbc-demo.conf
COPY sandbox/demo-server/checkout_api.py /opt/demo/checkout_api.py
COPY sandbox/demo-server/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /usr/local/sbin/sbc-gate /entrypoint.sh

EXPOSE 22 8080
VOLUME ["/etc/sbc", "/etc/ssh/keys"]
ENTRYPOINT ["/entrypoint.sh"]
