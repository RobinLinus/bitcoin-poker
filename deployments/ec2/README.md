# Deploying the hosted app

This is the deployment runbook for agents working in this repository. Run local
commands from the repository root. Deploy when the user requests deployment or
has authorized updating the hosted app; documentation-only changes need no build
or service restart.

## Target and service layout

| Item | Value |
| --- | --- |
| SSH | `ssh -o HostKeyAlias=3.122.53.147 ubuntu@18.192.254.198` (existing SSH key; no password) |
| Public app | https://poker.bitvm.org/ |
| Elastic IP | `18.192.254.198` |
| Remote source | `/home/ubuntu/bitcoin-poker` |
| Installed executable | `/opt/bitcoin-poker/poker-relay` |
| Active configuration | `/opt/bitcoin-poker/deployment.json` |
| Configuration source | `deployments/mutinynet/onchain-test.json` |
| systemd service/user | `poker-relay` |
| Internal HTTP listener | `127.0.0.1:3102` |
| HTTPS proxy | `caddy`, configured by `/etc/caddy/Caddyfile` |

Public TCP ports 80 and 443 must be allowed in the EC2 security group. Caddy
terminates HTTPS on the EC2 instance and renews its Let's Encrypt certificate
automatically. `sslip.io` was a DNS service, not an external HTTP/TLS proxy; both
hostnames use the same local Caddy-to-relay hop.

Use `18.192.254.198` for SSH/SCP deployments and `https://poker.bitvm.org/`
for browser checks and shared links. Do not deploy to the old IP.

The instance moved from `3.122.53.147` to the Elastic IP `18.192.254.198` on September 8, 2026.
Its existing SSH host key was verified using `HostKeyAlias=3.122.53.147`; retain
that verification when using the new address. `poker.bitvm.org` has the correct
A record. At deployment its AAAA record still pointed to the unrelated
`2a01:4f8:d0a:52ab::2` and must be removed: the EC2 instance has no public IPv6
address. Until that DNS correction propagates, ordinary IPv6 clients can reach
the wrong server; `curl -4` can verify the EC2 deployment independently.

The certificate for `poker.bitvm.org` was issued successfully on September 8,
2026. HTTP on the new instance IP redirects to this hostname. The old
`3-122-53-147.sslip.io` virtual host remains configured without a cross-origin
redirect, but its public DNS still points to the old instance IP. Do not clear
or migrate browser wallet/game storage as part of a hostname change: storage
belongs to the exact browser origin. The old origin can be checked against the
new instance with curl's `--resolve` while preserving TLS validation.

The relay is transient. It does not load a game database or run a recovery
monitor. Restarting loses its in-memory rooms; browsers with the reconnect fix
recreate rooms and replay their saved messages. Older tabs need to reload to
pick up new JavaScript. Never clear browser wallet storage as a deployment step.

## 1. Inspect and prepare

```sh
git status --short
ssh -o BatchMode=yes -o HostKeyAlias=3.122.53.147 -o ConnectTimeout=15 ubuntu@18.192.254.198 \
  'systemctl is-active poker-relay caddy; systemctl cat poker-relay; df -h /; free -h'
```

Other agents may be editing the shared checkout. Inspect the diff and remote
source before uploading. The working tree and remote tree can intentionally
differ: do not overwrite unrelated in-progress work or blindly deploy the whole
checkout. Include all modules imported by the changed code, their relay asset
routes, and any required Cargo manifest/lockfile changes.

Browser JavaScript, HTML, CSS, and Wasm are embedded in the Rust executable.
Uploading a web file alone does **not** update the running app. Run checks relevant
to the change, for example:

```sh
node scripts/test-browser.mjs
cargo test -p poker-relay --offline
cargo build -p poker-relay --offline
```

When Rust sources for browser Wasm change, rebuild those artifacts first using
`scripts/build-session-wasm.sh` or `scripts/build-browser-wasm.sh` as appropriate.
These use the project's Docker toolchain. Upload the generated Wasm and its
matching `apps/web/public/wasm/manifest.json` together. Do not replace pinned Wasm
with an arbitrary host build.

UI changes also require rebuilding and restarting the **local** relay with its
existing configuration, then checking its served assets. Inspect its process
command first: the local instance has used `target/release/poker-relay`, so an
offline debug build alone does not update it. Never upload that macOS executable
to the Linux server.

## 2. Upload the intended source changes

Example for a CSS-only change:

```sh
scp -o BatchMode=yes -o HostKeyAlias=3.122.53.147 apps/web/src/ui/styles.css \
  ubuntu@18.192.254.198:/home/ubuntu/bitcoin-poker/apps/web/src/ui/styles.css
```

For multiple files, use an explicit reviewed list. A tar archive preserves paths;
`COPYFILE_DISABLE=1` avoids macOS metadata files:

```sh
COPYFILE_DISABLE=1 tar -czf /tmp/poker-deploy.tar.gz \
  apps/web/index.html apps/web/src/ui/styles.css
scp -o BatchMode=yes -o HostKeyAlias=3.122.53.147 /tmp/poker-deploy.tar.gz ubuntu@18.192.254.198:/tmp/
ssh -o BatchMode=yes -o HostKeyAlias=3.122.53.147 ubuntu@18.192.254.198 \
  'tar -xzf /tmp/poker-deploy.tar.gz -C /home/ubuntu/bitcoin-poker'
```

Replace that example list with the actual files needed by the change. Do not
upload `.git`, `target`, local databases, wallet keys, or other local secrets.
Avoid `rsync --delete` against the remote source tree. If the local file contains
unrelated changes, apply a narrow reviewed patch to the remote file instead.

## 3. Build and activate over SSH

The instance has approximately 1 GB RAM. Build serially with LTO disabled. The
initial deployment installed Ubuntu's Rust/Cargo packages and created a 1 GB
swap file for build headroom. The remote source does not contain the local
`rust-toolchain.toml`; do not assume rustup or the local pinned toolchain is
installed. Check compatibility if a change requires a newer compiler.

```sh
ssh -o BatchMode=yes -o HostKeyAlias=3.122.53.147 ubuntu@18.192.254.198 'set -eu
  cd /home/ubuntu/bitcoin-poker
  CARGO_BUILD_JOBS=1 CARGO_PROFILE_RELEASE_LTO=false \
    cargo build -p poker-relay --release --locked > /tmp/poker-build.log 2>&1
  sudo cp -p /opt/bitcoin-poker/poker-relay /opt/bitcoin-poker/poker-relay.previous
  sudo install -m 755 target/release/poker-relay /opt/bitcoin-poker/poker-relay.next
  sudo mv /opt/bitcoin-poker/poker-relay.next /opt/bitcoin-poker/poker-relay
  sudo systemctl restart poker-relay
  systemctl is-active poker-relay
'
```

A failed build must not restart the service or replace the running binary.
Inspect `/tmp/poker-build.log` if this command fails. Routine app updates do not
require restarting Caddy or replacing the active deployment configuration.

The checked-in `poker-relay.service` and `Caddyfile` in this directory document
the installed services. If intentionally changing them, validate the Caddyfile
before reloading Caddy, and run `systemctl daemon-reload` before restarting a
changed systemd unit. Both services are enabled at boot.

## 4. Verify before reporting it live

```sh
ssh -o BatchMode=yes -o HostKeyAlias=3.122.53.147 ubuntu@18.192.254.198 \
  'systemctl is-active poker-relay caddy; sha256sum /opt/bitcoin-poker/poker-relay /home/ubuntu/bitcoin-poker/target/release/poker-relay'
curl -fsSI http://18.192.254.198/
curl -fsS https://poker.bitvm.org/api/v1/config
curl -fsS https://poker.bitvm.org/src/ui/styles.css -o /tmp/poker-served.css
cmp apps/web/src/ui/styles.css /tmp/poker-served.css
```

The installed and built executable hashes should match. HTTP should redirect to
HTTPS. Compare the actual changed assets, not just the CSS example above. When
you applied a narrow remote patch, compare served bytes with that remote source
instead of an unrelated local version.

For browser changes, check the public URL in an isolated browser: valid HTTPS,
no page errors, and the changed behavior. Wallet onboarding can be checked
without funding a wallet or starting a game. For transport changes, use isolated
rooms and simulated messages. Do not spend player funds merely to verify a
deployment. Tell users to reload both tabs when a fix requires new browser code.

## Troubleshooting and rollback

```sh
ssh -o HostKeyAlias=3.122.53.147 ubuntu@18.192.254.198 \
  'sudo journalctl -u poker-relay -n 60 --no-pager; sudo journalctl -u caddy -n 40 --no-pager; tail -30 /tmp/poker-build.log'
```

If local HTTP works on the instance but public traffic times out, check the EC2
security group and host firewall. Certificate issuance also requires public
reachability. Do not work around TLS failures by disabling certificate checks.

To restore the saved executable after a bad deployment:

```sh
ssh -o HostKeyAlias=3.122.53.147 ubuntu@18.192.254.198 'set -eu
  sudo install -m 755 /opt/bitcoin-poker/poker-relay.previous /opt/bitcoin-poker/poker-relay.next
  sudo mv /opt/bitcoin-poker/poker-relay.next /opt/bitcoin-poker/poker-relay
  sudo systemctl restart poker-relay
  systemctl is-active poker-relay
'
```

Reverify the public app afterward. Restore a changed configuration separately
if necessary; executable rollback does not undo source or configuration edits.
