# Agent Sandboxes

Run several Claude Code projects side by side on one host. Each **workspace** is a
project folder, a Claude Code session confined by [nono](https://github.com/nolabs-ai/nono),
and its own [AIO Sandbox](https://github.com/agent-infra/sandbox) container (Chromium,
VNC, VS Code, shell, MCP) that only that session can reach. A web UI manages it all.

## Architecture

```mermaid
flowchart LR
  user([Your browser])

  subgraph host[Host]
    ui["sandbox-ui<br/>systemd · Python · TLS"]
    tmux["tmux"]
    subgraph nono["nono sandbox (per workspace)"]
      claude["Claude Code"]
    end
    proj[("project folder<br/>~/projects/&lt;name&gt;")]
    agent["ssh-agent<br/>(per workspace)"]
    pool[("secrets/<br/>SSH keys · API tokens")]
    subgraph docker["Docker container aio-&lt;name&gt;"]
      aio["AIO Sandbox<br/>Chromium · VNC · VS Code · shell · MCP"]
    end
  end
  net((Internet))

  user -- "HTTPS :443 UI<br/>:91xx sandbox views" --> ui
  ui -- "pty" --> tmux --> claude
  ui -- "docker compose" --> docker
  ui -- "reverse proxy, injects API key" --> aio
  claude -- "MCP 127.0.0.1:81xx only" --> aio
  claude -- "r/w" --> proj
  aio -- "bind mount /home/gem/workspace" --> proj
  claude -- "allowlisted, via nono proxy<br/>(HTTPS and SSH; tokens injected)" --> net
  claude -- "socket only" --> agent
  ui -- "loads assigned keys" --> agent
  pool -. "read by UI / nono proxy only" .-> agent
  aio -- "unfiltered" --> net
```

- **Claude (nono):** reads/writes its project folder; reaches only its own sandbox port
  on localhost; internet limited to the workspace's allowlist; no Unix sockets except its
  own ssh-agent (so no Docker, tmux, D-Bus). Per-workspace settings (the **Access** tab)
  are rendered to `workspaces/<name>.profile.json`, which extends `claude-browser`.
- **Keys & tokens:** a pool in `secrets/`, assigned per workspace. SSH keys are loaded
  into that workspace's ssh-agent (live — unticking a key revokes it from a running
  session); Claude gets the socket, never the file. API tokens use nono's phantom-token
  proxy: Claude sees a placeholder, the proxy injects the real token only towards that
  service.
- **Container:** sees only its project folder; its API key is enforced, held by the
  UI and injected into Claude via a nono hook. Never in the repo.
- **Monitoring (optional):** Alloy → Prometheus + Loki → Grafana, see below.
- **UI:** token login, same-origin API, per-workspace capability URLs for sandbox views.
  Runs as your user with only `CAP_NET_BIND_SERVICE`, which it clears from the
  inheritable set once 443 is bound.

## Where things live

| Path | What |
|---|---|
| `ui/server.py`, `ui/static/` | Web UI (stdlib Python; vanilla JS; xterm.js 5.5.0 vendored, MIT) |
| `bin/sandbox-ui` | UI launcher (systemd `ExecStart`) |
| `bin/sandbox-ui-cert` | Private, name-constrained CA + server cert in `ui/tls/` |
| `bin/claude-in <name>` | Claude Code inside nono for one workspace (prepares agent + profile) |
| `libexec/ssh-proxy-connect` | SSH `ProxyCommand` through nono's proxy (readable in the sandbox) |
| `compose.workspace.yaml` | Container template (compose project `aio-<name>`) |
| `nono/claude-browser.jsonc` → `~/.config/nono/profiles/` | nono profile |
| `nono/aio-env.sh` → `~/.config/nono/hooks/` | nono hook: gives Claude its sandbox port/key |
| `systemd/agent-sandboxes-ui.service` → `/etc/systemd/system/` | Service unit |
| `mcp.json.template` → `<project>/.mcp.json` | Claude's MCP link to its sandbox |
| `ui/tmux.conf` | tmux server for Claude sessions (`tmux -L agent-sandboxes`) |
| `workspaces/<name>.env` ✱ | Per-workspace folder, port, API key |
| `workspaces/<name>.policy.json` ✱, `.profile.json` ✱ | Access settings; nono profile last used to start Claude |
| `secrets/ssh/`, `secrets/tokens/` ✱ | Key / token pool (0600; never readable inside nono) |
| `state/<name>/` ✱ | Workspace `ssh_config` and `known_hosts` (Claude-writable) |
| `$XDG_RUNTIME_DIR/agent-sandboxes/<name>/agent.sock` ✱ | Workspace ssh-agent |
| `ui/token` ✱, `ui/tls/` ✱, `ui/extra-hostnames` ✱ | Login token, TLS keys, extra DNS names |
| `bin/export-claude-project` | Run on another machine: sends a project + its Claude history to the inbox |
| `bin/ws-ssh` | SSH forced command for upload and per-workspace keys |
| `inbox/<folder>/` ✱ | Uploaded projects waiting for *Import* |
| `secrets/ssh-access.json` ✱ → `~/.ssh/authorized_keys` | Upload / workspace SSH keys (a marked block in that file) |
| `bin/monitoring`, `monitoring/compose.yaml` | Monitoring stack (compose project `agent-sandboxes-mon`) |
| `ui/exporter.py`, `systemd/agent-sandboxes-exporter.service` | Workspace metrics + nono audit events (user unit) |
| `monitoring/alloy/`, `prometheus/`, `loki/` | Collector and storage config |
| `monitoring/grafana/build-dashboards.py` → `dashboards/*.json` | Provisioned dashboards (edit the script, re-run) |
| `monitoring/.env` ✱, `monitoring/data/` ✱, `secrets/grafana-admin-password` ✱ | Monitoring settings, exporter output, Grafana data |

✱ created at runtime, git-ignored.

## Setup

Requires Linux with Landlock, Docker + compose, nono, tmux, python3 (3.11+), openssl and
Claude Code. Paths assume a clone at `~/agent-sandboxes` and the unit's user `metahertz`
(uid 1000); edit the unit and `nono/claude-browser.jsonc` hook path otherwise.

```bash
git clone <repo> ~/agent-sandboxes && cd ~/agent-sandboxes

nono pull nolabs-ai/claude
mkdir -p ~/.config/nono/{profiles,hooks}
cp nono/claude-browser.jsonc ~/.config/nono/profiles/
install -m 700 nono/aio-env.sh ~/.config/nono/hooks/
docker pull ghcr.io/agent-infra/sandbox:1.11.0

cp ui/extra-hostnames.example ui/extra-hostnames   # optional: add the host's DNS name

sudo install -m 644 systemd/agent-sandboxes-ui.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now agent-sandboxes-ui
sudo ufw allow from <your-subnet> to any port 443,9101:9199 proto tcp
```

Then, on the machine you browse from, import `ui/tls/ca.crt` as a trusted CA (it's also
at `https://<host>/ca.crt`; check the fingerprint in `journalctl -u agent-sandboxes-ui`)
and open `https://<host>/login?token=$(cat ~/agent-sandboxes/ui/token)`.

## Usage

- **New workspace** in the sidebar: name + optional folder (default `~/projects/<name>`).
  Creates the folder, `.mcp.json`, key and port, and starts the container.
- **Tabs:** *Claude* (sandboxed session, survives closing the tab) · *Browser* (live VNC,
  shared with Claude) · *VS Code* and *Terminal* (inside the container) · *Access* (SSH
  keys, API tokens, network allowlist, memory/process limits) · *Files* (browse/download
  from the container) · *Logs*.
- **Keys & tokens** (sidebar): generate or import SSH keys (copy the public key into
  GitHub etc.), add API tokens (GitHub, GitLab, OpenAI, Gemini, or any HTTPS API), and tick
  which workspaces get each. Inside the sandbox, `git` uses the keys via `GIT_SSH_COMMAND`;
  SSH hosts must be on the allowlist (add e.g. `git.example.com` under *Also allow*).
  Network, token and limit changes need a Claude restart; the header says when.
- **Network allowlist** (*Access* tab): domains, `*.domain` wildcards and IP addresses
  (IPv4, or IPv6 in canonical form; no CIDR ranges: nono's proxy matches hosts only).
  An allowed host is reachable on every port. `host:port` or `host:lo-hi` (`[v6]:port`)
  limits it to those ports: nono can't filter ports, so a workspace with such entries
  gets the UI server's port filter (`127.0.0.1:<sandbox port − 1000>`) as nono's
  `upstream_proxy`. nono checks the host first and the filter then checks the port, and
  port changes apply without a restart. While the UI server is down, such workspaces
  have no outbound network. Loopback, `0.0.0.0` and link-local addresses are refused,
  including names that resolve to them. Only programs that use `HTTPS_PROXY` (or, for
  SSH, `ssh-proxy-connect`) get out; raw TCP clients such as `psql` stay blocked.
- **Import** (sidebar): projects from other machines, with their Claude Code history.
  See [Importing projects](#importing-projects).
- **Remote terminal** (*Access* tab): SSH keys that reach one workspace only. See
  [SSH into a workspace](#ssh-into-a-workspace).
- **Settings** (sidebar): monitoring — dashboards link, local or external Prometheus /
  Loki, local Grafana address and retention, Claude Code telemetry — with *Save & apply*
  and *Stop monitoring*. See [Monitoring](#monitoring).
- **Shell access:** `bin/claude-in <name>` runs a workspace's Claude directly;
  `tmux -L agent-sandboxes attach -t cl-<name>` attaches to a UI-started session.
- **Service:** `sudo systemctl restart agent-sandboxes-ui` after editing `ui/server.py`;
  static files reload on browser refresh.

## Importing projects

On the machine the project is on now (Linux or macOS, python3 + rsync), get
`export-claude-project` (link on the *Import* page, or `bin/` here) and run:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/sandboxes-upload     # add the .pub under Import → Upload keys
python3 export-claude-project ~/code/my-app --to metahertz@<host> -i ~/.ssh/sandboxes-upload
```

It uploads to `inbox/my-app/`: the folder (with `.git`, `.claude/`, `CLAUDE.md`; without
`node_modules`, `.venv`, `__pycache__` unless `--include-all`), plus `.claude-import/` with
the project's Claude Code sessions and auto-memory (`~/.claude/projects/<project>/`), their
file checkpoints and todos, its prompt history, and a manifest (sent last, so a half-done
upload isn't importable). Upload keys can only rsync into the inbox (`rrsync -wo -munge`:
no shell, no reading; symlinks are stored defused and restored on import). With a normal
login use `--to user@host:agent-sandboxes/inbox`; or `--out DIR` and copy the folder in
any way. A plain folder with no `.claude-import/` imports too, without history.

*Import* moves the folder to `~/projects/<name>` (or the folder you give; never merging
into an existing one), creates the workspace, and installs the history under the new path
(`cwd` in transcripts rewritten), so `/resume` and `claude -c` pick conversations up.

## SSH into a workspace

Keys added in a workspace's *Access → Remote terminal* get a forced command
(`bin/ws-ssh <name>`, `restrict`) in `~/.ssh/authorized_keys`:

```bash
ssh -t -i ~/.ssh/key me@host            # attach to its Claude session (started if needed)
ssh -t -i ~/.ssh/key me@host shell      # bash inside the workspace's nono sandbox
ssh -i ~/.ssh/key me@host 'git status'  # any command, in the sandbox; rsync / scp / sftp too
```

Everything except the Claude session runs through `claude-in --shell / --exec`, i.e. under
that workspace's own nono profile: the key reaches exactly what Claude there can. No port
forwarding. tmux is configured so attached clients (SSH or the web terminal) can only
detach (`C-b d`) and scroll (`C-b [`), not open windows or switch sessions. Use a key per
workspace, and not one that already logs in to the account unrestricted (sshd would use
that line first; the UI refuses such keys).

## Monitoring

Start it from **Settings → Save & apply** in the UI, or from a shell:

```bash
bin/monitoring up          # first run writes monitoring/.env; also starts the exporter
bin/monitoring password    # Grafana admin password (also on the Settings page)
sudo ufw allow from <your-subnet> to any port 3000 proto tcp
```

Grafana is at `https://<host>:3000/` (same certificate as the UI), with two dashboards
in *Agent Sandboxes*: **overview** (every workspace's sandbox / Claude / policy state,
CPU and memory, tokens and cost, network denials, host) and **workspace** (one
workspace in detail, with its logs). What's collected:

| Source | Into | What |
|---|---|---|
| `ui/exporter.py` (every 15 s) | Prometheus `aio_*` | Container up/healthy, Claude running, policy pending, keys/tokens, limits, project size; Claude scope CPU / memory / processes / OOM kills |
| nono audit trail (via the exporter) | Loki `{source="nono"}`, `aio_nono_*` | Session start/end, every connection allowed or denied, with workspace |
| Claude Code OpenTelemetry | Loki `{service_name="claude-code"}`, Prometheus `claude_code_*` | API requests (tokens, cost, model), tool use and decisions, errors; prompt and response text stays redacted |
| cAdvisor (in Alloy) | Prometheus `container_*{workspace=…}` | Sandbox container CPU, memory, network |
| node exporter (in Alloy) | Prometheus `node_*` | Host CPU, memory, disk, load |
| Docker, journald | Loki `{source="docker"}`, `{source="journal"}` | `aio-*` / `mon-*` container logs; system journal |

Once `monitoring/.env` exists (and unless telemetry is switched off in Settings,
`CLAUDE_TELEMETRY=0`), workspace profiles add Claude Code's telemetry settings and open
localhost:4318 (Alloy's OTLP receiver) to the sandbox, so sessions started from then on
report. Prometheus and Loki aren't published outside the compose network.

To use an external Prometheus and Grafana, choose **External** under *Where data goes*
(`MON_STACK=0`) with its remote-write and Loki URLs, set the **Dashboards URL**
(`MONITORING_URL`) to your Grafana, import `monitoring/grafana/dashboards/*.json` there
(datasource UIDs `prometheus` and `loki`), then *Save & apply*: only Alloy and the
exporter keep running here; the local containers are removed, their volumes kept.
Remote-write / Loki authentication isn't wired up yet. Default retention: 30 days / 5 GB of metrics, 14 days of logs.

After updating, a tmux server that was already running keeps its old key bindings:
`tmux -L agent-sandboxes source-file ui/tmux.conf` applies the locked-down ones.

Claude always runs in a `systemd --user` scope (`claude-<name>-<pid>`, for resource
limits and its metrics), which needs lingering (`sudo loginctl enable-linger <user>`).

**Known gaps:** every workspace's Claude shares `~/.claude` (settings, credentials,
transcripts) and `/tmp/claude-$UID`; container egress is unfiltered; SSH host keys are
trust-on-first-use per workspace; pool secrets are unencrypted at rest (like `~/.ssh`);
telemetry's `workspace` label is set by the sandbox, so a workspace could mislabel its
own Claude metrics (nono and container data are labelled outside it); Alloy has the
Docker socket (root-equivalent, as any container monitor does); imported history lands in
that shared `~/.claude` too; upload and workspace SSH keys log in as this account (their
forced command is the boundary), and an upload key can fill the disk.
