#!/usr/bin/env bash
# nono before-hook. Install to ~/.config/nono/hooks/aio-env.sh (chmod 700).
#
# Finds the workspace whose WS_DIR is $NONO_WORKDIR and exports its
# AIO_PORT / AIO_KEY into the sandboxed process via $NONO_ENV_FILE.
# Keys live in ~/agent-sandboxes/workspaces, never in the project tree.
set -euo pipefail

WS_ROOT="${AIO_WORKSPACES:-$HOME/agent-sandboxes/workspaces}"
[[ -d "$WS_ROOT" && -n "${NONO_ENV_FILE:-}" && -n "${NONO_WORKDIR:-}" ]] || exit 0
workdir="$(realpath -- "$NONO_WORKDIR")"

for f in "$WS_ROOT"/*.env; do
  [[ -r "$f" ]] || continue
  WS_DIR= WS_PORT= WS_KEY=
  source "$f"
  if [[ -n "$WS_DIR" && "$(realpath -m -- "$WS_DIR")" == "$workdir" ]]; then
    printf 'AIO_PORT=%s\nAIO_KEY=%s\n' "$WS_PORT" "$WS_KEY" >> "$NONO_ENV_FILE"
    exit 0
  fi
done
