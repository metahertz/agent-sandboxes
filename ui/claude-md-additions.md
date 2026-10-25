## Sandbox environment (agent-sandboxes)

This project is the agent-sandboxes workspace **{{workspace}}**. Claude Code (you) runs on
the host inside a nono sandbox. A browser, desktop, VS Code and shell run separately in a
Docker container that you reach through the `aio-sandbox` MCP server. The two behave
differently.

### Your own tools (Bash, Read, Edit, …)

- **Files:** you can write to this project (`{{project_dir}}`) and Claude Code's own
  config; most of the host is read-only or hidden. On a permission error, ask the user
  instead of looking for a way around it.
- **Network:** only through nono's proxy (`HTTPS_PROXY` / `HTTP_PROXY` are set). Allowed:
  {{network}}. Anything else gets a 403 from the proxy. Programs that ignore the proxy
  variables (database clients, raw sockets) can't connect at all.
- **No Docker, tmux, systemd or D-Bus:** Unix sockets are blocked except the SSH agent.
  On localhost you can reach only the sandbox container's port.
- **SSH and git:** an ssh-agent holds this workspace's keys (you never see the key
  files); `ssh` and `git` tunnel through the proxy, so the host must be allowed above.

### API tokens

Token variables hold placeholders, not the real secrets: the proxy puts the real token in
on the way to that API, and only if the request carries the placeholder exactly as the
variable holds it. Never ask the user for a real token, and don't try to print or decode
one; a 64-character hex value is the expected placeholder.

{{tokens}}

### The aio-sandbox MCP server (browser, shell and files in the container)

- **It's a different machine:** the project is mounted at `{{container_dir}}` there, not
  at `{{project_dir}}`. Translate paths between the two.
- **No SSH keys or API tokens there.** Don't copy secrets or token placeholders into it.
- **Its network is not covered by this workspace's allowlist.** Don't use it to reach
  hosts the allowlist blocks.
- Use it for browsing, screenshots, and anything that needs a desktop or a full Linux
  userland (system packages, GUI apps).
