#!/usr/bin/env python3
"""Generates the provisioned Grafana dashboards (dashboards/*.json).

Edit here, then run:  python3 monitoring/grafana/build-dashboards.py
Grafana re-reads the files within 30s. Datasource UIDs are fixed by
provisioning/datasources/datasources.yaml.
"""

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dashboards"
PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}
WS = 'workspace="$workspace"'

# Workspace colours follow the name, so filtering never repaints the survivors.
BY_NAME = {"mode": "palette-classic-by-name"}
UP = [{"type": "value", "options": {
    "0": {"text": "✗ down", "color": "red", "index": 0},
    "1": {"text": "✓ up", "color": "green", "index": 1}}}]
RUNNING = [{"type": "value", "options": {
    "0": {"text": "– stopped", "color": "text", "index": 0},
    "1": {"text": "● running", "color": "green", "index": 1}}}]
PENDING = [{"type": "value", "options": {
    "0": {"text": "✓ applied", "color": "green", "index": 0},
    "1": {"text": "⚠ restart Claude", "color": "orange", "index": 1}}}]
HEALTHY = [{"type": "value", "options": {
    "0": {"text": "✗ unhealthy", "color": "orange", "index": 0},
    "1": {"text": "✓ healthy", "color": "green", "index": 1}}}]


class Board:
    def __init__(self):
        self.panels: list[dict] = []
        self.x = self.y = self.row_h = 0
        self.next_id = 1

    def add(self, panel: dict, w: int, h: int) -> dict:
        if self.x + w > 24:
            self.x, self.y = 0, self.y + self.row_h
            self.row_h = 0
        panel["id"] = self.next_id
        panel["gridPos"] = {"x": self.x, "y": self.y, "w": w, "h": h}
        self.next_id += 1
        self.x += w
        self.row_h = max(self.row_h, h)
        self.panels.append(panel)
        return panel

    def row(self, title: str):
        self.x, self.y = 0, self.y + self.row_h
        self.row_h = 0
        self.add({"type": "row", "title": title, "collapsed": False, "panels": []}, 24, 1)
        self.x, self.y, self.row_h = 0, self.y + 1, 0


def prom(expr: str, legend: str = "", ref: str = "A", instant=False, fmt="time_series") -> dict:
    t = {"datasource": PROM, "refId": ref, "expr": expr, "legendFormat": legend or "__auto",
         "format": fmt}
    if instant:
        t.update(instant=True, range=False)
    return t


def loki(expr: str, ref: str = "A", instant=False, legend: str = "") -> dict:
    t = {"datasource": LOKI, "refId": ref, "expr": expr, "queryType": "instant" if instant else "range"}
    if legend:
        t["legendFormat"] = legend
    return t


def stat(title, targets, unit="none", mappings=None, thresholds=None, desc="", text_mode="value",
         color_mode="value", decimals=None):
    d = {"unit": unit, "mappings": mappings or [], "color": {"mode": "thresholds"},
         "thresholds": {"mode": "absolute", "steps": thresholds or [{"color": "text", "value": None}]}}
    if decimals is not None:
        d["decimals"] = decimals
    return {"type": "stat", "title": title, "description": desc, "targets": targets,
            "datasource": targets[0]["datasource"],
            "fieldConfig": {"defaults": d, "overrides": []},
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                        "colorMode": color_mode, "graphMode": "none", "textMode": text_mode,
                        "justifyMode": "center", "wideLayout": True}}


def ts(title, targets, unit="none", desc="", stack=False, bars=False, overrides=None, min0=True,
       legend="list"):
    custom = {"lineWidth": 2, "fillOpacity": 8 if not bars else 85, "showPoints": "never",
              "spanNulls": 60000, "gradientMode": "none",
              "drawStyle": "bars" if bars else "line",
              "stacking": {"mode": "normal" if stack else "none", "group": "A"},
              "axisSoftMin": 0 if min0 else None}
    return {"type": "timeseries", "title": title, "description": desc, "targets": targets,
            "datasource": targets[0]["datasource"],
            "fieldConfig": {"defaults": {"unit": unit, "color": BY_NAME, "custom": custom},
                            "overrides": overrides or []},
            "options": {"legend": {"displayMode": legend, "placement": "bottom", "showLegend": True,
                                   "calcs": ["lastNotNull", "max"] if legend == "table" else []},
                        "tooltip": {"mode": "multi", "sort": "desc"}}}


def dashed(name_regex: str) -> dict:
    """Override: draw limit series as a thin dashed line, no fill."""
    return {"matcher": {"id": "byRegexp", "options": name_regex},
            "properties": [{"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [6, 4]}},
                           {"id": "custom.lineWidth", "value": 1},
                           {"id": "custom.fillOpacity", "value": 0},
                           {"id": "color", "value": {"mode": "fixed", "fixedColor": "text"}}]}


def table(title, targets, overrides, rename, exclude=(), desc="", sort=None, transforms_extra=(),
          join=None):
    if "Value" in rename:      # single-query Loki tables name it either way
        rename = {**rename, "Value #A": rename["Value"]}
    if join:                   # outer join keeps only the renamed columns
        exclude = ()
    org = {"excludeByName": {k: True for k in exclude}, "renameByName": rename,
           "indexByName": {k: i for i, k in enumerate(rename)}}
    return {"type": "table", "title": title, "description": desc, "targets": targets,
            "datasource": targets[0]["datasource"],
            "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}},
                                         "color": {"mode": "thresholds"},
                                         "thresholds": {"mode": "absolute",
                                                        "steps": [{"color": "text", "value": None}]}},
                            "overrides": overrides},
            "options": {"showHeader": True, "cellHeight": "sm",
                        "sortBy": [{"displayName": sort, "desc": False}] if sort else []},
            "transformations": [*([{"id": "labelsToFields", "options": {"mode": "columns"}}]
                                   if targets[0]["datasource"] is LOKI else []),
                                *([{"id": "joinByField", "options": {"byField": join, "mode": "outer"}},
                                   {"id": "filterFieldsByName", "options": {"include": {"names": list(rename)}}}]
                                  if join else [{"id": "merge", "options": {}}]),
                                {"id": "organize", "options": org}, *transforms_extra]}


def col(name, unit=None, mappings=None, color_text=False, link=None, width=None):
    props = []
    if unit:
        props.append({"id": "unit", "value": unit})
    if mappings:
        props.append({"id": "mappings", "value": mappings})
    if color_text:
        props.append({"id": "custom.cellOptions", "value": {"type": "color-text"}})
    if link:
        props.append({"id": "links", "value": [{"title": "Open workspace", "url": link}]})
    if width:
        props.append({"id": "custom.width", "value": width})
    return {"matcher": {"id": "byName", "options": name}, "properties": props}


def logs(title, expr, desc=""):
    return {"type": "logs", "title": title, "description": desc, "datasource": LOKI,
            "targets": [loki(expr)],
            "options": {"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending",
                        "enableLogDetails": True, "dedupStrategy": "none",
                        "prettifyLogMessage": False, "showLabels": False}}


def dashboard(uid, title, board, variables=(), desc="", links=()):
    return {"uid": uid, "title": title, "description": desc, "tags": ["agent-sandboxes"],
            "timezone": "browser", "editable": False, "graphTooltip": 1,
            "time": {"from": "now-6h", "to": "now"}, "refresh": "30s",
            "schemaVersion": 39, "version": 1, "fiscalYearStartMonth": 0,
            "templating": {"list": list(variables)}, "annotations": {"list": []},
            "links": list(links), "panels": board.panels}


def api(sel: str, field: str, by: str = "", rng: str = "$__interval") -> str:
    """Sum a numeric field of Claude Code's api_request events (exact, per request)."""
    agg = f"sum by ({by})" if by else "sum"
    return (f'{agg} (sum_over_time({{service_name="claude-code", {sel}}} | event_name="api_request"'
            f' | unwrap {field} [{rng}]))')


TOKEN_FIELDS = (("input_tokens", "input"), ("output_tokens", "output"),
                ("cache_read_tokens", "cache read"), ("cache_creation_tokens", "cache write"))


def tokens(sel: str, by: str = "", rng: str = "$__interval") -> str:
    return " + ".join(api(sel, f, by, rng) for f, _ in TOKEN_FIELDS)


CPU = 'sum by (workspace) (rate(container_cpu_usage_seconds_total{workspace!=""}[$__rate_interval]))'
MEM = 'sum by (workspace) (container_memory_working_set_bytes{workspace!=""})'
DENY_HOSTS = '{source="nono", decision="deny"} | json | target !~ "unix:.*"'
DENY_SOCKS = '{source="nono", decision="deny"} | json | target =~ "unix:.*"'
NONO_LINE = ('line_format "{{.workspace}}  {{.decision | upper}}  {{.target}}'
             '{{if .port}}:{{.port}}{{end}}  {{.reason}}{{.command}}"')


def overview() -> dict:
    b = Board()
    T = 'workspace=~"$workspace"'
    tiles = [
        stat("Sandboxes", [prom("sum(aio_workspace_container_up{%s})" % T, instant=True)],
             desc="AIO Sandbox containers running"),
        stat("Claude", [prom("sum(aio_workspace_claude_running{%s})" % T, instant=True)]),
        stat("Pending", [prom("sum(aio_workspace_policy_pending{%s})" % T, instant=True)],
             thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
             desc="Workspaces whose saved access policy needs a Claude restart to apply"),
        stat("Denials", [prom('sum(increase(aio_nono_network_events_total{decision="deny",%s}[$__range]))' % T,
                                      instant=True)], decimals=0,
             desc="Connections nono refused in the selected time range"),
        stat("Tokens", [loki(tokens(T, rng="$__range"), instant=True)], unit="short", decimals=1,
             desc="All token types, selected time range"),
        stat("Cost", [loki(api(T, "cost_usd", rng="$__range"), instant=True)], unit="currencyUSD",
             decimals=2,
             desc="Estimated API-equivalent cost reported by Claude Code, selected time range"),
    ]
    for t in tiles:
        b.add(t, 4, 4)

    q = [prom("aio_workspace_info{%s}" % T, ref="A", instant=True, fmt="table"),
         prom("aio_workspace_container_up{%s}" % T, ref="B", instant=True, fmt="table"),
         prom("aio_workspace_claude_running{%s}" % T, ref="C", instant=True, fmt="table"),
         prom("aio_workspace_policy_pending{%s}" % T, ref="D", instant=True, fmt="table"),
         prom("aio_workspace_ssh_keys{%s}" % T, ref="E", instant=True, fmt="table"),
         prom("aio_workspace_tokens{%s}" % T, ref="F", instant=True, fmt="table"),
         prom(MEM.replace('workspace!=""', T), ref="G", instant=True, fmt="table"),
         prom("sum by (workspace) (aio_claude_memory_bytes{%s})" % T, ref="H", instant=True, fmt="table"),
         prom("aio_workspace_dir_bytes{%s}" % T, ref="I", instant=True, fmt="table"),
         prom('sum by (workspace) (increase(aio_nono_network_events_total{decision="deny",workspace!="-",%s}[$__range]))' % T,
              ref="J", instant=True, fmt="table")]
    rename = {"workspace": "Workspace", "Value #B": "Sandbox", "Value #C": "Claude",
              "Value #D": "Policy", "network": "Network", "Value #E": "SSH keys",
              "Value #F": "Tokens", "Value #G": "Sandbox mem", "Value #H": "Claude mem",
              "Value #I": "Project size", "Value #J": "Denials"}
    b.add(table("Workspaces", q, [
        col("Workspace", link="/d/aio-workspace/workspace?var-workspace=${__value.raw}&${__url_time_range}",
            width=140),
        col("Sandbox", mappings=UP, color_text=True), col("Claude", mappings=RUNNING, color_text=True),
        col("Policy", mappings=PENDING, color_text=True), col("Sandbox mem", unit="bytes"),
        col("Claude mem", unit="bytes"), col("Project size", unit="bytes"),
        col("Denials", unit="short"),
    ], rename, join="workspace",
        desc="Click a workspace for its detail dashboard", sort="Workspace"), 24, 7)

    b.row("Resources")
    b.add(ts("Sandbox CPU", [prom(CPU.replace('workspace!=""', T), "{{workspace}}")], "cores",
             desc="AIO Sandbox container, CPU cores in use (limit 2)"), 12, 8)
    b.add(ts("Sandbox memory", [prom(MEM.replace('workspace!=""', T), "{{workspace}}")], "bytes",
             desc="AIO Sandbox container working set (limit 2 GiB)"), 12, 8)
    b.add(ts("Claude CPU", [prom("sum by (workspace) (rate(aio_claude_cpu_seconds_total{%s}[$__rate_interval]))" % T,
                                 "{{workspace}}")], "cores",
             desc="Claude Code and everything it runs, from its systemd scope"), 12, 8)
    b.add(ts("Claude memory", [prom("sum by (workspace) (aio_claude_memory_bytes{%s})" % T, "{{workspace}}")],
             "bytes", desc="Claude Code and everything it runs, from its systemd scope"), 12, 8)

    b.row("Claude Code usage")
    b.add(ts("Tokens", [loki(tokens(T, "workspace"), legend="{{workspace}}")], "short", bars=True, stack=True,
             desc="Input, output and cache tokens per interval, per workspace"), 12, 8)
    b.add(ts("Cost", [loki(api(T, "cost_usd", "workspace"), legend="{{workspace}}")], "currencyUSD",
             bars=True, stack=True,
             desc="Estimated API-equivalent cost per interval, per workspace"), 12, 8)

    b.row("Sandbox network policy (nono)")
    b.add(ts("Denied connections", [prom('sum by (workspace) (increase(aio_nono_network_events_total{decision="deny",%s}[$__interval]))' % T,
                                         "{{workspace}}")], "short", bars=True, stack=True,
             desc="Connections nono refused, per interval"), 12, 8)
    b.add(table("Most denied hosts", [loki('topk(15, sum by (target, workspace) (count_over_time(%s [$__range])))'
                                           % DENY_HOSTS.replace('decision="deny"', 'decision="deny", %s' % T),
                                           instant=True)],
                [col("Count", unit="short")], {"target": "Host", "workspace": "Workspace", "Value": "Count"},
                exclude=("Time",), desc="Hosts not in a workspace's allowlist that something tried to reach",
                transforms_extra=[{"id": "sortBy", "options": {"sort": [{"field": "Count", "desc": True}]}}]),
          12, 8)
    b.add(logs("Recent denials", ('%s | %s' % (DENY_HOSTS.replace('decision="deny"', 'decision="deny", %s' % T), NONO_LINE))),
          24, 9)

    b.row("Host")
    exporter = stat("Exporter age", [prom("time() - aio_exporter_last_run_timestamp_seconds", instant=True)],
             unit="s", decimals=0,
             thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 90}],
             desc="Seconds since ui/exporter.py last wrote metrics (user unit agent-sandboxes-exporter)")
    b.add(ts("Host CPU", [prom('1 - avg(rate(node_cpu_seconds_total{mode="idle"}[$__rate_interval]))', "used")],
             "percentunit"), 5, 7)
    b.add(ts("Host memory", [prom("node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes", "used"),
                             prom("node_memory_MemTotal_bytes", "total", ref="B")], "bytes",
             overrides=[dashed("total")]), 5, 7)
    b.add(ts("Disk used", [prom('1 - node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}', "/")],
             "percentunit"), 5, 7)
    b.add(ts("Load", [prom("node_load1", "1m"), prom("node_load5", "5m", ref="B")], "short"), 5, 7)
    b.add(exporter, 4, 7)

    var = {"name": "workspace", "label": "Workspace", "type": "query", "datasource": PROM,
           "query": {"query": "label_values(aio_workspace_info, workspace)", "refId": "ws"},
           "definition": "label_values(aio_workspace_info, workspace)",
           "refresh": 2, "multi": True, "includeAll": True, "allValue": ".+",
           "current": {"text": "All", "value": "$__all"}, "sort": 1}
    return dashboard("aio-overview", "Agent Sandboxes — overview", b, [var],
                     desc="All workspaces: sandboxes, Claude sessions, policy, usage, denials, host")


def workspace() -> dict:
    b = Board()
    tiles = [
        stat("Sandbox", [prom("aio_workspace_container_up{%s}" % WS, instant=True)], mappings=UP),
        stat("Health", [prom("aio_workspace_container_healthy{%s}" % WS, instant=True)], mappings=HEALTHY),
        stat("Claude", [prom("aio_workspace_claude_running{%s}" % WS, instant=True)], mappings=RUNNING),
        stat("Policy", [prom("aio_workspace_policy_pending{%s}" % WS, instant=True)], mappings=PENDING),
        stat("Network", [prom("aio_workspace_info{%s}" % WS, "{{network}}", instant=True)], text_mode="name"),
        stat("SSH keys", [prom("aio_workspace_ssh_keys{%s}" % WS, instant=True)]),
        stat("API tokens", [prom("aio_workspace_tokens{%s}" % WS, instant=True)]),
        stat("Disk", [prom("aio_workspace_dir_bytes{%s}" % WS, instant=True)], unit="bytes",
             desc="Project folder size"),
    ]
    for t in tiles:
        b.add(t, 3, 4)

    b.row("Claude Code (nono sandbox)")
    b.add(ts("Claude memory", [prom("aio_claude_memory_bytes{%s}" % WS, "used"),
                               prom("aio_workspace_memory_limit_bytes{%s} > 0" % WS, "limit", ref="B")],
             "bytes", overrides=[dashed("limit")], desc="Claude's systemd scope; limit set in the Access tab"),
          8, 8)
    b.add(ts("Claude CPU", [prom("rate(aio_claude_cpu_seconds_total{%s}[$__rate_interval])" % WS, "cores")],
             "cores"), 8, 8)
    b.add(ts("Claude processes", [prom("aio_claude_pids{%s}" % WS, "processes"),
                                  prom("aio_workspace_pids_limit{%s} > 0" % WS, "limit", ref="B")],
             "short", overrides=[dashed("limit")]), 8, 8)

    b.row("AIO Sandbox container")
    lim = 'container_spec_memory_limit_bytes{%s} > 0' % WS
    b.add(ts("Sandbox CPU", [prom("sum(rate(container_cpu_usage_seconds_total{%s}[$__rate_interval]))" % WS, "cores")],
             "cores"), 8, 8)
    b.add(ts("Sandbox memory", [prom("sum(container_memory_working_set_bytes{%s})" % WS, "working set"),
                                prom("max(%s)" % lim, "limit", ref="B")], "bytes",
             overrides=[dashed("limit")]), 8, 8)
    b.add(ts("Sandbox network", [prom("sum(rate(container_network_receive_bytes_total{%s}[$__rate_interval]))" % WS, "received"),
                                 prom("sum(rate(container_network_transmit_bytes_total{%s}[$__rate_interval]))" % WS, "sent", ref="B")],
             "Bps"), 8, 8)

    b.row("Claude Code usage (telemetry)")
    b.add(ts("Tokens", [loki(api(WS, f), ref="ABCD"[i], legend=name) for i, (f, name) in enumerate(TOKEN_FIELDS)],
             "short", bars=True, stack=True, desc="Per interval, by type"), 8, 8)
    b.add(ts("Cost", [loki(api(WS, "cost_usd", "model"), legend="{{model}}")], "currencyUSD", bars=True,
             stack=True, desc="Estimated API-equivalent cost per interval, by model"), 8, 8)
    b.add(ts("Tool use", [loki('sum by (tool_name) (count_over_time({service_name="claude-code", %s} | event_name="tool_result" [$__interval]))' % WS,
                               legend="{{tool_name}}")], "short", bars=True, stack=True,
             desc="Tool calls Claude made, by tool"), 8, 8)
    b.add(table("API requests", [loki('sum by (model) (count_over_time({service_name="claude-code", %s} | event_name="api_request" [$__range]))' % WS,
                                      ref="A", instant=True),
                                 loki('sum by (model) (count_over_time({service_name="claude-code", %s} | event_name="api_error" [$__range]))' % WS,
                                      ref="B", instant=True)],
                [col("Errors", color_text=True)],
                {"model": "Model", "Value #A": "Requests", "Value #B": "Errors"}, exclude=("Time",),
                desc="Selected time range"), 8, 6)
    b.add(table("Tool decisions", [loki('sum by (tool_name, decision) (count_over_time({service_name="claude-code", %s} | event_name="tool_decision" [$__range]))' % WS,
                                        instant=True)],
                [], {"tool_name": "Tool", "decision": "Decision", "Value": "Count"}, exclude=("Time",),
                desc="Permission prompts accepted or rejected, selected time range",
                transforms_extra=[{"id": "sortBy", "options": {"sort": [{"field": "Count", "desc": True}]}}]),
          8, 6)
    b.add(stat("Cost", [loki(api(WS, "cost_usd", rng="$__range"), instant=True)], unit="currencyUSD",
               decimals=2, desc="Estimated API-equivalent cost, selected range"), 4, 6)
    b.add(stat("Sessions", [prom("sum(increase(aio_nono_sessions_total{%s}[$__range]))" % WS, instant=True)],
               decimals=0, desc="Sandboxed sessions started, selected range"), 4, 6)

    b.row("Network policy (nono)")
    b.add(ts("Connections", [prom('sum by (decision) (increase(aio_nono_network_events_total{%s}[$__interval]))' % WS,
                                  "{{decision}}")], "short", bars=True, stack=True,
             overrides=[{"matcher": {"id": "byName", "options": "deny"},
                         "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]},
                        {"matcher": {"id": "byName", "options": "allow"},
                         "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}]}]),
          12, 8)
    ws_deny = DENY_HOSTS.replace('decision="deny"', 'decision="deny", %s' % WS)
    b.add(table("Denied hosts", [loki('topk(15, sum by (target) (count_over_time(%s [$__range])))' % ws_deny, instant=True)],
                [], {"target": "Host", "Value": "Count"}, exclude=("Time",),
                desc="Add legitimate ones to the workspace's allowlist (Access tab)",
                transforms_extra=[{"id": "sortBy", "options": {"sort": [{"field": "Count", "desc": True}]}}]),
          6, 8)
    b.add(table("Allowed hosts", [loki('topk(15, sum by (target) (count_over_time({source="nono", decision="allow", %s} | json [$__range])))' % WS,
                                       instant=True)],
                [], {"target": "Host", "Value": "Count"}, exclude=("Time",),
                transforms_extra=[{"id": "sortBy", "options": {"sort": [{"field": "Count", "desc": True}]}}]),
          6, 8)

    b.row("Logs")
    b.add(logs("Sandbox events (nono)", '{source="nono", %s} | json | %s' % (WS, NONO_LINE),
               desc="Session starts / ends and every connection allowed or denied"), 24, 9)
    b.add(logs("Claude Code events", '{service_name="claude-code", %s}' % WS,
               desc="Telemetry events (prompts and responses are redacted); expand a line for its fields"),
          12, 10)
    b.add(logs("AIO Sandbox container", '{source="docker", %s}' % WS), 12, 10)

    var = {"name": "workspace", "label": "Workspace", "type": "query", "datasource": PROM,
           "query": {"query": "label_values(aio_workspace_info, workspace)", "refId": "ws"},
           "definition": "label_values(aio_workspace_info, workspace)", "refresh": 2, "sort": 1}
    back = {"title": "Overview", "type": "link", "url": "/d/aio-overview", "icon": "dashboard",
            "keepTime": True}
    return dashboard("aio-workspace", "Agent Sandboxes — workspace", b, [var], links=[back],
                     desc="One workspace: sandbox, Claude scope, telemetry, network policy, logs")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    for name, d in (("overview", overview()), ("workspace", workspace())):
        (OUT / f"{name}.json").write_text(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
        print(f"wrote {OUT / name}.json ({len(d['panels'])} panels)")
