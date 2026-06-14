# vigiLANs

A Python Flask web application that audits firewall rules/ACLs. It parses firewall rule exports (currently FortiGate), extracts every rule, analyzes them for security issues, and presents findings in a web UI. Unlike grADus which classifies findings from other tools, vigiLANs **generates** findings from raw rule data.

## Tech Stack

- **Backend**: Python 3.11+, Flask 3.x
- **Database**: SQLite (raw `sqlite3` via `get_db()`, no ORM)
- **Rule parser**: Custom FortiGate rule parser (regex + state machine)
- **Frontend**: Vanilla JS SPA, dark theme only, no framework
- **Fonts**: IBM Plex Sans / IBM Plex Mono (bundled locally in `static/fonts/`)
- **Project tooling**: `pyproject.toml` with `src` layout

## Running

```bash
pip install -e .
flask --app vigilans.app:create_app run
```

A plain non-editable `pip install .` also works: `templates/` and `static/` ship as package data (`[tool.setuptools.package-data]` in `pyproject.toml`), and the tracked `mappings.json` at the repo root is found via the current working directory when the app is launched from the cloned repo. Automated provisioning that runs `pip install .` then `flask run` from the repo (e.g. the Win11-Pentest autounattend build, which clones this repo and pip-installs it non-editable) depends on this.

## Project Structure

```
vigiLANs/
├── pyproject.toml
├── mappings.json                    # Finding definitions (tracked; the active config the app reads)
├── vigilans.db                      # SQLite database (auto-created on first run)
├── CLAUDE.md
├── README.md
├── data/                            # Sample FortiGate rule exports
├── src/
│   └── vigilans/
│       ├── __init__.py
│       ├── app.py                   # Flask app factory, 16 MB upload limit
│       ├── db.py                    # SQLite connection, schema init, clear + migration
│       ├── mappings.py              # Resolve + load mappings.json (cwd → project root), classify findings, columns
│       ├── parsers/
│       │   ├── __init__.py          # Parser registry: PARSERS = {"fortigate": FortiGateParser()}
│       │   ├── base.py              # BaseParser ABC + ParseResult/Rule dataclasses
│       │   └── fortigate.py         # FortiGate rule parser (rules, groups, addresses, VIPs, services)
│       ├── routes/
│       │   ├── __init__.py
│       │   ├── api.py               # JSON API endpoints
│       │   └── pages.py             # Serves the SPA at /
│       ├── static/
│       │   ├── css/
│       │   │   └── style.css        # All styles, CSS custom properties, @font-face
│       │   ├── fonts/
│       │   │   ├── ibm-plex-sans.woff2
│       │   │   ├── ibm-plex-mono-400.woff2
│       │   │   └── ibm-plex-mono-500.woff2
│       │   ├── img/
│       │   │   └── logo.svg
│       │   └── js/
│       │       └── app.js           # SPA logic: IIFE, API calls, rendering, events
│       └── templates/
│           └── index.html           # Jinja2 shell template
```

## Architecture & Data Flow

```
Upload → Parser → DB (imports + rules + rule_issues + raw_findings) → classify against mappings.json → API response → JS render
```

1. User uploads a firewall rule export via the sidebar upload card
2. `api.py:import_report()` looks up the parser by tool slug from the `PARSERS` registry
3. Parser extracts hostname, device type, rules, and analyzes each rule for issues
4. Rules, issues, and metadata are stored in SQLite
5. `GET /api/findings` reads all raw findings, then `classify_findings()` matches them against `mappings.json`
6. Findings are classified as **parsed** (matched), **unparsed** (no match), or **ignored** (explicitly ignored)
7. Frontend renders cards with rules tables, highlighting, and group expansion

Full file content is NOT stored — only extracted rules, metadata, and issue titles.

## Database Schema

Defined in `db.py:SCHEMA`. WAL mode and foreign keys enabled.

```sql
CREATE TABLE IF NOT EXISTS imports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name   TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL DEFAULT '',
    report_date TEXT NOT NULL,
    filename    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id   INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
    rule_num    INTEGER NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    vdom        TEXT NOT NULL DEFAULT '',
    src_intf    TEXT NOT NULL DEFAULT '',
    dst_intf    TEXT NOT NULL DEFAULT '',
    src_addr    TEXT NOT NULL DEFAULT '',
    dst_addr    TEXT NOT NULL DEFAULT '',
    service     TEXT NOT NULL DEFAULT '',
    src_addr_expanded TEXT NOT NULL DEFAULT '',
    dst_addr_expanded TEXT NOT NULL DEFAULT '',
    service_expanded  TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT 'deny',
    log         TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'enable',
    nat         TEXT NOT NULL DEFAULT '',
    comments    TEXT NOT NULL DEFAULT '',
    schedule    TEXT NOT NULL DEFAULT '',
    raw         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rule_issues (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    UNIQUE(rule_id, title)
);

CREATE TABLE IF NOT EXISTS raw_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id   INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    UNIQUE(import_id, title)
);
```

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Serve SPA |
| `POST` | `/api/import/<tool_slug>` | Upload rule export (e.g. `fortigate`). Returns 409 on conflict. Append `?replace=true` to overwrite. |
| `GET` | `/api/imports` | List all imports (for sidebar) |
| `GET` | `/api/findings` | Get consolidated findings (parsed/unparsed/ignored) + all rules |
| `GET` | `/api/rules` | Get all rules, optionally filtered by `?import_id=N` |
| `DELETE` | `/api/imports/<import_id>` | Delete a single import and its rules/findings (cascades) |
| `DELETE` | `/api/database` | Clear all data |

### Duplicate detection on upload

When uploading for a tool+device_name that already exists:
1. Backend returns `409` with `{"conflict": true, "tool_name": "...", "device_name": "..."}`
2. Frontend shows `confirm()` prompt
3. If confirmed, re-sends with `?replace=true` which deletes old import(s) first

### `GET /api/findings` response shape

```json
{
  "stats": { "total": 10, "parsed": 8, "unparsed": 0, "ignored": 2 },
  "parsed": [{
    "findingName": "Overly Permissive Rule (Any Source)",
    "sourceTools": ["FortiGate"],
    "devices": ["FG2K5ETB18900061"],
    "rawTitles": [{"title": "Overly Permissive Rule (Any Source)", "toolName": "FortiGate"}],
    "columns": ["device", "id", "name", "srcAddr", "action"],
    "evidence": [],
    "comments": [],
    "rules": [{ "ruleNum": 2, "name": "internet", "device": "FG2K5ETB18900061", ... }]
  }],
  "unparsed": [{ "title": "...", "toolName": "FortiGate", "devices": ["..."] }],
  "ignored": [{ "title": "...", "toolName": "FortiGate", "devices": ["..."] }],
  "allRules": [{ "ruleNum": 1, "device": "...", ... }],
  "allRulesColumns": ["device", "id", "name", ...]
}
```

## Parser System

### BaseParser (`parsers/base.py`)

```python
class BaseParser(ABC):
    tool_name: str
    accepted_extensions: list[str]

    @abstractmethod
    def parse(self, file_content: str, filename: str) -> ParseResult: ...

@dataclass
class ParseResult:
    tool_name: str
    device_name: str
    device_type: str
    report_date: str
    rules: list[Rule]
    finding_titles: list[str]

@dataclass
class Rule:
    rule_num: int
    name, vdom, src_intf, dst_intf: str
    src_addr, dst_addr, service: str
    src_addr_expanded, dst_addr_expanded, service_expanded: str
    action, log, status, nat, comments, schedule, raw: str
    issues: list[str]
```

### FortiGate Parser (`parsers/fortigate.py`)

Parses FortiGate `.conf`/`.txt` rule exports. Key functions:

- `_find_vdom_ranges()` — detects VDOM boundaries (or single-domain mode)
- `_extract_hostname()` — gets hostname from `config system global`
- `_extract_section_entries()` — generic section parser for policies, addresses, services, groups
- `_extract_address_defs()` — parses `config firewall address` (subnets → CIDR, FQDNs, IP ranges)
- `_extract_vip_defs()` — parses `config firewall vip` (virtual IPs with port forwarding)
- `_extract_service_defs()` — parses `config firewall service custom` (ports, protocols)
- `_extract_groups()` — parses `config firewall addrgrp` and `config firewall service group`
- `_resolve_leaves()` — recursively resolves groups to leaf values (subnets, IPs, ports)
- `_analyze_rule()` — flags individual rule issues
- `_find_duplicate_rules()` — cross-rule duplicate detection

### Group expansion

Rules reference address groups and service groups by name. The parser resolves these recursively:
- Groups → their members → leaf definitions (subnets, FQDNs, IPs, ports)
- Both unexpanded (group name) and expanded (leaf values) are stored in the DB
- Frontend "Expand Groups" toggle switches between the two views

### Adding a new parser

1. Create `parsers/<slug>.py` with a class extending `BaseParser`
2. Register it in `parsers/__init__.py`: `PARSERS["<slug>"] = <Parser>()`
3. Add a `TOOLS` entry in `app.js`
4. Add CSS tool colour variables `--tool-<slug>` and `--tool-<slug>-dim` in `:root`
5. Add CSS rules for `.sidebar-import-tool[data-tool="<slug>"]` and `.raw-title-tool[data-tool="<slug>"]`

### Adding a new issue to the parser

When adding a new issue in `_analyze_rule()`, you MUST also:
1. Add a corresponding entry to `mappings.json` under `findings` with appropriate columns
2. Add a highlight entry in `HIGHLIGHT_MAP` in `app.js` mapping column IDs to severity functions
3. Severity functions return `'bad'` (red), `'warn'` (orange), or `''` (no highlight)

## Mappings JSON (`mappings.json`)

```json
{
  "findings": {
    "EXAMPLE_FINDING": {
      "columns": ["device", "id", "context", "name", "srcZone", "dstZone", "srcAddr", "dstAddr", "service", "action", "log", "status", "nat", "schedule", "comment"]
    },
    "Overly Permissive Rule (Any Source)": {
      "columns": ["device", "id", "context", "name", "srcZone", "dstZone", "srcAddr", "dstAddr", "service", "action", "comment"]
    },
    "Rule without Logging": {
      "findingName": "Custom Display Name",
      "columns": ["device", "id", "name", "log"]
    }
  },
  "ignored": ["Issue Title To Hide"]
}
```

### Field details

- `findings` — keyed by the parser's exact issue title. An empty object `{}` uses defaults.
- `findingName` — optional custom display name (defaults to the key)
- `columns` — which columns to show in the rules table for this finding (defaults to all)
- `EXAMPLE_FINDING` — special entry that defines the default columns for the "All Rules" view
- `ignored` — list of issue title strings to hide from the UI
- Multiple parser issue titles can map to the same `findingName` to group related issues

### File resolution

`mappings.json` is tracked in the repo (not gitignored) so a fresh clone — including automated provisioning — always has it. `load_mappings()` resolves it at call time, in order:

1. `mappings.json` in the **current working directory** (where `flask run` is launched). For a non-editable `pip install .`, this is what finds it: the app is run from the cloned repo, which contains the tracked file.
2. `mappings.json` at the **project root** resolved relative to `mappings.py` (covers an editable / `src`-layout checkout run from any directory).

There is no bundled copy, so launch `flask run` from the repo directory (or any directory containing a `mappings.json`).

### Column IDs (generic, not firewall-specific)

| ID | Label | DB field | Description |
|----|-------|----------|-------------|
| device | Device | device_name | Firewall hostname |
| id | # | rule_num | Rule number |
| context | Context | vdom | Virtual domain (FortiGate VDOM, PAN vsys, etc.) |
| name | Name | name | Rule name |
| srcZone | Src Zone | src_intf | Source interface / zone |
| dstZone | Dst Zone | dst_intf | Destination interface / zone |
| srcAddr | Src Addr | src_addr | Source address (expandable via groups) |
| dstAddr | Dst Addr | dst_addr | Destination address (expandable via groups) |
| service | Service | service | Service / port (expandable via groups) |
| action | Action | action | accept / deny |
| log | Log | log | Logging setting |
| status | Status | status | enable / disable |
| nat | NAT | nat | NAT setting |
| schedule | Schedule | schedule | Schedule |
| comment | Comment | comments | Rule comment |

## Frontend Architecture (`app.js`)

### Pattern

- IIFE-wrapped (`(function() { 'use strict'; ... })()`)
- No framework, no classes — functional helpers and string-template rendering
- `$` = `querySelector`, `$$` = `querySelectorAll` (scoped via optional context)
- `esc(text)` — XSS prevention via `textContent`/`innerHTML` trick. **Always use `esc()` when interpolating user data into HTML templates.**
- `toolSlug(name)` — converts display name to slug (lowercase, no spaces)
- Event delegation via `document.addEventListener('click', ...)` for toggle, copy, select
- `data-*` attributes for state (`data-toggle`, `data-category`, `data-devices`, `data-tool`, `data-copy`, `data-import-id`, `data-raw`, `data-device`, `data-collapsed`, `data-expanded`)

### TOOLS array

```javascript
const TOOLS = [
    { slug: 'fortigate', name: 'FortiGate', accept: '.conf,.txt', hint: 'Config file (.conf, .txt)' },
];
```

Each entry generates a sidebar upload card with click-to-browse and drag-and-drop.

### Data flow

1. `init()` → `renderUploadCards()` + `setupFilterTabs()` + `refresh()`
2. `refresh()` → parallel fetch of `/api/imports` and `/api/findings`
3. `renderImports(imports)` → sidebar device blocks grouped by device_name, showing tool + device type tags + date + delete button
4. `renderFindings(data)` → stats bar + filter tabs + card types:
   - `renderParsedCard(f, id)` — finding name, device tags, rules table with highlighting, evidence, comments
   - `renderAllRulesCard(rules, columns)` — all rules across all devices with column filter dropdown
   - `renderUnparsedCard(f, id)` — raw title and tool
   - `renderIgnoredCard(f, id)` — raw title, tool, and comments
5. `applyFilter(filter)` — shows/hides cards by category and device, filters table rows by device, updates rule counts

### Column-driven rules table (`renderRulesTable`)

The rules table is fully driven by a `columns` array from `mappings.json`:

- `COL_DEFS` — maps column IDs to display labels, data keys, and narrow/expandable flags
- `HIGHLIGHT_MAP` — maps finding titles to per-column severity functions returning `'bad'`, `'warn'`, or `''`
- In `__ALL__` mode (All Rules card), all highlight maps are combined — every rule shows all its issues
- Expandable columns (srcAddr, dstAddr, service) have `data-collapsed`/`data-expanded` attributes toggled by "Expand Groups"
- Per-value service highlighting: insecure services (red) and questionable services (orange) are coloured individually within comma-separated lists

### Insecure service classification

| Severity | Colour | Services |
|----------|--------|----------|
| Bad (red) | `--status-failed` | TELNET, FTP, TFTP, HTTP, RSH, RLOGIN, FINGER, TALK, IRC |
| Warn (orange) | `--status-unparsed` | SNMP, NFS, SMB, SAMBA, POP3, IMAP, SMTP |

### Row interaction

- Click a table row to select it (highlighted background)
- "Copy Config" button appears in the action bar — copies the raw config block for that rule
- "Copy Row" button (All Rules only) — copies the selected row as a markdown pipe-delimited row

### Copy Table format

Copies the entire rules table as markdown:
```
| DEVICE | # | NAME | ... |
| - | - | - | ... |
| FG2K5E... | 2 | internet | ... |
```
Headers are uppercased.

## CSS Conventions (`style.css`)

### Design tokens (`:root` custom properties)

**Backgrounds**: `--bg-primary` (#0D0D0F), `--bg-secondary` (#141417), `--bg-tertiary` (#1A1A1F), `--bg-elevated` (#222228), `--bg-hover` (#2A2A32)

**Text**: `--text-primary` (#F0F0F2), `--text-secondary` (#A0A0A8), `--text-tertiary` (#606068)

**Borders**: `--border-subtle` (#2A2A32), `--border-default` (#3A3A44)

**Accent**: `--accent-blue` (#3B82F6), `--accent-blue-dim` (15% opacity)

**Status colours**:
| Status | Solid | Dim (background) |
|--------|-------|-------------------|
| Parsed (green) | `--status-parsed` (#10B981) | `--status-parsed-dim` (12% opacity) |
| Unparsed (amber) | `--status-unparsed` (#F59E0B) | `--status-unparsed-dim` (12% opacity) |
| Ignored (purple) | `--status-ignored` (#8B5CF6) | `--status-ignored-dim` (12% opacity) |
| Failed (red) | `--status-failed` (#EF4444) | `--status-failed-dim` (12% opacity) |

**Tool colours**: `--tool-fortigate` (#F59E0B), `--tool-device-type` (#F59E0B)

**Fonts**: `--font-sans` (IBM Plex Sans stack), `--font-mono` (IBM Plex Mono stack)

**Radii**: `--radius-sm` (4px), `--radius-md` (8px), `--radius-lg` (12px)

**Layout**: `--sidebar-width` (280px)

### Patterns

- Base font size: 15px
- Transition timing: `0.15s` (used on all interactive elements)
- Responsive breakpoint: `768px` — sidebar hidden, padding reduced
- Dark theme only (no light mode)
- `[data-tool="<slug>"]` selectors for tool-specific colours on badges
- `[data-section="<type>"]` for section indicators
- `.show` / `.hidden` classes to toggle visibility
- `.expanded` class on cards to show `.finding-body`
- `.dragover` / `.uploading` states on upload cards
- `.copied` transient state for copy button feedback
- `.rule-val-bad` (red) and `.rule-val-warn` (orange) for table cell highlighting
- `.selected` class on table rows for row selection
- No external resources — fonts bundled locally, no CDN dependencies

## Coding Conventions

- **No ORM** — raw SQL with `?` parameter binding via `sqlite3`. Always use `get_db()` and close in `finally`.
- **No frontend framework** — vanilla JS, IIFE-scoped, template literals for HTML generation.
- **Functional style** — helper functions, not classes (frontend). Backend uses classes only for parsers.
- **`data-*` attributes** for all interactive state and identification.
- **`esc()` for all user data** interpolated into HTML to prevent XSS.
- **IBM Plex fonts** — Sans for UI, Mono for code/tables.
- **Dark theme only** — no light mode support.
- **CSS custom properties** for all colours, fonts, radii, layout values.
- **No build step** — plain CSS and JS served directly.
- **Fully offline** — no external resources, CDNs, or network dependencies.
- **Generic column IDs** — table columns use firewall-agnostic names (e.g. `context` not `vdom`, `srcZone` not `srcintf`).

## Documentation Policy

**Any change to the codebase must be reflected in `CLAUDE.md` and `README.md` (if relevant) as part of the same change.** Documentation is not a follow-up task — it ships with the code. This includes new features, schema changes, API changes, new fields, new parsers, UI changes, and convention changes.
