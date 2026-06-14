import json
from pathlib import Path

# Project root for an editable / src-layout checkout: src/vigilans/mappings.py -> repo root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _resolve_mappings_path() -> Path:
    """Locate the repo's ``mappings.json``.

    Looks in the current working directory first (where ``flask run`` is launched).
    This is what makes a non-editable ``pip install .`` work: the app is run from the
    cloned repo, which contains the tracked ``mappings.json``. Falls back to the project
    root resolved relative to this file, which covers an editable / ``src``-layout
    checkout run from any directory.
    """
    cwd_path = Path.cwd() / "mappings.json"
    if cwd_path.is_file():
        return cwd_path
    return _PROJECT_ROOT / "mappings.json"


# Resolved at import for callers/tests that reference it; load_mappings() re-resolves
# at call time so a mappings.json created later in the same process is still picked up.
MAPPINGS_PATH = _resolve_mappings_path()

ALL_COLUMNS = [
    "device", "id", "name", "context", "srcZone", "dstZone",
    "srcAddr", "dstAddr", "service", "action", "log",
    "status", "nat", "schedule", "comment",
]


def load_mappings() -> dict:
    with open(_resolve_mappings_path()) as f:
        return json.load(f)


def classify_findings(
    raw_titles: list[dict], mappings: dict
) -> dict:
    """Classify raw finding titles into parsed, unparsed, and ignored.

    raw_titles: [{"title": "...", "toolName": "...", "devices": [...]}, ...]

    mappings.findings is keyed by the parser's issue title.
    An empty object {} means use defaults (title as findingName, all columns).
    A "findingName" key overrides the display name.
    A "columns" key specifies which columns to show (defaults to all).
    """
    findings_config = mappings.get("findings", {})
    ignored_titles = set(mappings.get("ignored", []))

    # Accumulator for parsed findings (keyed by findingName)
    parsed_acc: dict[str, dict] = {}
    unparsed: list[dict] = []
    ignored: list[dict] = []

    for item in raw_titles:
        title = item["title"]
        tool = item["toolName"]
        devices = item.get("devices", [])

        if title in ignored_titles:
            ignored.append({
                "title": title,
                "toolName": tool,
                "devices": devices,
            })
        elif title in findings_config:
            fc = findings_config[title]
            name = fc.get("findingName", title)
            if name not in parsed_acc:
                parsed_acc[name] = {
                    "findingName": name,
                    "sourceTools": set(),
                    "devices": set(),
                    "rawTitles": [],
                    "columns": fc.get("columns", ALL_COLUMNS),
                    "evidence": fc.get("evidence", []),
                    "comments": fc.get("comments", []),
                }
            parsed_acc[name]["sourceTools"].add(tool)
            parsed_acc[name]["devices"].update(devices)
            parsed_acc[name]["rawTitles"].append({"title": title, "toolName": tool})
        else:
            unparsed.append({"title": title, "toolName": tool, "devices": devices})

    # Convert sets to sorted lists
    parsed = []
    for p in parsed_acc.values():
        p["sourceTools"] = sorted(p["sourceTools"])
        p["devices"] = sorted(p["devices"])
        parsed.append(p)

    total = len(parsed) + len(unparsed) + len(ignored)
    return {
        "stats": {
            "total": total,
            "parsed": len(parsed),
            "unparsed": len(unparsed),
            "ignored": len(ignored),
        },
        "parsed": parsed,
        "unparsed": unparsed,
        "ignored": ignored,
    }
