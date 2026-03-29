from pathlib import Path

from flask import Blueprint, jsonify, request

from ..db import get_db, clear_db
from ..mappings import load_mappings, classify_findings
from ..parsers import PARSERS

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/import/<tool_slug>", methods=["POST"])
def import_report(tool_slug: str):
    parser = PARSERS.get(tool_slug)
    if not parser:
        return jsonify({"error": f"Unknown tool: {tool_slug}"}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No filename"}), 400

    ext = Path(file.filename).suffix.lower()
    if ext not in parser.accepted_extensions:
        return jsonify({
            "error": f"Invalid file type: {ext}. Expected: {', '.join(parser.accepted_extensions)}"
        }), 400

    content = file.read().decode("utf-8", errors="replace")

    try:
        result = parser.parse(content, file.filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    db = get_db()
    try:
        # Check for existing import with same tool + device_name
        existing = db.execute(
            "SELECT id FROM imports WHERE tool_name = ? AND device_name = ?",
            (result.tool_name, result.device_name),
        ).fetchall()

        if existing and request.args.get("replace") != "true":
            return jsonify({
                "conflict": True,
                "tool_name": result.tool_name,
                "device_name": result.device_name,
            }), 409

        # Delete old imports for this tool + device_name if replacing
        if existing:
            for row in existing:
                db.execute("DELETE FROM imports WHERE id = ?", (row["id"],))

        cur = db.execute(
            "INSERT INTO imports (tool_name, device_name, device_type, report_date, filename) VALUES (?, ?, ?, ?, ?)",
            (result.tool_name, result.device_name, result.device_type, result.report_date, file.filename),
        )
        import_id = cur.lastrowid

        # Store raw finding titles
        for title in result.finding_titles:
            db.execute(
                "INSERT OR IGNORE INTO raw_findings (import_id, title) VALUES (?, ?)",
                (import_id, title),
            )

        # Store rules and their issues
        for rule in result.rules:
            rule_cur = db.execute(
                "INSERT INTO rules (import_id, rule_num, name, vdom, src_intf, dst_intf, "
                "src_addr, dst_addr, service, src_addr_expanded, dst_addr_expanded, "
                "service_expanded, action, log, status, nat, comments, schedule, raw) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (import_id, rule.rule_num, rule.name, rule.vdom, rule.src_intf,
                 rule.dst_intf, rule.src_addr, rule.dst_addr, rule.service,
                 rule.src_addr_expanded, rule.dst_addr_expanded, rule.service_expanded,
                 rule.action, rule.log, rule.status, rule.nat, rule.comments,
                 rule.schedule, rule.raw),
            )
            rule_id = rule_cur.lastrowid
            for issue in rule.issues:
                db.execute(
                    "INSERT OR IGNORE INTO rule_issues (rule_id, title) VALUES (?, ?)",
                    (rule_id, issue),
                )

        db.commit()
    finally:
        db.close()

    return jsonify({
        "import_id": import_id,
        "tool_name": result.tool_name,
        "device_name": result.device_name,
        "report_date": result.report_date,
        "rules_count": len(result.rules),
        "findings_count": len(result.finding_titles),
    }), 201


@api_bp.route("/imports", methods=["GET"])
def list_imports():
    db = get_db()
    try:
        rows = db.execute(
            "SELECT id, tool_name, device_name, device_type, report_date, filename, created_at "
            "FROM imports ORDER BY created_at DESC"
        ).fetchall()
    finally:
        db.close()

    return jsonify([dict(r) for r in rows])


@api_bp.route("/findings", methods=["GET"])
def get_findings():
    db = get_db()
    try:
        rows = db.execute(
            "SELECT rf.title, i.tool_name AS toolName, i.device_name "
            "FROM raw_findings rf "
            "JOIN imports i ON rf.import_id = i.id"
        ).fetchall()

        # Build rule lookup: {(toolName, title)} -> list of rule dicts
        rule_rows = db.execute(
            "SELECT r.rule_num, r.name, r.vdom, r.src_intf, r.dst_intf, "
            "r.src_addr, r.dst_addr, r.service, "
            "r.src_addr_expanded, r.dst_addr_expanded, r.service_expanded, "
            "r.action, r.log, r.status, r.nat, r.schedule, "
            "r.comments, r.raw, ri.title AS issue_title, i.device_name, i.tool_name "
            "FROM rule_issues ri "
            "JOIN rules r ON ri.rule_id = r.id "
            "JOIN imports i ON r.import_id = i.id"
        ).fetchall()

        all_rule_rows = db.execute(
            "SELECT r.rule_num, r.name, r.vdom, r.src_intf, r.dst_intf, "
            "r.src_addr, r.dst_addr, r.service, "
            "r.src_addr_expanded, r.dst_addr_expanded, r.service_expanded, "
            "r.action, r.log, r.status, r.nat, r.schedule, "
            "r.comments, r.raw, i.device_name "
            "FROM rules r "
            "JOIN imports i ON r.import_id = i.id "
            "ORDER BY i.device_name, r.rule_num"
        ).fetchall()
    finally:
        db.close()

    def _rule_dict(rr):
        return {
            "ruleNum": rr["rule_num"],
            "name": rr["name"],
            "context": rr["vdom"],
            "device": rr["device_name"],
            "srcZone": rr["src_intf"],
            "dstZone": rr["dst_intf"],
            "srcAddr": rr["src_addr"],
            "dstAddr": rr["dst_addr"],
            "service": rr["service"],
            "srcAddrExp": rr["src_addr_expanded"],
            "dstAddrExp": rr["dst_addr_expanded"],
            "serviceExp": rr["service_expanded"],
            "action": rr["action"],
            "log": rr["log"],
            "status": rr["status"],
            "nat": rr["nat"],
            "schedule": rr["schedule"],
            "comment": rr["comments"],
            "raw": rr["raw"],
        }

    # Group rules by (tool_name, issue_title)
    rules_by_issue: dict[tuple[str, str], list[dict]] = {}
    for rr in rule_rows:
        key = (rr["tool_name"], rr["issue_title"])
        rules_by_issue.setdefault(key, []).append(_rule_dict(rr))

    all_rules = [_rule_dict(rr) for rr in all_rule_rows]

    # Deduplicate: same title from same tool should appear once, collect devices
    seen: dict[tuple, dict] = {}
    raw_titles = []
    for r in rows:
        key = (r["title"], r["toolName"])
        if key not in seen:
            entry = {"title": r["title"], "toolName": r["toolName"], "devices": [r["device_name"]]}
            seen[key] = entry
            raw_titles.append(entry)
        elif r["device_name"] not in seen[key]["devices"]:
            seen[key]["devices"].append(r["device_name"])

    mappings = load_mappings()
    result = classify_findings(raw_titles, mappings)

    # Enrich findings with affected rules
    for finding in result["parsed"]:
        rules = []
        for rt in finding["rawTitles"]:
            key = (rt["toolName"], rt["title"])
            rules.extend(rules_by_issue.get(key, []))
        finding["rules"] = rules

    for finding in result["unparsed"]:
        key = (finding["toolName"], finding["title"])
        finding["rules"] = rules_by_issue.get(key, [])

    for finding in result["ignored"]:
        key = (finding["toolName"], finding["title"])
        finding["rules"] = rules_by_issue.get(key, [])

    result["allRules"] = all_rules
    example = mappings.get("findings", {}).get("EXAMPLE_FINDING", {})
    result["allRulesColumns"] = example.get("columns", None)
    return jsonify(result)


@api_bp.route("/rules", methods=["GET"])
def list_rules():
    """Return all parsed rules, optionally filtered by import_id."""
    import_id = request.args.get("import_id", type=int)
    db = get_db()
    try:
        if import_id:
            rows = db.execute(
                "SELECT r.*, i.device_name, i.tool_name FROM rules r "
                "JOIN imports i ON r.import_id = i.id "
                "WHERE r.import_id = ? ORDER BY r.rule_num",
                (import_id,),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT r.*, i.device_name, i.tool_name FROM rules r "
                "JOIN imports i ON r.import_id = i.id "
                "ORDER BY i.device_name, r.rule_num"
            ).fetchall()
    finally:
        db.close()

    return jsonify([dict(r) for r in rows])


@api_bp.route("/imports/<int:import_id>", methods=["DELETE"])
def delete_import(import_id: int):
    db = get_db()
    try:
        row = db.execute("SELECT id FROM imports WHERE id = ?", (import_id,)).fetchone()
        if not row:
            return jsonify({"error": "Import not found"}), 404

        db.execute("DELETE FROM imports WHERE id = ?", (import_id,))
        db.commit()
    finally:
        db.close()
    return jsonify({"status": "ok"})


@api_bp.route("/database", methods=["DELETE"])
def clear_database():
    clear_db()
    return jsonify({"status": "ok"})
