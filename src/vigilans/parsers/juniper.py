from __future__ import annotations

import re
from .base import BaseParser, ParseResult, Rule

# ---------------------------------------------------------------------------
# Predefined Junos applications (junos-*) -> (protocol, destination-port).
#
# Validated against Juniper's official "Predefined Policy Applications" doc and
# cross-checked against an independent reference; ports agree across both. Only
# the common applications are listed (enough for display expansion + insecure
# service detection); unknown junos-* names are shown verbatim without a port.
# ---------------------------------------------------------------------------
PREDEFINED_APPS: dict[str, tuple[str, str]] = {
    "junos-ftp": ("tcp", "21"),
    "junos-ftp-data": ("tcp", "20"),
    "junos-tftp": ("udp", "69"),
    "junos-telnet": ("tcp", "23"),
    "junos-ssh": ("tcp", "22"),
    "junos-http": ("tcp", "80"),
    "junos-http-ext": ("tcp", "8080"),
    "junos-https": ("tcp", "443"),
    "junos-smtp": ("tcp", "25"),
    "junos-smtps": ("tcp", "465"),
    "junos-pop3": ("tcp", "110"),
    "junos-pop3s": ("tcp", "995"),
    "junos-imap": ("tcp", "143"),
    "junos-imaps": ("tcp", "993"),
    "junos-snmp": ("udp", "161"),
    "junos-snmp-agentx": ("tcp", "705"),
    "junos-dns-udp": ("udp", "53"),
    "junos-dns-tcp": ("tcp", "53"),
    "junos-ntp": ("udp", "123"),
    "junos-ldap": ("tcp", "389"),
    "junos-rsh": ("tcp", "514"),
    "junos-rlogin": ("tcp", "513"),
    "junos-finger": ("tcp", "79"),
    "junos-syslog": ("udp", "514"),
    "junos-ike": ("udp", "500"),
    "junos-ike-nat": ("udp", "4500"),
    "junos-netbios-session": ("tcp", "139"),
    "junos-smb": ("tcp", "139/445"),
    "junos-smb-session": ("tcp", "445"),
    "junos-nfs": ("udp", "111"),
    "junos-ms-rpc-tcp": ("tcp", "135"),
    "junos-ms-rpc-udp": ("udp", "135"),
    "junos-rdp": ("tcp", "3389"),
    "junos-sip": ("udp", "5060"),
    "junos-radius": ("udp", "1812"),
    "junos-tacacs": ("tcp", "49"),
    "junos-bgp": ("tcp", "179"),
    "junos-ping": ("icmp", ""),
    "junos-traceroute": ("udp", ""),
}

# Service classification (mirrors the FortiGate parser so finding titles match).
INSECURE_SERVICES = {
    "TELNET", "FTP", "FTP-DATA", "TFTP", "HTTP", "RSH", "RLOGIN", "FINGER",
    "TALK", "IRC",
}
QUESTIONABLE_SERVICES = {
    "SNMP", "NFS", "SMB", "SAMBA", "POP3", "IMAP", "SMTP", "NETBIOS",
}

# Predefined junos-* names that are insecure/questionable by their well-known role.
INSECURE_APP_NAMES = {
    "junos-telnet", "junos-ftp", "junos-ftp-data", "junos-tftp",
    "junos-http", "junos-rsh", "junos-rlogin", "junos-finger",
}
QUESTIONABLE_APP_NAMES = {
    "junos-snmp", "junos-snmp-agentx", "junos-nfs", "junos-smb",
    "junos-smb-session", "junos-netbios-session", "junos-pop3",
    "junos-imap", "junos-smtp",
}

# Insecure/questionable by resolved (protocol, port) — catches custom applications.
INSECURE_PORTS = {
    ("tcp", "23"): "TELNET", ("tcp", "21"): "FTP", ("tcp", "20"): "FTP",
    ("udp", "69"): "TFTP", ("tcp", "80"): "HTTP", ("tcp", "514"): "RSH",
    ("tcp", "513"): "RLOGIN", ("tcp", "79"): "FINGER",
}
QUESTIONABLE_PORTS = {
    ("udp", "161"): "SNMP", ("udp", "162"): "SNMP", ("tcp", "110"): "POP3",
    ("tcp", "143"): "IMAP", ("tcp", "25"): "SMTP", ("tcp", "445"): "SMB",
    ("tcp", "139"): "NETBIOS", ("udp", "137"): "NETBIOS", ("udp", "138"): "NETBIOS",
    ("udp", "111"): "NFS", ("tcp", "2049"): "NFS",
}

ANY_ADDR = {"any", "any-ipv4", "any-ipv6"}


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _tokenize(text: str) -> list[str]:
    """Split a statement into tokens, honouring quotes and dropping list brackets.

    Junos `[ a b c ]` value lists become the bare values a b c (the brackets are
    dropped); `show | display set` output never uses brackets so this only affects
    the flattened hierarchical form.
    """
    raw = re.findall(r'"[^"]*"|\S+', text)
    out: list[str] = []
    for tok in raw:
        if tok in ("[", "]"):
            continue
        tok = tok.strip("[]") if tok not in ('"', '""') else tok
        if tok:
            out.append(_strip_quotes(tok))
    return out


def _logical_statements(text: str):
    """Yield logical Junos statements, joining wrapped/multi-line lists.

    A statement ends at `{`, `}`, or `;`. `/* */` comments and `#` lines are stripped.
    """
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    buf = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        buf = f"{buf} {line}".strip() if buf else line
        if line.endswith("{") or line.endswith("}") or line.endswith(";"):
            yield buf
            buf = ""
    if buf:
        yield buf


def _flatten_hierarchical(text: str) -> list[tuple[list[str], bool]]:
    """Flatten curly-brace config into (token_path, inactive) leaves.

    Mirrors what `show configuration | display set` produces: each leaf statement
    becomes the full path of enclosing context tokens plus the leaf tokens.
    """
    stack: list[tuple[list[str], bool]] = []
    out: list[tuple[list[str], bool]] = []
    for stmt in _logical_statements(text):
        inactive = False
        if stmt.startswith("inactive:"):
            inactive = True
            stmt = stmt[len("inactive:"):].strip()
        if stmt == "}":
            if stack:
                stack.pop()
            continue
        if stmt.endswith("{"):
            stack.append((_tokenize(stmt[:-1]), inactive))
            continue
        if stmt.endswith(";"):
            stmt = stmt[:-1].strip()
        toks = _tokenize(stmt)
        if not toks:
            continue
        path: list[str] = []
        inact = inactive
        for ctoks, cinact in stack:
            path.extend(ctoks)
            inact = inact or cinact
        path.extend(toks)
        out.append((path, inact))
    return out


def _flatten_set(text: str) -> list[tuple[list[str], bool]]:
    """Parse `set`/`deactivate` lines into (token_path, inactive) leaves."""
    stmts: list[list[str]] = []
    deactivated: list[list[str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("set "):
            stmts.append(_tokenize(line[4:]))
        elif line.startswith("deactivate "):
            deactivated.append(_tokenize(line[len("deactivate "):]))
    out: list[tuple[list[str], bool]] = []
    for toks in stmts:
        inactive = any(toks[: len(d)] == d for d in deactivated if d)
        out.append((toks, inactive))
    return out


def _detect_and_flatten(text: str) -> list[tuple[list[str], bool]]:
    has_set = any(l.lstrip().startswith(("set ", "deactivate ")) for l in text.splitlines())
    has_brace = any(l.rstrip().endswith("{") for l in text.splitlines())
    if has_set and not has_brace:
        return _flatten_set(text)
    if has_brace and not has_set:
        return _flatten_hierarchical(text)
    # Mixed/ambiguous: prefer set if any set lines exist, else hierarchical.
    return _flatten_set(text) if has_set else _flatten_hierarchical(text)


def _format_address(deftoks: list[str]) -> str | None:
    """Render an address-book entry's value tokens to a display string.

    Returns None for non-value statements (e.g. `description`) so they don't
    overwrite a previously parsed value.
    """
    if not deftoks:
        return None
    head = deftoks[0]
    if head == "description":
        return None
    if head == "dns-name":
        return deftoks[1] if len(deftoks) > 1 else "dns-name"
    if head == "range-address":
        # range-address LOWER to UPPER
        if len(deftoks) >= 4 and deftoks[2] == "to":
            return f"{deftoks[1]}-{deftoks[3]}"
        return " ".join(deftoks[1:])
    if head == "wildcard-address":
        return deftoks[1] if len(deftoks) > 1 else "wildcard-address"
    # Bare ip-prefix, e.g. 10.1.1.5/32
    return head


class _Model:
    def __init__(self) -> None:
        self.hostname = ""
        self.version = ""
        self.addr_defs: dict[str, str] = {}
        self.addr_groups: dict[str, list[str]] = {}
        self.app_custom: dict[str, dict] = {}
        self.app_groups: dict[str, list[str]] = {}
        # policy key -> dict; insertion order preserved for rule numbering
        self.policies: dict[tuple, dict] = {}

    def _policy(self, key: tuple, name: str, is_global: bool) -> dict:
        pol = self.policies.get(key)
        if pol is None:
            pol = {
                "name": name, "fz": "", "tz": "", "src": [], "dst": [],
                "app": [], "action": "", "log": [], "desc": "", "inactive": False,
                "is_global": is_global,
            }
            self.policies[key] = pol
        return pol


def _handle_address_book(rest: list[str], model: _Model) -> None:
    """rest begins after `address-book` (global, named, or zone-scoped)."""
    if not rest:
        return
    if rest[0] == "address" and len(rest) >= 2:
        name = rest[1]
        value = _format_address(rest[2:])
        if value is not None:
            model.addr_defs[name] = value
    elif rest[0] == "address-set" and len(rest) >= 4:
        name = rest[1]
        if rest[2] in ("address", "address-set"):
            model.addr_groups.setdefault(name, []).extend(rest[3:])


def _handle_application(toks: list[str], model: _Model) -> None:
    """toks begins with the application NAME."""
    if not toks:
        return
    name = toks[0]
    rest = toks[1:]
    acc = model.app_custom.setdefault(name, {"proto": "", "dport": "", "terms": []})
    if not rest:
        return
    if rest[0] == "protocol" and len(rest) > 1:
        acc["proto"] = rest[1]
    elif rest[0] == "destination-port" and len(rest) > 1:
        acc["dport"] = rest[1]
    elif rest[0] == "term":
        proto = dport = ""
        i = 2
        while i < len(rest) - 1:
            if rest[i] == "protocol":
                proto = rest[i + 1]
            elif rest[i] == "destination-port":
                dport = rest[i + 1]
            i += 2
        acc["terms"].append((proto, dport))


def _build_model(statements: list[tuple[list[str], bool]]) -> _Model:
    model = _Model()
    for toks, inactive in statements:
        if not toks:
            continue
        if toks[:2] == ["system", "host-name"] and len(toks) > 2:
            model.hostname = toks[2]
        elif toks[:1] == ["version"] and len(toks) > 1:
            model.version = toks[1]
        elif toks[:3] == ["security", "zones", "security-zone"] and len(toks) >= 4:
            rest = toks[4:]
            if rest[:1] == ["address-book"]:
                _handle_address_book(rest[1:], model)
        elif toks[:2] == ["security", "address-book"] and len(toks) >= 3:
            # security address-book <book> address|address-set ...
            _handle_address_book(toks[3:], model)
        elif toks[:2] == ["applications", "application"] and len(toks) >= 3:
            _handle_application(toks[2:], model)
        elif toks[:2] == ["applications", "application-set"] and len(toks) >= 4:
            name = toks[2]
            if toks[3] in ("application", "application-set"):
                model.app_groups.setdefault(name, []).extend(toks[4:])
        elif toks[:2] == ["security", "policies"]:
            _handle_policy_statement(toks[2:], inactive, model)
    return model


def _handle_policy_statement(rest: list[str], inactive: bool, model: _Model) -> None:
    if rest[:1] == ["global"] and len(rest) >= 3 and rest[1] == "policy":
        name = rest[2]
        pol = model._policy(("__global__", name), name, True)
        _apply_policy_fields(pol, rest[3:])
    elif rest[:1] == ["from-zone"] and len(rest) >= 6 and rest[2] == "to-zone" and rest[4] == "policy":
        fz, tz, name = rest[1], rest[3], rest[5]
        pol = model._policy((fz, tz, name), name, False)
        pol["fz"], pol["tz"] = fz, tz
        _apply_policy_fields(pol, rest[6:])
    else:
        return
    if inactive:
        pol["inactive"] = True


def _apply_policy_fields(pol: dict, fields: list[str]) -> None:
    if not fields:
        return
    if fields[0] == "match" and len(fields) >= 2:
        sub, vals = fields[1], fields[2:]
        if sub == "source-address":
            pol["src"].extend(vals)
        elif sub == "destination-address":
            pol["dst"].extend(vals)
        elif sub == "application":
            pol["app"].extend(vals)
        elif sub == "from-zone" and vals:
            pol["fz"] = vals[0]
        elif sub == "to-zone" and vals:
            pol["tz"] = vals[0]
    elif fields[0] == "then" and len(fields) >= 2:
        action = fields[1]
        if action in ("permit", "deny", "reject"):
            pol["action"] = action
        elif action == "log":
            pol["log"].extend(fields[2:])
    elif fields[0] == "description":
        pol["desc"] = " ".join(fields[1:])


def _app_value(name: str, model: _Model) -> str:
    """Resolve a single application name to a 'PROTO/port' display value."""
    acc = model.app_custom.get(name)
    if acc:
        if acc["terms"]:
            parts = [f"{p.upper()}/{d}" if d else p.upper() for p, d in acc["terms"] if p or d]
            if parts:
                return ", ".join(parts)
        if acc["dport"]:
            return f"{acc['proto'].upper()}/{acc['dport']}" if acc["proto"] else acc["dport"]
        if acc["proto"]:
            return acc["proto"].upper()
    if name in PREDEFINED_APPS:
        proto, port = PREDEFINED_APPS[name]
        return f"{proto.upper()}/{port}" if port else proto.upper()
    return name


def _resolve_leaves(name: str, groups: dict[str, list[str]], defs: dict[str, str],
                    seen: set[str] | None = None) -> list[str]:
    if seen is None:
        seen = set()
    if name in seen:
        return [name]
    seen = seen | {name}
    if name in groups:
        leaves: list[str] = []
        for m in groups[name]:
            leaves.extend(_resolve_leaves(m, groups, defs, seen))
        return leaves
    if name in defs:
        return [defs[name]]
    return [name]


def _expand(values: list[str], groups: dict[str, list[str]], defs: dict[str, str]) -> str:
    leaves: list[str] = []
    for v in values:
        leaves.extend(_resolve_leaves(v, groups, defs))
    return ", ".join(leaves)


def _app_index(model: _Model) -> dict[str, tuple[str, str]]:
    """Map every known application name to a (protocol, port) for insecure checks."""
    index: dict[str, tuple[str, str]] = dict(PREDEFINED_APPS)
    for name, acc in model.app_custom.items():
        if acc["terms"]:
            for proto, dport in acc["terms"]:
                if proto or dport:
                    index[name] = (proto.lower(), dport)
        elif acc["proto"] or acc["dport"]:
            index[name] = (acc["proto"].lower(), acc["dport"])
    return index


def _service_is_insecure(app_names: list[str], app_index: dict[str, tuple[str, str]]) -> bool:
    for raw in app_names:
        name = raw.strip()
        if not name:
            continue
        lower = name.lower()
        if lower in INSECURE_APP_NAMES or lower in QUESTIONABLE_APP_NAMES:
            return True
        base = name[6:] if lower.startswith("junos-") else name
        if base.upper() in INSECURE_SERVICES or base.upper() in QUESTIONABLE_SERVICES:
            return True
        proto_port = app_index.get(name)
        if proto_port:
            proto, port = proto_port
            for p in str(port).replace("/", ",").split(","):
                key = (proto, p.strip())
                if key in INSECURE_PORTS or key in QUESTIONABLE_PORTS:
                    return True
    return False


def _analyze_rule(rule: Rule, app_names: list[str], app_index: dict[str, tuple[str, str]]) -> list[str]:
    """Flag issues for a Junos policy. Titles match the FortiGate parser/mappings.json."""
    issues: list[str] = []
    is_allow = rule.action == "permit"

    src_vals = [s.strip().lower() for s in rule.src_addr.split(",") if s.strip()]
    dst_vals = [s.strip().lower() for s in rule.dst_addr.split(",") if s.strip()]
    app_vals = [s.strip().lower() for s in rule.service.split(",") if s.strip()]

    any_src = any(v in ANY_ADDR for v in src_vals)
    any_dst = any(v in ANY_ADDR for v in dst_vals)
    any_svc = any(v == "any" for v in app_vals) or not app_vals

    if is_allow:
        if any_src and any_dst and any_svc:
            issues.append("Overly Permissive Rule (Any Source, Any Destination, Any Service)")
        elif any_src and any_dst:
            issues.append("Overly Permissive Rule (Any Source, Any Destination)")
        elif any_src and any_svc:
            issues.append("Overly Permissive Rule (Any Source, Any Service)")
        elif any_dst and any_svc:
            issues.append("Overly Permissive Rule (Any Destination, Any Service)")
        elif any_src:
            issues.append("Overly Permissive Rule (Any Source)")
        elif any_dst:
            issues.append("Overly Permissive Rule (Any Destination)")
        elif any_svc:
            issues.append("Overly Permissive Rule (Any Service)")

    any_src_zone = rule.src_intf.lower() in ("any", "")
    any_dst_zone = rule.dst_intf.lower() in ("any", "")
    if is_allow:
        if any_src_zone and any_dst_zone:
            issues.append("Overly Permissive Rule (Any Source Zone, Any Destination Zone)")
        elif any_src_zone:
            issues.append("Overly Permissive Rule (Any Source Zone)")
        elif any_dst_zone:
            issues.append("Overly Permissive Rule (Any Destination Zone)")

    if is_allow and _service_is_insecure(app_names, app_index):
        issues.append("Insecure Service Permitted")

    if not rule.comments:
        issues.append("Rule without Comment")
    if is_allow and rule.log in ("", "disable"):
        issues.append("Rule without Logging")
    if rule.status == "disable":
        issues.append("Disabled Rule")
    if not rule.name:
        issues.append("Rule without Name")

    return issues


def _find_duplicate_rules(rules: list[Rule]) -> None:
    seen: dict[tuple, int] = {}
    for rule in rules:
        key = (rule.src_intf, rule.dst_intf, rule.src_addr, rule.dst_addr,
               rule.service, rule.action)
        if key in seen:
            if "Duplicate Rule" not in rule.issues:
                rule.issues.append("Duplicate Rule")
        else:
            seen[key] = rule.rule_num


def _policy_to_rule(pol: dict, num: int, model: _Model, app_index: dict[str, tuple[str, str]]) -> Rule:
    src = pol["src"] or ["any"]
    dst = pol["dst"] or ["any"]
    app = pol["app"] or ["any"]
    fz = pol["fz"] or "any"
    tz = pol["tz"] or "any"

    # Service display values: resolve names to PROTO/port; expand application-sets.
    app_defs = {name: _app_value(name, model) for name in app}
    for name in model.app_groups:
        app_defs.setdefault(name, _app_value(name, model))
    svc_expanded_defs = {**{n: _app_value(n, model) for n in PREDEFINED_APPS},
                         **{n: _app_value(n, model) for n in model.app_custom},
                         **app_defs}

    action = pol["action"] or "deny"
    log = ", ".join(pol["log"])

    raw_lines = [
        f"set security policies from-zone {fz} to-zone {tz} policy {pol['name']} "
        f"match source-address {' '.join(src)}",
        f"set security policies from-zone {fz} to-zone {tz} policy {pol['name']} "
        f"match destination-address {' '.join(dst)}",
        f"set security policies from-zone {fz} to-zone {tz} policy {pol['name']} "
        f"match application {' '.join(app)}",
        f"set security policies from-zone {fz} to-zone {tz} policy {pol['name']} then {action}",
    ]
    for entry in pol["log"]:
        raw_lines.append(
            f"set security policies from-zone {fz} to-zone {tz} policy {pol['name']} then log {entry}"
        )

    return Rule(
        rule_num=num,
        name=pol["name"],
        vdom="",
        src_intf=fz,
        dst_intf=tz,
        src_addr=", ".join(src),
        dst_addr=", ".join(dst),
        service=", ".join(app),
        src_addr_expanded=_expand(src, model.addr_groups, model.addr_defs),
        dst_addr_expanded=_expand(dst, model.addr_groups, model.addr_defs),
        service_expanded=_expand(app, model.app_groups, svc_expanded_defs),
        action=action,
        log=log,
        status="disable" if pol["inactive"] else "enable",
        nat="",
        comments=pol["desc"],
        schedule="",
        raw="\n".join(raw_lines),
    )


def _extract_report_date(text: str) -> str:
    m = re.search(r"##\s*Last (?:commit|changed):\s*([0-9]{4}-[0-9]{2}-[0-9]{2})", text)
    if m:
        return m.group(1)
    return ""


class JuniperParser(BaseParser):
    tool_name = "Juniper"
    accepted_extensions = [".conf", ".txt"]

    def parse(self, file_content: str, filename: str) -> ParseResult:
        statements = _detect_and_flatten(file_content)
        model = _build_model(statements)
        app_index = _app_index(model)

        device_name = model.hostname or f"File: {filename}"
        device_type = f"Junos SRX {model.version}".strip() if model.version else "Junos SRX"
        report_date = _extract_report_date(file_content)

        rules: list[Rule] = []
        for num, pol in enumerate(model.policies.values(), start=1):
            app_names = pol["app"] or ["any"]
            rule = _policy_to_rule(pol, num, model, app_index)
            rule.issues = _analyze_rule(rule, app_names, app_index)
            rules.append(rule)

        _find_duplicate_rules(rules)

        all_titles: set[str] = set()
        for rule in rules:
            all_titles.update(rule.issues)

        return ParseResult(
            tool_name=self.tool_name,
            device_name=device_name,
            device_type=device_type,
            report_date=report_date,
            rules=rules,
            finding_titles=sorted(all_titles),
        )
