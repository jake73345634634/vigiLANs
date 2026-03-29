from __future__ import annotations

import re
from .base import BaseParser, ParseResult, Rule


def _strip_quotes(value: str) -> str:
    """Strip surrounding quotes from a single value."""
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _parse_multi_value(value: str) -> str:
    """Parse a FortiGate value that may contain multiple quoted strings.

    'set srcaddr "addr1" "addr2"' -> "addr1, addr2"
    'set action accept'           -> "accept"
    """
    parts = re.findall(r'"([^"]*)"', value)
    if parts:
        return ", ".join(parts)
    return _strip_quotes(value.strip())


def _parse_header(text: str) -> dict:
    """Extract metadata from the #config-version header line."""
    info = {"model": "", "version": "", "opmode": "", "vdom_enabled": False, "build_date": ""}
    first_line = text.split("\n", 1)[0].strip()
    if not first_line.startswith("#config-version="):
        return info

    # Example: #config-version=FG100E-6.0.4-FW-build0231-190107:opmode=0:vdom=1:user=admin
    header = first_line[len("#config-version="):]
    parts = header.split(":")
    if parts:
        fw_part = parts[0]
        # Extract model and version: FG100E-6.0.4-FW-build0231-190107
        m = re.match(r"(\w+)-([\d.]+)-FW-build(\d+)-(\d+)", fw_part)
        if m:
            info["model"] = m.group(1)
            info["version"] = m.group(2)
            info["build_date"] = m.group(4)

    for part in parts[1:]:
        if part.startswith("vdom="):
            info["vdom_enabled"] = part.split("=", 1)[1] == "1"
        elif part.startswith("opmode="):
            info["opmode"] = part.split("=", 1)[1]

    return info


def _extract_hostname(text: str) -> str:
    """Extract hostname from config system global section."""
    in_global = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "config system global":
            in_global = True
            continue
        if in_global:
            if stripped == "end":
                break
            if stripped.startswith("set hostname "):
                return _strip_quotes(stripped[len("set hostname "):].strip())
    return ""


def _find_vdom_ranges(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Find VDOM text ranges within the config.

    Returns {vdom_name: (start_line, end_line)}.
    For non-VDOM configs, returns {"": (0, len(lines))}.

    FortiGate VDOM configs have multiple "config vdom" blocks:
    - A declaration block at the top: config vdom / edit X / next / edit Y / next / end
    - Content blocks later: config vdom / edit X / <sections...> / end
    The content blocks contain the actual per-VDOM configuration.
    We skip short declaration blocks and capture the content blocks.
    """
    vdoms: dict[str, tuple[int, int]] = {}
    i = 0
    found_any_vdom = False

    while i < len(lines):
        stripped = lines[i].strip()

        if stripped == "config vdom":
            found_any_vdom = True
            i += 1
            # Next line should be "edit <vdom_name>"
            if i < len(lines):
                edit_line = lines[i].strip()
                if edit_line.startswith("edit "):
                    vdom_name = _strip_quotes(edit_line[5:].strip())
                    content_start = i + 1
                    i += 1

                    # Check if this is a short declaration (next line is "next" or "end")
                    # or a content block (next line is "config ..." or other content)
                    if i < len(lines) and lines[i].strip() in ("next", "end"):
                        # Declaration block — skip through until "end"
                        while i < len(lines) and lines[i].strip() != "end":
                            i += 1
                        i += 1  # skip the "end"
                        continue

                    # Content block — find its end by tracking config/end depth
                    depth = 0
                    while i < len(lines):
                        s = lines[i].strip()
                        if s.startswith("config "):
                            depth += 1
                        elif s == "end":
                            if depth > 0:
                                depth -= 1
                            else:
                                # This end closes the "config vdom" block
                                vdoms[vdom_name] = (content_start, i)
                                i += 1
                                break
                        i += 1
                    continue
        i += 1

    if not found_any_vdom:
        return {"": (0, len(lines))}

    return vdoms


def _extract_section_entries(
    lines: list[str], start: int, end: int, section_name: str
) -> list[dict]:
    """Find all 'config <section_name>' blocks within a line range and extract entries."""
    all_entries = []
    i = start

    while i < end:
        stripped = lines[i].strip()
        if stripped == f"config {section_name}":
            # Found the section, now extract entries
            depth = 1
            entry = None
            entry_lines: list[str] = []
            nested_depth = 0
            j = i + 1

            while j < end and depth > 0:
                s = lines[j].strip()

                if nested_depth > 0:
                    entry_lines.append(lines[j])
                    if s.startswith("config "):
                        nested_depth += 1
                    elif s == "end":
                        nested_depth -= 1
                    j += 1
                    continue

                if s.startswith("config "):
                    # Nested config inside an entry
                    nested_depth = 1
                    entry_lines.append(lines[j])
                elif s.startswith("edit "):
                    entry_id = _strip_quotes(s[5:].strip())
                    entry = {"_id": entry_id}
                    entry_lines = [lines[j]]
                elif s == "next":
                    if entry is not None:
                        entry_lines.append(lines[j])
                        entry["_raw"] = "\n".join(entry_lines)
                        all_entries.append(entry)
                        entry = None
                        entry_lines = []
                elif s == "end":
                    depth -= 1
                elif s.startswith("set ") and entry is not None:
                    parts = s[4:].split(None, 1)
                    key = parts[0]
                    value = parts[1] if len(parts) > 1 else ""
                    entry[key] = value
                    entry_lines.append(lines[j])
                elif s.startswith("unset ") and entry is not None:
                    entry_lines.append(lines[j])
                else:
                    if entry is not None:
                        entry_lines.append(lines[j])

                j += 1
            i = j
        else:
            i += 1

    return all_entries


def _extract_groups(
    lines: list[str], start: int, end: int, section_name: str
) -> dict[str, list[str]]:
    """Extract group name -> member list from a config section."""
    groups: dict[str, list[str]] = {}
    entries = _extract_section_entries(lines, start, end, section_name)
    for entry in entries:
        name = entry.get("_id", "")
        members_raw = entry.get("member", "")
        members = re.findall(r'"([^"]*)"', members_raw)
        if not members:
            val = members_raw.strip()
            if val:
                members = [val]
        if name and members:
            groups[name] = members
    return groups


def _mask_to_cidr(mask: str) -> int:
    """Convert a dotted netmask to CIDR prefix length."""
    try:
        parts = mask.split(".")
        bits = 0
        for part in parts:
            bits = (bits << 8) | int(part)
        return bin(bits).count("1")
    except (ValueError, IndexError):
        return -1


def _format_subnet(raw: str) -> str:
    """Convert 'IP MASK' to CIDR notation like '10.1.128.0/24'."""
    parts = raw.split()
    if len(parts) == 2:
        prefix = _mask_to_cidr(parts[1])
        if prefix >= 0:
            return f"{parts[0]}/{prefix}"
    return raw


def _extract_address_defs(
    lines: list[str], start: int, end: int
) -> dict[str, str]:
    """Extract address name -> human-readable value from config firewall address."""
    defs: dict[str, str] = {}
    entries = _extract_section_entries(lines, start, end, "firewall address")
    for entry in entries:
        name = entry.get("_id", "")
        if not name:
            continue
        if "subnet" in entry:
            defs[name] = _format_subnet(_strip_quotes(entry["subnet"]))
        elif "start-ip" in entry:
            defs[name] = f"{_strip_quotes(entry['start-ip'])}-{_strip_quotes(entry.get('end-ip', ''))}"
        elif "fqdn" in entry:
            defs[name] = _strip_quotes(entry["fqdn"])
        elif "wildcard-fqdn" in entry:
            defs[name] = _strip_quotes(entry["wildcard-fqdn"])
    return defs


def _extract_vip_defs(
    lines: list[str], start: int, end: int
) -> dict[str, str]:
    """Extract VIP name -> human-readable value from config firewall vip."""
    defs: dict[str, str] = {}
    entries = _extract_section_entries(lines, start, end, "firewall vip")
    for entry in entries:
        name = entry.get("_id", "")
        if not name:
            continue
        mapped_ip = _strip_quotes(entry.get("mappedip", ""))
        if not mapped_ip:
            continue
        ext_ip = _strip_quotes(entry.get("extip", ""))
        port_fwd = _strip_quotes(entry.get("portforward", "")) == "enable"
        if port_fwd:
            mapped_port = _strip_quotes(entry.get("mappedport", ""))
            ext_port = _strip_quotes(entry.get("extport", ""))
            defs[name] = f"{mapped_ip}:{mapped_port} (ext {ext_ip}:{ext_port})"
        else:
            defs[name] = f"{mapped_ip} (ext {ext_ip})" if ext_ip else mapped_ip
    return defs


def _extract_service_defs(
    lines: list[str], start: int, end: int
) -> dict[str, str]:
    """Extract service name -> human-readable value from config firewall service custom."""
    defs: dict[str, str] = {}
    entries = _extract_section_entries(lines, start, end, "firewall service custom")
    for entry in entries:
        name = entry.get("_id", "")
        if not name:
            continue
        parts = []
        if "tcp-portrange" in entry:
            parts.append(f"TCP/{_strip_quotes(entry['tcp-portrange'])}")
        if "udp-portrange" in entry:
            parts.append(f"UDP/{_strip_quotes(entry['udp-portrange'])}")
        if not parts and "protocol" in entry:
            proto = _strip_quotes(entry["protocol"])
            if "protocol-number" in entry:
                proto += f"/{_strip_quotes(entry['protocol-number'])}"
            parts.append(proto)
        if parts:
            defs[name] = " ".join(parts)
    # ANY is equivalent to ALL — if ALL is defined but ANY isn't, alias it
    if "ALL" in defs and "ANY" not in defs:
        defs["ANY"] = defs["ALL"]
    return defs


def _resolve_leaves(name: str, groups: dict[str, list[str]], defs: dict[str, str],
                    seen: set[str] | None = None) -> list[str]:
    """Recursively resolve a name to its leaf values (subnets, IPs, ports, etc.)."""
    if seen is None:
        seen = set()
    if name in seen:
        return [name]
    seen = seen | {name}

    if name in groups:
        leaves = []
        for m in groups[name]:
            leaves.extend(_resolve_leaves(m, groups, defs, seen))
        return leaves
    if name in defs:
        return [defs[name]]
    return [name]


def _expand_to_leaves(value: str, groups: dict[str, list[str]], defs: dict[str, str]) -> str:
    """Expand a multi-value field to a flat list of leaf values."""
    parts = re.findall(r'"([^"]*)"', value)
    if not parts:
        val = _strip_quotes(value.strip())
        return ", ".join(_resolve_leaves(val, groups, defs))
    leaves = []
    for p in parts:
        leaves.extend(_resolve_leaves(p, groups, defs))
    return ", ".join(leaves)


def _entry_to_rule(entry: dict, vdom: str, groups: dict[str, list[str]],
                   defs: dict[str, str]) -> Rule:
    """Convert a parsed policy entry dict to a Rule."""
    src_raw = entry.get("srcaddr", "")
    dst_raw = entry.get("dstaddr", "")
    svc_raw = entry.get("service", "")
    return Rule(
        rule_num=int(entry.get("_id", 0)),
        name=_parse_multi_value(entry.get("name", "")),
        vdom=vdom,
        src_intf=_parse_multi_value(entry.get("srcintf", "")),
        dst_intf=_parse_multi_value(entry.get("dstintf", "")),
        src_addr=_parse_multi_value(src_raw),
        dst_addr=_parse_multi_value(dst_raw),
        service=_parse_multi_value(svc_raw),
        src_addr_expanded=_expand_to_leaves(src_raw, groups, defs),
        dst_addr_expanded=_expand_to_leaves(dst_raw, groups, defs),
        service_expanded=_expand_to_leaves(svc_raw, groups, defs),
        action=_strip_quotes(entry.get("action", "deny")),
        log=_strip_quotes(entry.get("logtraffic", "")),
        status=_strip_quotes(entry.get("status", "enable")),
        nat=_strip_quotes(entry.get("nat", "")),
        comments=_parse_multi_value(entry.get("comments", "")),
        schedule=_parse_multi_value(entry.get("schedule", "")),
        raw=entry.get("_raw", ""),
    )


INSECURE_SERVICES = {
    "TELNET", "FTP", "TFTP", "HTTP", "RSH", "RLOGIN", "FINGER",
    "TALK", "IRC",
}

QUESTIONABLE_SERVICES = {
    "SNMP", "NFS", "SMB", "SAMBA", "POP3", "IMAP", "SMTP",
}


def _analyze_rule(rule: Rule) -> list[str]:
    """Analyze a firewall rule and return a list of issue titles."""
    issues = []
    src_lower = rule.src_addr.lower()
    dst_lower = rule.dst_addr.lower()
    svc_upper = rule.service.upper()
    is_allow = rule.action == "accept"

    any_src = src_lower in ("all", "any")
    any_dst = dst_lower in ("all", "any")
    any_svc = svc_upper in ("ALL", "ANY")

    # Overly permissive address/service checks — mutually exclusive, highest match wins
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

    # Overly permissive zone checks — separate chain from address/service
    any_src_zone = rule.src_intf.lower() in ("any", "")
    any_dst_zone = rule.dst_intf.lower() in ("any", "")
    if is_allow:
        if any_src_zone and any_dst_zone:
            issues.append("Overly Permissive Rule (Any Source Zone, Any Destination Zone)")
        elif any_src_zone:
            issues.append("Overly Permissive Rule (Any Source Zone)")
        elif any_dst_zone:
            issues.append("Overly Permissive Rule (Any Destination Zone)")

    # Insecure service check
    if is_allow:
        svc_parts = [s.strip().upper() for s in rule.service.split(",")]
        if any(s in INSECURE_SERVICES or s in QUESTIONABLE_SERVICES for s in svc_parts):
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
    """Mark rules that are duplicates of each other."""
    seen: dict[tuple, int] = {}
    for rule in rules:
        key = (rule.src_intf, rule.dst_intf, rule.src_addr, rule.dst_addr,
               rule.service, rule.action)
        if key in seen:
            if "Duplicate Rule" not in rule.issues:
                rule.issues.append("Duplicate Rule")
        else:
            seen[key] = rule.rule_num


class FortiGateParser(BaseParser):
    tool_name = "FortiGate"
    accepted_extensions = [".conf", ".txt"]

    def parse(self, file_content: str, filename: str) -> ParseResult:
        header = _parse_header(file_content)
        hostname = _extract_hostname(file_content)
        device_name = hostname or f"File: {filename}"

        model = header.get("model", "")
        version = header.get("version", "")
        device_type = f"{model} FortiOS {version}" if model else ""

        build_date = header.get("build_date", "")
        if len(build_date) == 6:
            report_date = f"20{build_date[:2]}-{build_date[2:4]}-{build_date[4:6]}"
        else:
            report_date = build_date

        lines = file_content.splitlines()
        vdom_ranges = _find_vdom_ranges(lines)

        rules: list[Rule] = []
        for vdom_name, (start, end) in vdom_ranges.items():
            # Build group and leaf definition lookups for this VDOM
            groups: dict[str, list[str]] = {}
            groups.update(_extract_groups(lines, start, end, "firewall service group"))
            groups.update(_extract_groups(lines, start, end, "firewall addrgrp"))

            defs: dict[str, str] = {}
            defs.update(_extract_address_defs(lines, start, end))
            defs.update(_extract_vip_defs(lines, start, end))
            defs.update(_extract_service_defs(lines, start, end))

            entries = _extract_section_entries(lines, start, end, "firewall policy")
            for entry in entries:
                rule = _entry_to_rule(entry, vdom_name, groups, defs)
                rule.issues = _analyze_rule(rule)
                rules.append(rule)

        # Cross-rule analysis
        _find_duplicate_rules(rules)

        # Collect unique finding titles across all rules
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
