from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Rule:
    rule_num: int
    name: str = ""
    vdom: str = ""
    src_intf: str = ""
    dst_intf: str = ""
    src_addr: str = ""
    dst_addr: str = ""
    service: str = ""
    src_addr_expanded: str = ""
    dst_addr_expanded: str = ""
    service_expanded: str = ""
    action: str = "deny"
    log: str = ""
    status: str = "enable"
    nat: str = ""
    comments: str = ""
    schedule: str = ""
    raw: str = ""
    issues: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    tool_name: str
    device_name: str
    device_type: str
    report_date: str
    rules: list[Rule] = field(default_factory=list)
    finding_titles: list[str] = field(default_factory=list)


class BaseParser(ABC):
    tool_name: str
    accepted_extensions: list[str]

    @abstractmethod
    def parse(self, file_content: str, filename: str) -> ParseResult:
        ...
