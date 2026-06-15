from .fortigate import FortiGateParser
from .juniper import JuniperParser

PARSERS = {
    "fortigate": FortiGateParser(),
    "juniper": JuniperParser(),
}
