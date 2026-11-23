from dataclasses import dataclass
from enum import StrEnum, Enum


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"

class AppProtocol(StrEnum):
    HTTP = "http"
    DNS = "dns"
    ECHO = "echo"

class PacketStatus(Enum):
    OPEN = 1
    CLOSED = 2
    FILTERED = 3
    OPEN_FILTERED = 4

@dataclass(frozen=True, slots=True)
class PortTarget:
    port: int
    protocol: Protocol = Protocol.TCP

@dataclass(slots=True, frozen=True)
class ScannerResult:
    status: PacketStatus
    response_time_ms: float | None = None
    app_protocol: AppProtocol | None = None

@dataclass(frozen=True, slots=True)
class ParsedTCPResponse:
    source_port: int
    dest_port: int
    ack_number: int
    status: PacketStatus
