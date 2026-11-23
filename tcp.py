import random
import socket
import struct
from enum import IntEnum, IntFlag
from functools import cached_property


class TCPConfig(IntEnum):
    SOURCE_FIRST = 49152
    SOURCE_LAST = 65535
    SEQ_FIRST = 0
    SEQ_LAST = 2 ** 32 - 1
    WINDOW_SIZE = 8192

class TCPFlags(IntFlag):
    SYN = 0x02
    RST = 0x04

class RawTCP:
    def __init__(
            self,
            *,
            target_ip: str,
            target_port: int,
            source_ip: str,
            source_port: int | None = None,
            seq_number: int | None = None,
            flag: TCPFlags = TCPFlags.SYN,
    ) -> None:
        self._dest_ip: str = target_ip
        self._dest_port: int = target_port
        self._source_ip: str = source_ip

        self.source_port: int = random.randint(
            TCPConfig.SOURCE_FIRST,
            TCPConfig.SOURCE_LAST
        ) if source_port is None else source_port

        self.seq_number: int = random.randint(
            TCPConfig.SEQ_FIRST,
            TCPConfig.SEQ_LAST
        ) if seq_number is None else seq_number

        self.flag: TCPFlags = flag

    def _get_tcp_header(self) -> bytes:
        source_port: int = self.source_port
        dest_port: int = self._dest_port
        seq_number: int = self.seq_number
        ack_number: int = 0
        offset: int = 5 << 4
        flags: int = self.flag.value
        window_size: int = TCPConfig.WINDOW_SIZE
        checksum: int = 0
        urgent_pointer: int = 0

        tcp_header_dummy: bytes = struct.pack(
            "!HHLLBBHHH",
            source_port,
            dest_port,
            seq_number,
            ack_number,
            offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
        )

        tcp_dummy_len: int = len(tcp_header_dummy)
        source_ip: bytes = socket.inet_aton(self._source_ip)
        dest_ip: bytes = socket.inet_aton(self._dest_ip)

        pseudo_ip: bytes = struct.pack(
            "!4s4sBBH", source_ip, dest_ip, 0, socket.IPPROTO_TCP, tcp_dummy_len
        )

        checksum = self.calculate_checksum(data=pseudo_ip + tcp_header_dummy)

        tcp_header: bytes = struct.pack(
            "!HHLLBBHHH",
            source_port,
            dest_port,
            seq_number,
            ack_number,
            offset,
            flags,
            window_size,
            checksum,
            urgent_pointer,
        )

        return tcp_header

    @cached_property
    def header_bytes(self) -> bytes:
        return self._get_tcp_header()

    @staticmethod
    def calculate_checksum(*, data: bytes) -> int:
        if len(data) % 2 != 0:
            data += b"\x00"

        words_count: int = len(data) // 2
        words: tuple[int, ...] = struct.unpack(f"!{words_count}H", data)

        words_sum: int = sum(words)
        while words_sum >> 16:
            words_sum = (words_sum & 0xFFFF) + (words_sum >> 16)

        checksum: int = ~words_sum & 0xFFFF
        return checksum
