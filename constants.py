from enum import IntEnum


class HeaderLength(IntEnum):
    TCP = 20
    IP = 20
    ICMP = 8
    UDP = 8