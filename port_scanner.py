import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from threading import Lock
from typing import Dict, Iterable

from guesser import guess_tcp_protocol, guess_udp_protocol
from models import PortTarget, Protocol, PacketStatus, ScannerResult
from parsers import parse_tcp_response, parse_icmp_response
from tcp import RawTCP, TCPFlags


@dataclass(slots=True, frozen=True)
class PendingTCPProbe:
    target_port: int
    sent_packet: RawTCP
    sent_at_ms: float

class PortScanner:
    DUMMY_PORT = 80
    BARRIER_TIMEOUT = 2.0
    MAX_RETRIES = 2

    def __init__(
            self,
            target_ip: str,
            target_ports: Iterable[PortTarget],
            timeout: float,
            thread_count: int,
            verbose: bool,
            guess: bool,
    ) -> None:
        self.target_ip = target_ip
        self.target_ports = target_ports
        self.timeout = timeout
        self.thread_count = thread_count
        self.verbose = verbose
        self.guess = guess

        self.running = False
        self.executor = ThreadPoolExecutor(max_workers=thread_count)
        self.lock = Lock()
        self.source_ip = self._get_source_ip(self.target_ip)

        self.pending_tcp: Dict[int, PendingTCPProbe] = {}
        self.pending_udp = set()

        self.results: Dict[PortTarget, ScannerResult] = {}

    def listen_udp(self, sock: socket.socket, ready_barrier: threading.Barrier) -> None:
        ready_barrier.wait()
        while self.running:
            try:
                _, sender_addr = sock.recvfrom(512)
            except OSError:
                break

            if not sender_addr or sender_addr[0] != self.target_ip:
                continue

            remote_port = sender_addr[1]

            with self.lock:
                if remote_port in self.pending_udp:
                    self.pending_udp.remove(remote_port)
                    self.results[PortTarget(remote_port, Protocol.UDP)] = ScannerResult(
                        status=PacketStatus.OPEN,
                    )

    def listen_icmp(self, sock: socket.socket, ready_barrier: threading.Barrier) -> None:
        ready_barrier.wait()
        while self.running:
            try:
                response, sender_addr = sock.recvfrom(4096)
            except OSError:
                break

            if not sender_addr or sender_addr[0] != self.target_ip:
                continue

            remote_port = parse_icmp_response(response)
            if remote_port is None:
                continue

            with self.lock:
                if remote_port in self.pending_udp:
                    self.pending_udp.remove(remote_port)
                    self.results[PortTarget(remote_port, Protocol.UDP)] = ScannerResult(
                        status=PacketStatus.CLOSED,
                    )

    def listen_tcp(self, sock: socket.socket, ready_barrier: threading.Barrier) -> None:
        ready_barrier.wait()
        while self.running:
            try:
                response, sender_addr = sock.recvfrom(4096)
            except OSError:
                break

            if not sender_addr or sender_addr[0] != self.target_ip:
                continue

            parsed_response = parse_tcp_response(response)
            if parsed_response is None:
                continue

            remote_port = parsed_response.source_port
            local_port = parsed_response.dest_port
            server_ack_number = parsed_response.ack_number

            with self.lock:
                probe = self.pending_tcp.get(local_port)

            if probe is None:
                continue

            expected_port = probe.target_port
            sent_tcp = probe.sent_packet
            sent_at_ms = probe.sent_at_ms

            if (
                remote_port != expected_port
                or local_port != sent_tcp.source_port
                or server_ack_number != sent_tcp.seq_number + 1
            ):
                continue

            if parsed_response.status == PacketStatus.OPEN:
                rst_packet = RawTCP(
                    target_ip=self.target_ip,
                    target_port=expected_port,
                    source_ip=self.source_ip,
                    source_port=local_port,
                    seq_number=parsed_response.ack_number,
                    flag=TCPFlags.RST,
                )
                sock.sendto(rst_packet.header_bytes, (self.target_ip, expected_port))

            with self.lock:
                self.pending_tcp.pop(local_port, None)
                self.results[PortTarget(expected_port, Protocol.TCP)] = ScannerResult(
                    status=parsed_response.status,
                    response_time_ms=(time.perf_counter() - sent_at_ms) * 1000
                )

    def send_tcp(self, sock: socket.socket, target: PortTarget) -> None:
        raw_tcp = RawTCP(
            target_ip=self.target_ip, target_port=target.port, source_ip=self.source_ip
        )
        with self.lock:
            self.results[target] = ScannerResult(
                status=PacketStatus.FILTERED,
            )
            self.pending_tcp[raw_tcp.source_port] = PendingTCPProbe(
                target_port=target.port,
                sent_packet=raw_tcp,
                sent_at_ms=time.perf_counter()
            )
        sock.sendto(raw_tcp.header_bytes, (self.target_ip, target.port))

    def send_udp(self, sock: socket.socket, target: PortTarget) -> None:
        with self.lock:
            self.pending_udp.add(target.port)
            self.results[target] = ScannerResult(
                status=PacketStatus.OPEN_FILTERED,
            )
        sock.sendto(b"", (self.target_ip, target.port))

    def start(self):
        udp_sock = None
        tcp_sock = None
        icmp_sock = None

        try:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            udp_sock.bind(("0.0.0.0", 0))
            self.running = True
            ready_barrier = threading.Barrier(4)

            threading.Thread(
                target=self.listen_tcp,
                args=(tcp_sock, ready_barrier),
                daemon=True
            ).start()

            threading.Thread(
                target=self.listen_udp,
                args=(udp_sock, ready_barrier),
                daemon=True
            ).start()

            threading.Thread(
                target=self.listen_icmp,
                args=(icmp_sock, ready_barrier),
                daemon=True
            ).start()

            try:
                ready_barrier.wait(timeout=self.BARRIER_TIMEOUT)
            except threading.BrokenBarrierError:
                raise RuntimeError("Listener threads failed to start")

            self._send_targets(self.target_ports, tcp_sock, udp_sock)
            time.sleep(self.timeout / 2)

            retry_targets = self._pop_unanswered_targets()
            if retry_targets:
                self._send_targets(retry_targets, tcp_sock, udp_sock)
                time.sleep(self.timeout / 2)

            if self.guess:
                self._run_protocol_guessing()

        except KeyboardInterrupt:
            sys.stderr.write("[PortScan] Got signal to stop scanner\n")

        finally:
            self.running = False
            for sock in (udp_sock, icmp_sock, tcp_sock):
                if sock is not None:
                    sock.close()
            self.executor.shutdown(wait=False)

        return self.results

    def _send_targets(
            self,
            targets: Iterable[PortTarget],
            tcp_sock: socket.socket,
            udp_sock: socket.socket,
    ) -> None:
        sender_futures = []
        for target in targets:
            future = None
            if target.protocol == Protocol.UDP:
                future = self.executor.submit(self.send_udp, udp_sock, target)
            elif target.protocol == Protocol.TCP:
                future = self.executor.submit(self.send_tcp, tcp_sock, target)

            if future is not None:
                sender_futures.append(future)

        if sender_futures:
            wait(sender_futures)

    def _pop_unanswered_targets(self) -> list[PortTarget]:
        retry_targets: list[PortTarget] = []
        with self.lock:
            for probe in self.pending_tcp.values():
                retry_targets.append(PortTarget(probe.target_port, Protocol.TCP))
            self.pending_tcp.clear()

            for port in self.pending_udp:
                retry_targets.append(PortTarget(port, Protocol.UDP))
            self.pending_udp.clear()

        return retry_targets

    def _get_source_ip(self, target_ip: str) -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            try:
                s.connect((target_ip, self.DUMMY_PORT))
                return str(s.getsockname()[0])
            except OSError:
                return "127.0.0.1"

    def _run_protocol_guessing(self):
        probe_timeout = min(self.timeout, 1.0)
        for target, result in list(self.results.items()):
            if target.protocol == Protocol.TCP and result.status == PacketStatus.OPEN:
                app_protocol = guess_tcp_protocol(self.target_ip, target.port, probe_timeout)
                if app_protocol is not None:
                    self.results[target] = ScannerResult(
                        status=result.status,
                        response_time_ms=result.response_time_ms,
                        app_protocol=app_protocol,
                    )
            elif target.protocol == Protocol.UDP and result.status in (
                    PacketStatus.OPEN,
                    PacketStatus.OPEN_FILTERED,
            ):
                app_protocol = guess_udp_protocol(self.target_ip, target.port, probe_timeout)
                if app_protocol is not None:
                    self.results[target] = ScannerResult(
                        status=PacketStatus.OPEN,
                        response_time_ms=result.response_time_ms,
                        app_protocol=app_protocol,
                    )
