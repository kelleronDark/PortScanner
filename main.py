import sys

from cli import iter_target_ports, parse_args
from models import PacketStatus, PortTarget, Protocol, ScannerResult
from port_scanner import PortScanner


def format_result_line(
    target: PortTarget,
    result: ScannerResult,
    *,
    verbose: bool,
    guess: bool,
) -> str:
    parts: list[str] = [target.protocol.value.upper(), str(target.port)]

    if verbose:
        if target.protocol == Protocol.TCP and result.response_time_ms is not None:
            parts.append(f"{result.response_time_ms:.2f}")
        else:
            parts.append("-")

    if guess:
        protocol_name = result.app_protocol.value.upper() if result.app_protocol else "-"
        parts.append(protocol_name)

    return " ".join(parts)


def print_results(
    results: dict[PortTarget, ScannerResult],
    *,
    verbose: bool,
    guess: bool,
) -> None:
    for target, result in sorted(
            results.items(), key=lambda item: (item[0].protocol.value, item[0].port)
    ):
        if result.status == PacketStatus.OPEN:
            print(format_result_line(target, result, verbose=verbose, guess=guess))


def main() -> None:
    args = parse_args()
    targets = iter_target_ports(args.ports)

    scanner = PortScanner(
        target_ip=args.ip_address,
        target_ports=targets,
        timeout=args.timeout,
        thread_count=args.num_threads,
        verbose=args.verbose,
        guess=args.guess,
    )

    try:
        results = scanner.start()
    except PermissionError:
        print(
            "[ERROR]: Root privileges are required for using raw sockets. [!] Run with sudo.",
            file=sys.stderr,
        )
        sys.exit(1)

    print_results(results, verbose=args.verbose, guess=args.guess)


if __name__ == "__main__":
    main()
