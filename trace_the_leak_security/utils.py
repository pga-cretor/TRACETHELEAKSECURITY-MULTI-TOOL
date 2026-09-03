from __future__ import annotations

import logging
import time
from collections.abc import Iterator


LOGGER = logging.getLogger("traceleak")


def configure_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()
    for part in value.split(","):
        item = part.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Intervallo porte non valido: {item}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    result = sorted(ports)
    if any(port < 1 or port > 65535 for port in result):
        raise ValueError("Le porte devono essere comprese tra 1 e 65535.")
    return result


def throttled(items: list[int], seconds: float) -> Iterator[int]:
    for index, item in enumerate(items):
        if index:
            time.sleep(seconds)
        yield item
