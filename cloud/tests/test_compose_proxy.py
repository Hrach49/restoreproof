"""W5.1 (docs/decisions.md 2026-10-15, "W5.1 (#66)", point 1): the local
stack's HTTPS front, Caddy, through which the Worker reaches the Cloud at
`https://localhost:8443`, its private root trusted through the Worker's
`cloud_ca_file`. The file's text is held here; the stack itself is shown by
hand (docs/testing.md "The local HTTPS front")."""
from __future__ import annotations

import re

from app.schemas import shared_schemas_dir


def shared_dir():
    return shared_schemas_dir().parent


def compose_text() -> str:
    return (shared_dir().parent / "cloud" / "docker-compose.yml").read_text(encoding="utf-8")


def caddyfile_text() -> str:
    return (shared_dir().parent / "cloud" / "docker" / "Caddyfile").read_text(encoding="utf-8")


def proxy_service(compose: str) -> str:
    start = compose.index("\n  proxy:\n")
    end = compose.index("\nvolumes:\n", start)
    return compose[start:end]


def caddy_lines() -> list[str]:
    return [line.strip() for line in caddyfile_text().splitlines() if line.strip() and not line.strip().startswith("#")]


def test_the_proxy_is_the_official_caddy_image_pinned_by_digest():
    proxy = proxy_service(compose_text())

    assert re.search(r"\n    image: caddy@sha256:[0-9a-f]{64}\n", proxy)
    assert "build:" not in proxy


def test_the_proxy_publishes_one_port_on_127_0_0_1_alone():
    proxy = proxy_service(compose_text())
    ports = re.findall(r'\n      - "([^"]+)"', proxy[proxy.index("ports:"):])

    assert ports == ["127.0.0.1:8443:443"]


def test_the_proxy_keeps_its_root_in_a_named_volume_and_reads_the_caddyfile_read_only():
    compose = compose_text()
    proxy = proxy_service(compose)

    assert "      - caddy-data:/data\n" in proxy
    assert "      - ./docker/Caddyfile:/etc/caddy/Caddyfile:ro\n" in proxy
    assert compose.endswith("  caddy-data:\n")
    assert "condition: service_healthy" in proxy[proxy.index("depends_on:"):]


def test_the_caddyfile_serves_localhost_by_its_own_ca_to_the_api_with_no_body_limit():
    lines = caddy_lines()
    text = "\n".join(lines)

    assert "skip_install_trust" in lines
    assert "local_certs" in lines
    assert "localhost {" in lines
    assert "tls internal" in lines
    assert "reverse_proxy api:8000" in lines
    # The app's 64 KiB and 96 MiB caps are the only ones (C5.11, C5.7).
    assert "request_body" not in text
    assert "max_size" not in text
    # Nothing turns the Worker's checks off from this side either: no plain
    # http site, no other host.
    assert "http://" not in text
    assert [line for line in lines if line.endswith("{") and not line.startswith(("localhost", "{"))] == []
