from __future__ import annotations

import subprocess
from collections.abc import Sequence

from wpbench.env import down, status, up
from wpbench.proxy import ALLOWED, is_allowed, parse_connect
from wpbench.runplan import ContainerSpec


def test_parse_connect() -> None:
    assert parse_connect("CONNECT API.anthropic.com:443 HTTP/1.1\r\n") == ("api.anthropic.com", 443)
    for bad in ("GET http://x/ HTTP/1.1", "CONNECT nohost HTTP/1.1", "CONNECT a:b HTTP/1.1", "CONNECT a:443", ""):
        assert parse_connect(bad) is None


def test_allow_list_is_exact() -> None:
    assert is_allowed(("api.anthropic.com", 443))
    assert not is_allowed(("api.anthropic.com", 80))
    assert not is_allowed(("evil.api.anthropic.com", 443)) and not is_allowed(("example.com", 443))
    assert ALLOWED == {("api.anthropic.com", 443)}


class Fake:
    def __init__(self, fail: set[str] | None = None, outputs: dict[str, str] | None = None) -> None:
        self.calls: list[list[str]] = []
        self.fail, self.outputs = fail or set(), outputs or {}

    def __call__(self, cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        key = " ".join(cmd[:3])
        return subprocess.CompletedProcess(list(cmd), 1 if key in self.fail else 0, self.outputs.get(key, ""), "err")


def test_up_creates_an_internal_network_and_attaches_the_proxy() -> None:
    f = Fake(fail={"docker network inspect", "docker inspect wpbench-proxy"})
    up(ContainerSpec(), f)
    flat = [" ".join(c) for c in f.calls]
    assert any(c.startswith("docker network create --internal wpbench-egress") for c in flat)
    assert any("network connect --alias wpbench-proxy wpbench-egress wpbench-proxy" in c for c in flat)
    down(ContainerSpec(), f)


def test_status_requires_an_internal_network() -> None:
    ok = Fake(outputs={"docker network inspect": "true", "docker inspect wpbench-proxy": "true"})
    assert status(ContainerSpec(), ok).ready
    leaky = Fake(outputs={"docker network inspect": "false", "docker inspect wpbench-proxy": "true"})
    assert not status(ContainerSpec(), leaky).ready
