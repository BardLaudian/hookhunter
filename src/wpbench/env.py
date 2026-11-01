"""Docker environment for the agent runs: images, the internal network and the egress proxy."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from wpbench.runplan import ContainerSpec

Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]
PROXY_IMAGE = "wpbench-proxy:1"
PROXY_NAME = "wpbench-proxy"


def sh(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(cmd), capture_output=True, text=True, check=False)


@dataclass
class EnvStatus:
    image: bool
    proxy_image: bool
    network_internal: bool
    proxy_running: bool

    @property
    def ready(self) -> bool:
        return self.image and self.network_internal and self.proxy_running


def status(spec: ContainerSpec, run: Runner = sh) -> EnvStatus:
    image = run(["docker", "image", "inspect", spec.image]).returncode == 0
    pimage = run(["docker", "image", "inspect", PROXY_IMAGE]).returncode == 0
    net = run(["docker", "network", "inspect", spec.network, "--format", "{{.Internal}}"])
    running = run(["docker", "inspect", PROXY_NAME, "--format", "{{.State.Running}}"])
    return EnvStatus(image, pimage, net.returncode == 0 and net.stdout.strip() == "true", running.returncode == 0 and running.stdout.strip() == "true")


def build(spec: ContainerSpec, root: Path = Path("."), run: Runner = sh, claude_binary: Path | None = None) -> list[str]:
    """Build both images. Returns the log lines; raises RuntimeError on the first failure."""
    log: list[str] = []
    binary = claude_binary or Path(shutil.which("claude") or "").resolve()
    if not binary.is_file():
        raise RuntimeError("claude binary not found; pass it explicitly")
    docker = root / "docker"
    shutil.copy2(binary, docker / "claude")
    shutil.copy2(root / "src" / "wpbench" / "proxy.py", docker / "proxy.py")
    for image, dockerfile in ((spec.image, "Dockerfile.agent"), (PROXY_IMAGE, "Dockerfile.proxy")):
        res = run(["docker", "build", "-q", "-t", image, "-f", str(docker / dockerfile), str(docker)])
        log.append(f"{image}: {'ok' if res.returncode == 0 else 'FAILED'} {res.stdout.strip()[:80]}")
        if res.returncode != 0:
            raise RuntimeError(f"docker build {image} failed:\n{res.stderr[-800:]}")
    return log


def up(spec: ContainerSpec, run: Runner = sh) -> list[str]:
    """Create the internal network and start the proxy, attached to the default bridge (outbound) and the internal network."""
    log: list[str] = []
    if run(["docker", "network", "inspect", spec.network]).returncode != 0:
        res = run(["docker", "network", "create", "--internal", spec.network])
        if res.returncode != 0:
            raise RuntimeError(res.stderr)
        log.append(f"network {spec.network} created (internal)")
    if run(["docker", "inspect", PROXY_NAME]).returncode == 0:
        run(["docker", "rm", "-f", PROXY_NAME])
    res = run(["docker", "run", "-d", "--name", PROXY_NAME, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--restart", "unless-stopped", PROXY_IMAGE])
    if res.returncode != 0:
        raise RuntimeError(res.stderr)
    res = run(["docker", "network", "connect", "--alias", PROXY_NAME, spec.network, PROXY_NAME])
    if res.returncode != 0:
        raise RuntimeError(res.stderr)
    log.append("proxy started and attached to " + spec.network)
    return log


def down(spec: ContainerSpec, run: Runner = sh) -> list[str]:
    run(["docker", "rm", "-f", PROXY_NAME])
    run(["docker", "network", "rm", spec.network])
    return ["proxy and network removed"]
