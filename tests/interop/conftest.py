"""Explicit integration suite: python -m pytest tests/interop (requires local oracle setup)."""

import base64
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from run_java_tests import BUILD, jdk_tool  # noqa: E402


class Oracle:
    def __init__(self, native=False):
        cp = (
            str(BUILD / "classes")
            + ":"
            + ":".join(str(BUILD / p) for p in ("curve25519.jar", "protobuf.jar", "junit.jar"))
        )
        args = [jdk_tool("java")]
        if native:
            args.append("-Djava.library.path=" + str(BUILD))
        self.proc = subprocess.Popen(
            [*args, "-cp", cp, "InteropOracle"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )

    def call(self, *args):
        fields = [base64.b64encode(x).decode() if isinstance(x, bytes) else str(x) for x in args]
        self.proc.stdin.write("\t".join(fields) + "\n")
        self.proc.stdin.flush()
        response = self.proc.stdout.readline().rstrip("\n").split("\t")
        if response[0] != "OK":
            raise RuntimeError("\t".join(response))
        return response[1:]

    def raw(self, *args):
        return base64.b64decode(self.call(*args)[0])

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)
        self.proc.stdout.close()
        assert self.proc.returncode == 0


@pytest.fixture(scope="module")
def java():
    if not (BUILD / "classes/InteropOracle.class").exists():
        pytest.fail("Run python tools/prepare_java.py and python tools/run_java_tests.py first")
    obj = Oracle()
    yield obj
    obj.close()


@pytest.fixture(scope="module")
def native_java():
    obj = Oracle(True)
    yield obj
    obj.close()
