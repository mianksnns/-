#!/usr/bin/env python3
"""ciphey_api.py - Core API wrapper around the ciphey decoding tool.

Two backends are supported:

1. Native PyO3 bindings (preferred). When the compiled extension module
   `ciphey` (target/release/libciphey.so, built with
   ``cargo build --release --features python``) is importable, decoding runs
   entirely in-process with no subprocess and no output parsing.
2. The ciphey CLI subprocess, used as a fallback. It invokes the binary with
   ``--json`` and parses the JSON document.

Usage:
    python3 ciphey_api.py "SGVsbG8gV29ybGQ="
    python3 ciphey_api.py --binary /path/to/ciphey --timeout 15 "your ciphertext"

Can also be imported and used as a library:

    from ciphey_api import ciphey_decrypt, CipheyResult
    result = ciphey_decrypt("SGVsbG8gV29ybGQ=")
    if result.success:
        print(result.plaintext)
"""

import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional

# ANSI escape sequences used by ciphey for coloured output.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


@dataclass
class CipheyResult:
    """Structured result returned by ciphey.

    Attributes:
        success: True when a plaintext was recovered.
        plaintext: The decoded plaintext (empty on failure).
        decoders: Ordered list of decoders used in the decoding path.
        error: Human readable error message (empty on success).
    """

    success: bool
    plaintext: str = ""
    decoders: List[str] = field(default_factory=list)
    error: str = ""


def _try_load_native_module() -> Optional[object]:
    """Try to import the native PyO3 extension module.

    Returns the module object, or None when it is not available. When present,
    decoding uses the in-process bindings instead of spawning a subprocess.
    """
    # Try the on-disk build output first, then the regular import path.
    candidates = ["ciphey"]
    try:
        module = importlib.import_module("ciphey")
        if hasattr(module, "crack"):
            return module
    except ImportError:
        pass

    for name in candidates:
        spec = importlib.util.find_spec(name)
        if spec is not None:
            try:
                module = importlib.import_module(name)
                if hasattr(module, "crack"):
                    return module
            except ImportError:
                continue
    return None


_NATIVE_MODULE = _try_load_native_module()


def _strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def _find_binary(binary: str) -> Optional[str]:
    """Locate the ciphey binary. Returns an absolute path or None."""
    if shutil.which(binary):
        return shutil.which(binary)
    return None


def _parse_json_output(stdout: str) -> CipheyResult:
    """Parse the JSON document emitted by ciphey --json into a CipheyResult."""
    text = _strip_ansi(stdout).strip()
    # Locate the JSON document: it starts at the first '{'.
    start = text.find("{")
    if start == -1:
        return CipheyResult(
            success=False,
            error=f"No JSON document found in ciphey output. Raw output:\n{text}",
        )
    try:
        data = json.loads(text[start:])
    except json.JSONDecodeError as exc:
        return CipheyResult(
            success=False,
            error=f"Failed to parse ciphey JSON output: {exc}. Raw output:\n{text}",
        )

    if data.get("success"):
        return CipheyResult(
            success=True,
            plaintext=data.get("plaintext", ""),
            decoders=[str(d) for d in data.get("path", [])],
        )

    return CipheyResult(
        success=False,
        error=data.get("error", "ciphey could not decode the text within the timeout."),
    )


def ciphey_decrypt(
    ciphertext: str,
    binary: str = "ciphey",
    timeout: int = 30,
    extra_args: Optional[List[str]] = None,
) -> CipheyResult:
    """Run ciphey on the given ciphertext and return a CipheyResult.

    When the native PyO3 extension is importable it is used directly
    (no subprocess). Otherwise the ciphey executable is invoked with ``--json``
    and the output is parsed.

    Args:
        ciphertext: The encoded text to decode.
        binary: Name or path of the ciphey executable.
        timeout: Number of seconds ciphey is allowed to run.
        extra_args: Optional extra CLI flags for ciphey (e.g. ["--regex", "..."]).
            Only used with the subprocess backend.

    Returns:
        A CipheyResult containing either the decoded plaintext and the
        decoders used, or an error description.
    """
    # Native in-process path.
    if _NATIVE_MODULE is not None and not extra_args:
        try:
            result = _NATIVE_MODULE.crack(ciphertext, timeout=timeout)
            if result.success:
                return CipheyResult(
                    success=True,
                    plaintext=result.plaintext or "",
                    decoders=list(result.path),
                )
            return CipheyResult(
                success=False,
                error="ciphey could not decode the text within the timeout.",
            )
        except Exception as exc:  # noqa: BLE001 - fall back to the subprocess path
            return CipheyResult(
                success=False,
                error=f"Native ciphey module failed: {exc}",
            )

    # Subprocess fallback.
    bin_path = _find_binary(binary)
    if bin_path is None:
        return CipheyResult(
            success=False,
            error=(
                f"ciphey binary '{binary}' not found. Install it or pass --binary. "
                "See https://github.com/bee-san/ciphey for build instructions."
            ),
        )

    command = [bin_path, "-t", ciphertext, "-d", "--json"]
    if extra_args:
        command.extend(extra_args)

    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return CipheyResult(
            success=False,
            error=f"ciphey timed out after {timeout} seconds.",
        )
    except OSError as exc:
        return CipheyResult(
            success=False,
            error=f"Failed to run ciphey: {exc}",
        )

    result = _parse_json_output(proc.stdout)
    if not result.success and proc.stderr.strip():
        result.error = f"{result.error}\n{_strip_ansi(proc.stderr).strip()}"
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decode ciphertext using the ciphey tool.",
    )
    parser.add_argument("ciphertext", help="The encoded text to decode.")
    parser.add_argument(
        "--binary",
        default="ciphey",
        help="Name or path of the ciphey executable (default: ciphey).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Seconds allowed for decoding (default: 30).",
    )
    args = parser.parse_args()

    backend = "native (PyO3)" if _NATIVE_MODULE is not None else "subprocess"
    result = ciphey_decrypt(
        args.ciphertext,
        binary=args.binary,
        timeout=args.timeout,
    )

    if result.success:
        print(f"Plaintext: {result.plaintext}")
        if result.decoders:
            print(f"Decoders used: {' -> '.join(result.decoders)}")
    else:
        print(f"Failed to decode: {result.error}")
    print(f"[backend: {backend}]")


if __name__ == "__main__":
    main()
