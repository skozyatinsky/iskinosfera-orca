#!/usr/bin/env python3
# ======================================================================
# candidate_sandbox.py — версия 2.0
# Private-root Linux namespace adapter for untrusted candidate code.
# ======================================================================
from __future__ import annotations

import argparse
import ctypes
import os
import resource
import subprocess
import sys
import tempfile
from pathlib import Path

LIBC = ctypes.CDLL(None, use_errno=True)
PR_SET_NO_NEW_PRIVS = 38
PR_CAPBSET_DROP = 24
MNT_DETACH = 2
X86_64_MACHINES = {"x86_64", "amd64"}


def _syscall_number(name: str, x86_64_number: int, asm_generic_number: int, machine: str | None = None) -> int:
    """Select a syscall number for the running ABI.

    x86_64 keeps its own table; every other supported architecture (arm64 in
    particular) follows the asm-generic numbering, where the numbers differ.
    """
    override = getattr(os, f"SYS_{name}", None)
    if override is not None:
        return override
    machine = machine if machine is not None else os.uname().machine
    return x86_64_number if machine in X86_64_MACHINES else asm_generic_number


SYS_PIVOT_ROOT = _syscall_number("pivot_root", 155, 41)
SYS_CAPSET = _syscall_number("capset", 126, 91)


class SandboxError(RuntimeError):
    pass


def _run(argv: list[str]) -> None:
    proc = subprocess.run(argv, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SandboxError(f"SANDBOX_SETUP_FAILED:{' '.join(argv)}:{proc.stderr.strip()}")


def _mkdir(path: Path, mode: int = 0o755) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)


def _bind_readonly(source: Path, target: Path) -> None:
    _mkdir(target if source.is_dir() else target.parent)
    if source.is_file() and not target.exists():
        target.touch()
    _run(["mount", "--rbind", str(source), str(target)])
    _run(["mount", "--make-rslave", str(target)])
    # util-linux supports recursive read-only remount through -R on modern hosts.
    proc = subprocess.run(
        ["mount", "-R", "-o", "remount,bind,ro,nosuid,nodev", str(target)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        _run(["mount", "-o", "remount,bind,ro,nosuid,nodev", str(target)])


def _bind_device(source: str, root: Path) -> None:
    target = root / source.lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch(exist_ok=True)
    _run(["mount", "--bind", source, str(target)])


def _drop_capabilities() -> None:
    for capability in range(0, 64):
        LIBC.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0)

    class CapHeader(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class CapData(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    header = CapHeader(0x20080522, 0)
    data = (CapData * 2)()
    if LIBC.syscall(SYS_CAPSET, ctypes.byref(header), ctypes.byref(data)) != 0:
        err = ctypes.get_errno()
        raise SandboxError(f"SANDBOX_CAPABILITY_DROP_FAILED:{err}")
    if LIBC.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise SandboxError(f"SANDBOX_NO_NEW_PRIVS_FAILED:{err}")


def _pivot_root(new_root: Path) -> None:
    old_root = new_root / "oldroot"
    _mkdir(old_root)
    os.chdir(new_root)
    if LIBC.syscall(SYS_PIVOT_ROOT, b".", b"oldroot") != 0:
        err = ctypes.get_errno()
        raise SandboxError(f"SANDBOX_PIVOT_ROOT_FAILED:{err}")
    os.chdir("/")
    if LIBC.umount2(b"/oldroot", MNT_DETACH) != 0:
        err = ctypes.get_errno()
        raise SandboxError(f"SANDBOX_OLDROOT_DETACH_FAILED:{err}")
    try:
        os.rmdir("/oldroot")
    except OSError as exc:
        raise SandboxError(f"SANDBOX_OLDROOT_REMOVE_FAILED:{exc.errno}") from exc


def _prepare_root(workspace: Path, readonly_paths: list[Path], writable_paths: list[Path]) -> Path:
    _run(["mount", "--make-rprivate", "/"])
    host_root = Path(tempfile.mkdtemp(prefix="aps_private_root_"))
    _run(["mount", "-t", "tmpfs", "-o", "mode=0755,nosuid,nodev", "tmpfs", str(host_root)])

    for name in ("workspace", "tmp", "proc", "dev", "home/candidate", "run"):
        _mkdir(host_root / name, 0o700 if name in {"tmp", "home/candidate"} else 0o755)

    _bind_readonly(workspace, host_root / "workspace")

    # Install the private /tmp before any explicitly approved paths located
    # below host /tmp are mounted. This prevents the tmpfs from hiding the
    # trusted validator tree and controlled evidence output directories.
    _run(["mount", "-t", "tmpfs", "-o", "mode=1777,nosuid,nodev,noexec", "tmpfs", str(host_root / "tmp")])

    # Runtime only: no /home, host /tmp, Docker socket, trusted DB or repository
    # siblings are mounted into the private root.
    for system_path in (Path("/usr"),):
        if system_path.exists():
            _bind_readonly(system_path, host_root / system_path.relative_to("/"))

    for link_name in ("bin", "lib", "lib64", "sbin"):
        source = Path("/") / link_name
        target = host_root / link_name
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        elif source.exists():
            _bind_readonly(source, target)

    for source in readonly_paths:
        source = source.resolve()
        target = host_root / source.relative_to("/")
        _bind_readonly(source, target)

    for source in writable_paths:
        source = source.resolve()
        target = host_root / source.relative_to("/")
        _mkdir(target if source.is_dir() else target.parent)
        if source.is_file() and not target.exists():
            target.touch()
        _run(["mount", "--bind", str(source), str(target)])

    _run(["mount", "-t", "tmpfs", "-o", "mode=0755,nosuid", "tmpfs", str(host_root / "dev")])
    for device in ("/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"):
        _bind_device(device, host_root)
    _run(["mount", "-t", "tmpfs", "-o", "mode=0555,nosuid,nodev,noexec", "tmpfs", str(host_root / "proc")])
    return host_root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--readonly-path", action="append", default=[])
    parser.add_argument("--writable-path", action="append", default=[])
    parser.add_argument("--workdir", default="/workspace")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("SANDBOX_COMMAND_MISSING", file=sys.stderr)
        return 2
    try:
        workspace = Path(args.workspace).resolve(strict=True)
        readonly = [Path(value).resolve(strict=True) for value in args.readonly_path]
        writable = [Path(value).resolve(strict=True) for value in args.writable_path]
        root = _prepare_root(workspace, readonly, writable)
        _pivot_root(root)
        _drop_capabilities()
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.chdir(args.workdir)
        sandbox_tmp = os.path.join(os.sep, "tmp")
        os.environ.update({
            "HOME": os.path.join(os.sep, "home", "candidate"),
            "TMPDIR": sandbox_tmp,
            "TEMP": sandbox_tmp,
            "TMP": sandbox_tmp,
            "PATH": os.pathsep.join([
                os.path.join(os.sep, "usr", "local", "bin"),
                os.path.join(os.sep, "usr", "bin"),
                os.path.join(os.sep, "bin"),
            ]),
        })
    except (OSError, ValueError, SandboxError) as exc:
        print(str(exc), file=sys.stderr)
        return 126
    os.execvpe(command[0], command, os.environ)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
