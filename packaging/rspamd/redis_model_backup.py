#!/usr/bin/env python3
"""Root-only RDB snapshots for the local Rspamd Bayes Redis database."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable


DEFAULT_BACKUP_ROOT = Path("/var/backups/had-antispam/rspamd/redis")
BACKUP_NAME_RE = re.compile(r"^redis-[0-9]{8}T[0-9]{6}Z$")
MAX_REDIS_COMMAND_SECONDS = 10


class BackupError(RuntimeError):
    pass


def parse_info(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_redis_cli(command: list[str], *, socket_path: str | None = None) -> str:
    redis_cli = shutil.which("redis-cli")
    if not redis_cli:
        raise BackupError("redis-cli não está instalado.")
    args = [redis_cli, "--raw"]
    if socket_path:
        args.extend(["-s", socket_path])
    args.extend(command)
    try:
        result = subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=MAX_REDIS_COMMAND_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BackupError("Não foi possível consultar o Redis local.") from exc
    output = result.stdout.strip()
    if result.returncode != 0 or output.startswith("ERR "):
        raise BackupError("O Redis recusou um comando administrativo de backup.")
    return output


def _read_config_pair(key: str) -> str:
    lines = _run_redis_cli(["CONFIG", "GET", key]).splitlines()
    if len(lines) != 2 or lines[0].strip() != key or not lines[1].strip():
        raise BackupError(f"Não foi possível ler a configuração Redis {key}.")
    return lines[1].strip()


def _read_info(section: str) -> dict[str, str]:
    return parse_info(_run_redis_cli(["INFO", section]))


def _wait_until_idle(timeout: float) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        info = _read_info("persistence")
        if info.get("rdb_bgsave_in_progress") == "0":
            return info
        time.sleep(0.25)
    raise BackupError("O Redis manteve um BGSAVE ativo além do limite de espera.")


def _trigger_rdb_save(rdb_path: Path, timeout: float = 120.0) -> None:
    before_mtime = rdb_path.stat().st_mtime_ns if rdb_path.exists() else -1
    _wait_until_idle(timeout)
    response = _run_redis_cli(["BGSAVE"]).lower()
    if "background saving" not in response:
        raise BackupError("O Redis não confirmou o início do snapshot RDB.")

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        info = _read_info("persistence")
        if (
            info.get("rdb_bgsave_in_progress") == "0"
            and info.get("rdb_last_bgsave_status") == "ok"
            and rdb_path.is_file()
            and rdb_path.stat().st_mtime_ns > before_mtime
        ):
            return
        time.sleep(0.25)
    raise BackupError("O snapshot RDB não terminou com sucesso dentro do prazo.")


def _write_atomic(path: Path, content: bytes, mode: int = 0o600) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _prepare_backup_root(root: Path) -> Path:
    if root.exists() and root.is_symlink():
        raise BackupError("O diretório de backup não pode ser um link simbólico.")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise BackupError("O destino de backup não é um diretório.")
    os.chmod(resolved, 0o700)
    return resolved


def parse_keyspace_info(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in text.splitlines():
        database, separator, values = line.partition(":")
        if not separator or not re.fullmatch(r"db[0-9]+", database):
            continue
        for item in values.split(","):
            key, equals, value = item.partition("=")
            if key == "keys" and equals and value.isdigit():
                counts[database] = int(value)
                break
    return counts


def _prune_old_backups(root: Path, retention_days: int, now: datetime) -> int:
    cutoff = now - timedelta(days=retention_days)
    removed = 0
    for child in root.iterdir():
        if child.is_symlink() or not child.is_dir() or not BACKUP_NAME_RE.fullmatch(child.name):
            continue
        manifest_path = child / "manifest.json"
        if manifest_path.is_symlink():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            created = datetime.fromisoformat(manifest["created_at"])
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if created.tzinfo is None or created >= cutoff:
            continue
        shutil.rmtree(child)
        removed += 1
    return removed


def create_backup(
    backup_root: Path = DEFAULT_BACKUP_ROOT,
    retention_days: int = 30,
    *,
    now: datetime | None = None,
    trigger_save: Callable[[Path], None] = _trigger_rdb_save,
) -> Path:
    if retention_days < 1 or retention_days > 3650:
        raise BackupError("A retenção deve estar entre 1 e 3650 dias.")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise BackupError("O horário do snapshot precisa incluir fuso horário.")

    redis_dir = Path(_read_config_pair("dir"))
    dbfilename = _read_config_pair("dbfilename")
    if Path(dbfilename).name != dbfilename or dbfilename in {"", ".", ".."}:
        raise BackupError("O nome do arquivo RDB configurado é inválido.")
    redis_dir = redis_dir.resolve(strict=True)
    rdb_path = redis_dir / dbfilename
    trigger_save(rdb_path)
    if not rdb_path.is_file() or rdb_path.is_symlink():
        raise BackupError("O snapshot Redis não é um arquivo RDB regular.")

    root = _prepare_backup_root(backup_root)
    stamp = current.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = root / f"redis-{stamp}"
    target.mkdir(mode=0o700)
    before = rdb_path.stat()
    destination = target / "dump.rdb"
    temporary = target / ".dump.rdb.tmp"
    try:
        with rdb_path.open("rb") as source, temporary.open("xb") as copy:
            shutil.copyfileobj(source, copy, length=1024 * 1024)
            copy.flush()
            os.fsync(copy.fileno())
        after = rdb_path.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ino,
        ):
            raise BackupError("O arquivo RDB mudou durante a cópia; backup cancelado.")
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
        server = _read_info("server")
        manifest = {
            "format_version": 1,
            "created_at": current.astimezone(timezone.utc).isoformat(),
            "redis_version": server.get("redis_version", "unknown"),
            "rdb_file": destination.name,
            "rdb_size": destination.stat().st_size,
            "rdb_sha256": sha256_file(destination),
        }
        _write_atomic(
            target / "manifest.json",
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        )
        os.chmod(target, 0o700)
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise

    removed = _prune_old_backups(root, retention_days, current.astimezone(timezone.utc))
    print(
        f"Backup Redis criado: {target}; bytes={manifest['rdb_size']}; "
        f"sha256={manifest['rdb_sha256']}; backups_expirados={removed}"
    )
    return target


def _validated_backup(backup: Path, backup_root: Path) -> tuple[Path, dict[str, object]]:
    if backup.is_symlink() or backup_root.is_symlink():
        raise BackupError("Links simbólicos não são aceitos no caminho de backup.")
    root = backup_root.resolve(strict=True)
    target = backup.resolve(strict=True)
    if target.parent != root or not BACKUP_NAME_RE.fullmatch(target.name) or not target.is_dir():
        raise BackupError("Informe um snapshot Redis direto dentro do diretório de backup configurado.")
    rdb_path = target / "dump.rdb"
    manifest_path = target / "manifest.json"
    if rdb_path.is_symlink() or manifest_path.is_symlink() or not rdb_path.is_file() or not manifest_path.is_file():
        raise BackupError("O snapshot não contém arquivos regulares esperados.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise BackupError("O manifesto do snapshot é inválido.") from exc
    if (
        manifest.get("format_version") != 1
        or manifest.get("rdb_file") != "dump.rdb"
        or manifest.get("rdb_size") != rdb_path.stat().st_size
        or not isinstance(manifest.get("rdb_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", manifest["rdb_sha256"])
        or sha256_file(rdb_path) != manifest["rdb_sha256"]
    ):
        raise BackupError("O checksum ou os metadados do RDB não conferem.")
    return rdb_path, manifest


def verify_rdb(rdb_path: Path) -> dict[str, int]:
    redis_server = shutil.which("redis-server")
    if not redis_server:
        raise BackupError("redis-server é necessário para validar a leitura isolada do RDB.")
    with tempfile.TemporaryDirectory(prefix="had-rspamd-rdb-verify-") as temp_name:
        temp = Path(temp_name)
        shutil.copyfile(rdb_path, temp / "dump.rdb")
        socket_path = str(temp / "redis.sock")
        process = subprocess.Popen(
            [
                redis_server,
                "--port",
                "0",
                "--unixsocket",
                socket_path,
                "--unixsocketperm",
                "700",
                "--daemonize",
                "no",
                "--save",
                "",
                "--appendonly",
                "no",
                "--dir",
                str(temp),
                "--dbfilename",
                "dump.rdb",
                "--logfile",
                "",
                "--loglevel",
                "warning",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise BackupError("Redis isolado encerrou ao validar o RDB.")
                if Path(socket_path).exists():
                    try:
                        if _run_redis_cli(["PING"], socket_path=socket_path) == "PONG":
                            return parse_keyspace_info(
                                _run_redis_cli(["INFO", "keyspace"], socket_path=socket_path)
                            )
                    except BackupError:
                        pass
                time.sleep(0.1)
            raise BackupError("Redis isolado não iniciou dentro do limite para validar o RDB.")
        finally:
            if process.poll() is None:
                try:
                    _run_redis_cli(["SHUTDOWN", "NOSAVE"], socket_path=socket_path)
                except BackupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)


def verify_backup(backup: Path, backup_root: Path = DEFAULT_BACKUP_ROOT) -> None:
    rdb, manifest = _validated_backup(backup, backup_root)
    counts = verify_rdb(rdb)
    print(
        f"Snapshot válido e carregado em Redis isolado: {backup.resolve()}; "
        f"bytes={manifest['rdb_size']}; databases={len(counts)}"
    )


def _require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise BackupError("Execute este comando como root.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Backup e verificação privada do RDB Redis do Rspamd.")
    parser.add_argument("action", choices=("backup", "verify"))
    parser.add_argument("snapshot", nargs="?", help="snapshot redis-YYYYmmddTHHMMSSZ para verify")
    parser.add_argument("--backup-root", type=Path, default=DEFAULT_BACKUP_ROOT)
    parser.add_argument("--retention-days", type=int, default=30)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _require_root()
        if args.action == "backup":
            if args.snapshot:
                raise BackupError("Não informe snapshot no modo backup.")
            create_backup(args.backup_root, args.retention_days)
        else:
            if not args.snapshot:
                raise BackupError("Informe o caminho do snapshot a verificar.")
            verify_backup(Path(args.snapshot), args.backup_root)
    except BackupError as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
