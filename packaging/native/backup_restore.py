#!/usr/bin/env python3
"""Consistent, version-pinned backup and restore for the native SPFBL bundle."""

from __future__ import print_function

import argparse
import datetime
import hashlib
import json
import os
try:
    import pwd
    import grp
except ImportError:  # Test imports on Windows; the deployed CLI runs on Linux.
    pwd = None
    grp = None
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath


FORMAT_VERSION = 1
MAX_UNCOMPRESSED_BYTES = 20 * 1024 * 1024 * 1024
SERVICE = "had-antispam-core.service"
APP = Path("/opt/spfbl")
ETC = Path("/etc/spamfox")
STATE = Path("/var/lib/had-antispam")
BACKUPS = Path("/var/backups/had-antispam")
ETC_ARCHIVE = "etc/spamfox"
LEGACY_ETC_ARCHIVE = "etc/had-antispam"
STATE_ARCHIVE = "var/lib/had-antispam"


class BackupError(RuntimeError):
    pass


class Layout(object):
    def __init__(self, app=APP, etc=ETC, state=STATE, backups=BACKUPS):
        self.app = Path(app)
        self.etc = Path(etc)
        self.state = Path(state)
        self.backups = Path(backups)

    def core_version(self):
        current = self.app / "current"
        for candidate in (current / "release" / "version", current / "version"):
            if candidate.is_file():
                value = candidate.read_text(encoding="utf-8").strip()
                if value:
                    return value
        try:
            return current.resolve(strict=True).name
        except OSError as exc:
            raise BackupError("Não foi possível identificar a release ativa: {0}".format(exc))


class SystemdService(object):
    def __init__(self, layout=None, service=SERVICE):
        self.layout = layout or Layout()
        self.service = service

    @staticmethod
    def _unit_active(unit):
        result = subprocess.run(
            ["/usr/bin/systemctl", "is-active", unit],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True,
        )
        return result.returncode == 0 and result.stdout.strip() == "active"

    def pause_maintenance(self):
        timer = "had-antispam-store.timer"
        store = "had-antispam-store.service"
        timer_was_active = self._unit_active(timer)
        try:
            if timer_was_active:
                subprocess.run(["/usr/bin/systemctl", "stop", timer], check=True)
            if self._unit_active(store):
                subprocess.run(["/usr/bin/systemctl", "stop", store], check=True)
        except Exception:
            if timer_was_active:
                subprocess.run(["/usr/bin/systemctl", "start", timer], check=False)
            raise
        return timer_was_active

    @staticmethod
    def resume_maintenance(timer_was_active):
        if timer_was_active:
            subprocess.run(["/usr/bin/systemctl", "start", "had-antispam-store.timer"], check=True)

    def active(self):
        result = subprocess.run(
            ["/usr/bin/systemctl", "is-active", self.service],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True,
        )
        state = result.stdout.strip()
        if result.returncode == 0 and state == "active":
            return True
        if state in ("inactive", "failed", "unknown", "deactivating"):
            return False
        raise BackupError("Estado systemd inesperado para {0}: {1}".format(self.service, state or "sem resposta"))

    def stop(self):
        subprocess.run(["/usr/bin/systemctl", "stop", self.service], check=True)
        if self.active():
            raise BackupError("O serviço SPFBL continuou ativo após systemctl stop")

    def start(self):
        subprocess.run(["/usr/bin/systemctl", "start", self.service], check=True)

    def wait_ready(self, timeout=120):
        control = self.layout.app / "current" / "control.py"
        deadline = time.monotonic() + timeout
        last_error = None
        while time.monotonic() < deadline:
            try:
                if self.active():
                    result = subprocess.run(
                        [str(control), "version"], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, timeout=5, universal_newlines=True,
                    )
                    if result.returncode == 0 and result.stdout.strip().startswith("SPFBL-"):
                        return result.stdout.strip()
                    last_error = result.stderr.strip() or result.stdout.strip()
            except (OSError, subprocess.SubprocessError, BackupError) as exc:
                last_error = str(exc)
            time.sleep(1)
        raise BackupError("SPFBL não ficou pronto após {0}s: {1}".format(timeout, last_error or "sem resposta"))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ensure_private_directory(path):
    path = Path(path)
    if path.is_symlink():
        raise BackupError("Diretório de backup não pode ser link simbólico: {0}".format(path))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        info = path.stat()
        if info.st_uid != 0:
            raise BackupError("Diretório de backup deve pertencer ao root: {0}".format(path))
        os.chmod(str(path), 0o700)
    return path


def _validate_source(layout):
    for name, path in (("configuração", layout.etc), ("estado", layout.state)):
        if path.is_symlink() or not path.is_dir():
            raise BackupError("Diretório de {0} ausente ou não é diretório real: {1}".format(name, path))
    required = (
        layout.etc / "spfbl.conf",
        layout.state / "data",
        layout.state / "data" / "server.key",
        layout.state / "history",
    )
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        raise BackupError("Estado incompleto para backup/restore: {0}".format(", ".join(missing)))
    if not (layout.state / "data" / "server.key").is_file():
        raise BackupError("data/server.key não é um arquivo regular; backup recusado para preservar tickets")


def _collect_files(layout):
    roots = ((layout.etc, ETC_ARCHIVE), (layout.state, STATE_ARCHIVE))
    files = []
    for source, archive_root in roots:
        for directory, subdirs, names in os.walk(str(source), topdown=True, followlinks=False):
            relative_dir = Path(directory).relative_to(source)
            if source == layout.state and relative_dir == Path("."):
                subdirs[:] = [name for name in subdirs if name != ".junique"]
            subdirs.sort()
            names.sort()
            for name in list(subdirs) + names:
                path = Path(directory) / name
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise BackupError("Link simbólico dentro dos dados/configuração; backup recusado: {0}".format(path))
                if stat.S_ISDIR(info.st_mode):
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise BackupError("Arquivo especial dentro dos dados/configuração; backup recusado: {0}".format(path))
                if source == layout.state and path.relative_to(source).parts[:1] == (".junique",):
                    continue
                relative = path.relative_to(source).as_posix()
                archive_name = archive_root + "/" + relative
                files.append({
                    "path": archive_name,
                    "size": info.st_size,
                    "sha256": sha256_file(path),
                    "mode": stat.S_IMODE(info.st_mode),
                    "uid": info.st_uid,
                    "gid": info.st_gid,
                })
    return sorted(files, key=lambda item: item["path"])


def _add_tree(tar, source, archive_root, skip_junique=False):
    source = Path(source)
    tar.add(str(source), arcname=archive_root, recursive=False)
    for directory, subdirs, names in os.walk(str(source), topdown=True, followlinks=False):
        current = Path(directory)
        relative = current.relative_to(source)
        if skip_junique and relative == Path("."):
            subdirs[:] = [name for name in subdirs if name != ".junique"]
        subdirs.sort()
        names.sort()
        for name in subdirs:
            child = current / name
            info = child.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise BackupError("Diretório alterado durante backup: {0}".format(child))
            tar.add(str(child), arcname=archive_root + "/" + child.relative_to(source).as_posix(), recursive=False)
        for name in names:
            child = current / name
            info = child.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise BackupError("Arquivo alterado durante backup: {0}".format(child))
            if skip_junique and child.relative_to(source).parts[:1] == (".junique",):
                continue
            tar.add(str(child), arcname=archive_root + "/" + child.relative_to(source).as_posix(), recursive=False)


def create_archive(layout, output_dir, prefix="spfbl"):
    _validate_source(layout)
    output_dir = _ensure_private_directory(output_dir)
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    token = uuid.uuid4().hex[:8]
    archive = output_dir / "{0}-{1}-{2}.tar.gz".format(prefix, timestamp, token)
    temporary = output_dir / ("." + archive.name + ".partial")
    manifest = {
        "format_version": FORMAT_VERSION,
        "created_utc": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source_version": layout.core_version(),
        "scope": ["/etc/spamfox", "/var/lib/had-antispam except .junique runtime locks"],
        "files": _collect_files(layout),
    }
    try:
        with tarfile.open(str(temporary), mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
            _add_tree(tar, layout.etc, ETC_ARCHIVE)
            _add_tree(tar, layout.state, STATE_ARCHIVE, skip_junique=True)
            encoded = json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
            info = tarfile.TarInfo("MANIFEST.json")
            info.size = len(encoded)
            info.mode = 0o600
            info.uid = 0
            info.gid = 0
            info.mtime = int(time.time())
            import io
            tar.addfile(info, io.BytesIO(encoded))
        os.chmod(str(temporary), 0o600)
        os.replace(str(temporary), str(archive))
        digest = sha256_file(archive)
        checksum_path = Path(str(archive) + ".sha256")
        checksum_temp = Path(str(checksum_path) + ".partial")
        checksum_temp.write_text("{0}  {1}\n".format(digest, archive.name), encoding="ascii")
        os.chmod(str(checksum_temp), 0o600)
        os.replace(str(checksum_temp), str(checksum_path))
        inspect_archive(archive, expected_version=manifest["source_version"])
        return archive, digest, manifest
    except Exception:
        for path in (temporary, archive, Path(str(archive) + ".sha256"), Path(str(archive) + ".sha256.partial")):
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _read_checksum(archive):
    checksum_path = Path(str(archive) + ".sha256")
    if not checksum_path.is_file() or checksum_path.is_symlink():
        raise BackupError("Checksum lateral ausente; esperado: {0}".format(checksum_path))
    fields = checksum_path.read_text(encoding="ascii").strip().split()
    if not fields or len(fields[0]) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in fields[0]):
        raise BackupError("Arquivo SHA-256 inválido: {0}".format(checksum_path))
    actual = sha256_file(archive)
    if actual.lower() != fields[0].lower():
        raise BackupError("SHA-256 do backup não confere")
    return actual


def _validate_member_name(name):
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        raise BackupError("Caminho inválido no arquivo: {0!r}".format(name))
    normalized = name.rstrip("/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise BackupError("Caminho inseguro no arquivo: {0}".format(name))
    value = path.as_posix()
    config_roots = (ETC_ARCHIVE, LEGACY_ETC_ARCHIVE)
    if value != "MANIFEST.json" and value not in config_roots + (STATE_ARCHIVE,) \
            and not any(value.startswith(root + "/") for root in config_roots + (STATE_ARCHIVE,)):
        raise BackupError("Caminho fora do escopo de restore: {0}".format(name))
    return value


def inspect_archive(archive_path, expected_version=None):
    archive_path = Path(archive_path)
    if archive_path.is_symlink() or not archive_path.is_file():
        raise BackupError("Arquivo de backup ausente ou link simbólico: {0}".format(archive_path))
    digest = _read_checksum(archive_path)
    try:
        tar = tarfile.open(str(archive_path), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise BackupError("Backup não é um tar.gz válido: {0}".format(exc))
    with tar:
        members = tar.getmembers()
        seen = set()
        file_members = {}
        total_size = 0
        manifest_member = None
        for member in members:
            name = _validate_member_name(member.name)
            if name in seen:
                raise BackupError("Caminho duplicado no arquivo: {0}".format(name))
            seen.add(name)
            if member.isdir():
                continue
            if not member.isfile():
                raise BackupError("Link ou arquivo especial não permitido: {0}".format(name))
            total_size += member.size
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise BackupError("Arquivo excede o limite de descompactação de 20 GiB")
            if name == "MANIFEST.json":
                if member.size > 4 * 1024 * 1024:
                    raise BackupError("Manifesto excede 4 MiB")
                manifest_member = member
            else:
                file_members[name] = member
        if manifest_member is None:
            raise BackupError("Manifesto ausente no backup")
        stream = tar.extractfile(manifest_member)
        try:
            manifest = json.loads(stream.read().decode("utf-8"))
        except (AttributeError, UnicodeDecodeError, ValueError) as exc:
            raise BackupError("Manifesto inválido: {0}".format(exc))
        if manifest.get("format_version") != FORMAT_VERSION or not isinstance(manifest.get("files"), list):
            raise BackupError("Versão/formato de backup não suportado")
        expected_files = {}
        for entry in manifest["files"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
                raise BackupError("Entrada de arquivo inválida no manifesto")
            name = _validate_member_name(entry["path"])
            if name == "MANIFEST.json" or name in expected_files:
                raise BackupError("Arquivo duplicado/inesperado no manifesto: {0}".format(name))
            expected_files[name] = entry
        if set(file_members) != set(expected_files):
            raise BackupError("Conteúdo não corresponde ao manifesto do backup")
        for name, member in file_members.items():
            entry = expected_files[name]
            if member.size != entry.get("size"):
                raise BackupError("Tamanho diverge do manifesto: {0}".format(name))
            if not isinstance(entry.get("sha256"), str) or len(entry["sha256"]) != 64:
                raise BackupError("Hash ausente/inválido no manifesto: {0}".format(name))
            source = tar.extractfile(member)
            digest_file = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest_file.update(chunk)
            if digest_file.hexdigest() != entry["sha256"].lower():
                raise BackupError("Hash interno não confere: {0}".format(name))
        has_config = any(
            name in expected_files
            for name in (ETC_ARCHIVE + "/spfbl.conf", LEGACY_ETC_ARCHIVE + "/spfbl.conf")
        )
        if not has_config or STATE_ARCHIVE + "/data/server.key" not in expected_files:
            raise BackupError("Backup não contém configuração e chave de tickets completas")
        if not any(name.startswith("var/lib/had-antispam/data/") for name in expected_files):
            raise BackupError("Diretório de dados SPFBL ausente no backup")
        if not any(name.startswith("var/lib/had-antispam/history/") for name in seen):
            # A history directory can be empty; tar must still contain its directory entry.
            if "var/lib/had-antispam/history" not in seen:
                raise BackupError("Diretório de histórico ausente no backup")
        version = manifest.get("source_version")
        if not isinstance(version, str) or not version:
            raise BackupError("Release de origem ausente no manifesto")
        if expected_version is not None and version != expected_version:
            raise BackupError("Release incompatível: backup={0}; instalado={1}".format(version, expected_version))
        return {"manifest": manifest, "sha256": digest, "archive": str(archive_path)}


def _extract_verified(archive_path, destination, manifest):
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tarfile.open(str(archive_path), mode="r:gz") as tar:
        directories = []
        for member in tar.getmembers():
            name = _validate_member_name(member.name)
            if name == "MANIFEST.json":
                continue
            target = destination.joinpath(*PurePosixPath(name).parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                directories.append((target, member.mode))
                continue
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = tar.extractfile(member)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(str(target), flags, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            os.chmod(str(target), member.mode & 0o777)
        for directory, mode in sorted(directories, key=lambda item: len(item[0].parts), reverse=True):
            os.chmod(str(directory), mode & 0o777)
    return destination


def _normalize_ownership(etc_stage, state_stage):
    if os.name != "posix":
        return
    if pwd is None or grp is None:
        raise BackupError("Módulo POSIX de permissões não está disponível")
    try:
        service_uid = pwd.getpwnam("hadantispam").pw_uid
        service_gid = grp.getgrnam("hadantispam").gr_gid
    except KeyError as exc:
        raise BackupError("Conta/grupo hadantispam não existe; restore cancelado: {0}".format(exc))
    os.chown(str(state_stage), service_uid, service_gid)
    os.chmod(str(state_stage), 0o750)
    for directory, subdirs, files in os.walk(str(state_stage), topdown=False):
        for name in files:
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise BackupError("Tipo de arquivo inesperado no estágio de estado: {0}".format(path))
            os.chown(str(path), service_uid, service_gid)
            os.chmod(str(path), stat.S_IMODE(info.st_mode) & 0o640)
        for name in subdirs:
            path = Path(directory) / name
            os.chown(str(path), service_uid, service_gid)
            os.chmod(str(path), 0o750)
    for directory, subdirs, files in os.walk(str(etc_stage), topdown=False):
        for name in files:
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise BackupError("Tipo de arquivo inesperado na configuração restaurada: {0}".format(path))
            os.chown(str(path), 0, service_gid)
            os.chmod(str(path), 0o640)
        for name in subdirs:
            path = Path(directory) / name
            os.chown(str(path), 0, service_gid)
            os.chmod(str(path), 0o750)
    os.chown(str(etc_stage), 0, service_gid)
    os.chmod(str(etc_stage), 0o750)


class BackupRestore(object):
    def __init__(self, layout=None, service=None, owner_normalizer=None):
        self.layout = layout or Layout()
        self.service = service or SystemdService(self.layout)
        self.owner_normalizer = owner_normalizer or _normalize_ownership

    def _require_root(self):
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise BackupError("Execute como root.")

    def _create_snapshot(self, prefix):
        _validate_source(self.layout)
        return create_archive(self.layout, self.layout.backups, prefix=prefix)

    def backup(self):
        self._require_root()
        maintenance_state = self.service.pause_maintenance()
        was_active = False
        stopped = False
        archive_result = None
        failure = None
        try:
            was_active = self.service.active()
            if was_active:
                stopped = True
                self.service.stop()
                archive_result = self._create_snapshot("spfbl")
        except Exception as exc:
            failure = exc
        finally:
            restart_error = None
            if was_active and stopped:
                try:
                    if not self.service.active():
                        self.service.start()
                    self.service.wait_ready()
                except Exception as exc:
                    restart_error = exc
            try:
                self.service.resume_maintenance(maintenance_state)
            except Exception as exc:
                if restart_error is None:
                    restart_error = exc
            if restart_error is not None:
                raise BackupError("Backup={0}; reinício do core/timer falhou: {1}".format(
                    "concluído" if archive_result else "não concluído", restart_error))
        if failure is not None:
            raise failure
        return archive_result

    def verify(self, archive_path):
        return inspect_archive(archive_path, expected_version=self.layout.core_version())

    def restore(self, archive_path, confirm=False, dry_run=False):
        self._require_root()
        inspected = self.verify(archive_path)
        manifest = inspected["manifest"]
        if dry_run:
            return {"dry_run": True, "verification": inspected}
        if not confirm:
            raise BackupError("Restore exige confirmação explícita: informe --yes")
        for name, path in (("configuração", self.layout.etc), ("estado", self.layout.state)):
            if path.is_symlink() or not path.is_dir():
                raise BackupError("Diretório de {0} ausente ou não é diretório real: {1}".format(name, path))

        maintenance_state = self.service.pause_maintenance()
        was_active = False
        stopped = False
        swaps = []
        stages = []
        extracted = None
        safety_archive = None
        try:
            was_active = self.service.active()
            if was_active:
                stopped = True
                self.service.stop()
            safety_archive, _, _ = self._create_snapshot("pre-restore")
            temp_root = Path(tempfile.mkdtemp(prefix="had-antispam-restore-", dir=str(self.layout.backups)))
            extracted = temp_root / "payload"
            _extract_verified(archive_path, extracted, manifest)
            restored_etc = extracted / "etc" / "spamfox"
            if not restored_etc.is_dir():
                restored_etc = extracted / "etc" / "had-antispam"
            restored_state = extracted / "var" / "lib" / "had-antispam"
            if not restored_etc.is_dir() or not restored_state.is_dir() \
                    or not (restored_state / "data" / "server.key").is_file() \
                    or not (restored_state / "history").is_dir():
                raise BackupError("Estrutura restaurada não contém config, chave, data e history")

            replacements = ((self.layout.etc, restored_etc), (self.layout.state, restored_state))
            for target, source in replacements:
                stage = Path(tempfile.mkdtemp(prefix=".had-antispam-stage-", dir=str(target.parent)))
                stages.append(stage)
                for child in source.iterdir():
                    destination = stage / child.name
                    if child.is_dir():
                        shutil.copytree(str(child), str(destination), copy_function=shutil.copy2)
                    else:
                        shutil.copy2(str(child), str(destination))
            etc_stage, state_stage = stages[0], stages[1]
            # The normalizer needs both roots at once; re-run after staging both.
            self.owner_normalizer(etc_stage, state_stage)

            token = uuid.uuid4().hex
            for target, stage in ((self.layout.etc, etc_stage), (self.layout.state, state_stage)):
                old = target.parent / ("." + target.name + ".had-antispam-old-" + token)
                os.replace(str(target), str(old))
                swaps.append((target, old))
                os.replace(str(stage), str(target))
            if was_active:
                self.service.start()
                self.service.wait_ready()
            for _, old in swaps:
                shutil.rmtree(str(old), ignore_errors=True)
            return {"dry_run": False, "verification": inspected, "safety_archive": str(safety_archive)}
        except Exception as original:
            rollback_error = None
            try:
                if swaps:
                    if self.service.active():
                        self.service.stop()
                    for target, old in reversed(swaps):
                        if target.exists():
                            shutil.rmtree(str(target))
                        if old.exists():
                            os.replace(str(old), str(target))
                if was_active and stopped and not self.service.active():
                    self.service.start()
                    self.service.wait_ready()
            except Exception as exc:
                rollback_error = exc
            if rollback_error is not None:
                raise BackupError("Restore falhou ({0}); rollback também falhou ({1}). Snapshot preservado em {2}".format(
                    original, rollback_error, safety_archive or "não criado"))
            raise
        finally:
            for stage in stages:
                if stage.exists():
                    shutil.rmtree(str(stage), ignore_errors=True)
            if extracted is not None:
                temp_root = extracted.parent
                if temp_root.exists():
                    shutil.rmtree(str(temp_root), ignore_errors=True)
            self.service.resume_maintenance(maintenance_state)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Backup/restore consistente do core SPFBL nativo HAD")
    commands = parser.add_subparsers(dest="command")
    backup_parser = commands.add_parser("backup", help="grava estado e cria backup consistente")
    backup_parser.add_argument("--output-dir", default=str(BACKUPS), help="diretório privado (padrão: %(default)s)")
    restore_parser = commands.add_parser("restore", help="valida e restaura um backup da mesma release")
    restore_parser.add_argument("archive", help="arquivo .tar.gz acompanhado de .tar.gz.sha256")
    restore_parser.add_argument("--dry-run", action="store_true", help="verifica sem alterar serviço ou arquivos")
    restore_parser.add_argument("--yes", action="store_true", help="confirma substituição após criar snapshot de segurança")
    verify_parser = commands.add_parser("verify", help="valida checksum, manifesto, caminhos e release")
    verify_parser.add_argument("archive")
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help(sys.stderr)
        return 2
    manager = BackupRestore()
    try:
        if args.command == "backup":
            manager.layout.backups = Path(args.output_dir)
            archive, digest, manifest = manager.backup()
            print("Backup consistente criado: {0}".format(archive))
            print("SHA-256: {0}".format(digest))
            print("Release: {0}; arquivos: {1}".format(manifest["source_version"], len(manifest["files"])))
            return 0
        if args.command == "verify":
            result = manager.verify(args.archive)
            manifest = result["manifest"]
            print("Backup válido: {0}".format(result["archive"]))
            print("Release: {0}; arquivos: {1}; SHA-256: {2}".format(
                manifest["source_version"], len(manifest["files"]), result["sha256"]))
            return 0
        result = manager.restore(args.archive, confirm=args.yes, dry_run=args.dry_run)
        if args.dry_run:
            manifest = result["verification"]["manifest"]
            print("DRY-RUN PASS: release {0}, {1} arquivos, SHA-256 {2}".format(
                manifest["source_version"], len(manifest["files"]), result["verification"]["sha256"]))
        else:
            print("Restore concluído. Snapshot do estado anterior: {0}".format(result["safety_archive"]))
        return 0
    except (BackupError, OSError, subprocess.SubprocessError, tarfile.TarError) as exc:
        print("HAD AntiSpam backup/restore: {0}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
