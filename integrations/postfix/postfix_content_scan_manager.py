#!/usr/bin/env python3
"""Transactional installer for the Postfix after-queue Rspamd MONITOR path."""

from __future__ import print_function

import argparse
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

SERVICE_USER = "had-content-scan"
SERVICE = "had-content-scan"
CONTENT_FILTER = "had-content-scan:dummy"
BEGIN = b"# BEGIN HAD-CONTENT-SCAN TRANSPORT"
END = b"# END HAD-CONTENT-SCAN TRANSPORT"
STATE = "/var/lib/had-content-scan/postfix-install/current"
ARCHIVE = "/var/lib/had-content-scan/postfix-install/archive"
LOCK = "/run/lock/had-content-scan-postfix-installer.lock"
CONFIG_BASE = "/etc/had-content-scan"
CONFIG_DIR = "/etc/had-content-scan/postfix"
CONFIG = "/etc/had-content-scan/postfix/client.json"
UPLOAD_BASE = "/var/lib/had-content-scan"
UPLOAD_DIR = "/var/lib/had-content-scan/postfix"
UPLOAD_LOCK = "/var/lib/had-content-scan/postfix/upload.lock"
UPLOAD_LOCK_SECONDARY = UPLOAD_LOCK + ".1"
LIB_DIR = "/usr/local/libexec/had-antispam"
FILTER = "/usr/local/libexec/had-antispam/postfix_content_filter.py"
SCAN_CLIENT = "/usr/local/libexec/had-antispam/scan_client.py"
ENDPOINT = "https://matrix.hadcloud.srv.br/internal/sfox/scan"
CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{40,256}$")
SERVICE_BLOCK = (
    BEGIN + b"\n"
    b"had-content-scan unix - n n - 2 pipe\n"
    b"  -o pipe_destination_recipient_limit=1\n"
    b"  flags=q user=had-content-scan null_sender=\n"
    b"  argv=/usr/bin/python3 /usr/local/libexec/had-antispam/postfix_content_filter.py --sender=${sender} --recipient=${recipient} --queue-id=${queue_id} --config="
    + CONFIG.encode("ascii") + b" --lock=" + UPLOAD_LOCK.encode("ascii") + b"\n"
    + END + b"\n"
)
SMTP_OVERRIDE = b"  -o content_filter=had-content-scan:dummy\n"


class ContentScanManagerError(RuntimeError):
    pass


class Paths(object):
    def __init__(self, root="/"):
        self.root = os.path.abspath(root)
        self.main = self.path("/etc/postfix/main.cf")
        self.master = self.path("/etc/postfix/master.cf")
        self.postfix = self.path("/usr/sbin/postfix")
        self.postconf = self.path("/usr/sbin/postconf")
        self.python = self.path("/usr/bin/python3")
        self.state = self.path(STATE)
        self.archive = self.path(ARCHIVE)
        self.lock = self.path(LOCK)
        self.config_base = self.path(CONFIG_BASE)
        self.config_dir = self.path(CONFIG_DIR)
        self.config = self.path(CONFIG)
        self.upload_lock = self.path(UPLOAD_LOCK)
        self.upload_lock_secondary = self.path(UPLOAD_LOCK_SECONDARY)
        self.upload_base = self.path(UPLOAD_BASE)
        self.upload_dir = self.path(UPLOAD_DIR)
        self.lib_dir = self.path(LIB_DIR)
        self.filter = self.path(FILTER)
        self.scan_client = self.path(SCAN_CLIENT)
        here = os.path.dirname(os.path.abspath(__file__))
        self.source_filter = os.path.join(here, "postfix_content_filter.py")
        self.source_scan_client = os.path.join(here, "..", "content_scan", "scan_client.py")

    def path(self, value):
        if self.root == os.path.abspath(os.sep):
            return value
        return os.path.join(self.root, value.lstrip("/"))


def _read(path):
    if not os.path.exists(path):
        return None
    if not os.path.isfile(path) or os.path.islink(path):
        raise ContentScanManagerError("Recusando arquivo ausente, não regular ou symlink: " + path)
    with open(path, "rb") as stream:
        return stream.read()


def _metadata(path):
    if not os.path.exists(path):
        return None
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise ContentScanManagerError("Recusando caminho que não seja arquivo regular: " + path)
    return {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path, data, metadata=None):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    fd, temporary = tempfile.mkstemp(prefix=".had-content-scan-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if metadata:
            os.chmod(temporary, metadata["mode"])
            if os.geteuid() == 0:
                os.chown(temporary, metadata["uid"], metadata["gid"])
        else:
            os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _atomic_install(source, destination, mode, uid=0, gid=0):
    with open(source, "rb") as stream:
        data = stream.read()
    _atomic_write(destination, data, {"mode": mode, "uid": uid, "gid": gid})


def _top_level(lines):
    """Yield (index, parsed service fields) for master.cf declarations."""
    for index, line in enumerate(lines):
        if not line or line[:1] in (b" ", b"\t", b"#"):
            continue
        fields = line.split()
        if len(fields) >= 8:
            yield index, fields


def _smtp_service_span(lines):
    matches = []
    for index, fields in _top_level(lines):
        service = fields[0].rsplit(b":", 1)[-1]
        if service == b"smtp" and fields[1] == b"inet" and fields[7] == b"smtpd":
            end = len(lines)
            for next_index, _ in _top_level(lines):
                if next_index > index:
                    end = next_index
                    break
            matches.append((index, end))
    if len(matches) != 1:
        raise ContentScanManagerError(
            "Esperava exatamente um serviço smtp/inet/smtpd em master.cf; encontrados {0}".format(
                len(matches)))
    return matches[0]


def _managed_transport_span(data):
    starts = []
    ends = []
    offset = 0
    while True:
        pos = data.find(BEGIN, offset)
        if pos < 0:
            break
        starts.append(pos)
        offset = pos + len(BEGIN)
    offset = 0
    while True:
        pos = data.find(END, offset)
        if pos < 0:
            break
        ends.append(pos)
        offset = pos + len(END)
    if not starts and not ends:
        return None
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ContentScanManagerError("Marcadores do transporte de conteúdo ausentes ou divergentes")
    start = data.rfind(b"\n", 0, starts[0]) + 1
    end = data.find(b"\n", ends[0])
    return start, len(data) if end < 0 else end + 1


def transform_master_cf(data):
    """Add only an inbound SMTP service override and one managed pipe transport."""
    span = _managed_transport_span(data)
    if span:
        start, end = span
        if data[start:end] != SERVICE_BLOCK:
            raise ContentScanManagerError("Transporte HAD existente diverge do pacote")
        lines = data.splitlines(keepends=True)
        smtp_start, smtp_end = _smtp_service_span(lines)
        block = b"".join(lines[smtp_start:smtp_end])
        if block.count(SMTP_OVERRIDE) != 1:
            raise ContentScanManagerError("Override SMTP HAD ausente ou duplicado")
        return data, False

    lines = data.splitlines(keepends=True)
    if not lines and data:
        lines = [data]
    smtp_start, smtp_end = _smtp_service_span(lines)
    smtp_lines = lines[smtp_start:smtp_end]
    if any(b"content_filter" in line for line in smtp_lines):
        raise ContentScanManagerError("O serviço smtp já possui um override content_filter; preservei a configuração")
    if b"had-content-scan unix" in data:
        raise ContentScanManagerError("Serviço had-content-scan já existe fora dos marcadores gerenciados")

    # Put the setting first in the service block, before any existing per-service
    # overrides. No existing content_filter is replaced or shadowed.
    lines.insert(smtp_start + 1, SMTP_OVERRIDE)
    updated = b"".join(lines)
    if updated and not updated.endswith(b"\n"):
        updated += b"\n"
    if updated and not updated.endswith(b"\n\n"):
        updated += b"\n"
    updated += SERVICE_BLOCK
    return updated, True


def config_bytes(client_id, token):
    parsed = scan_client_url(ENDPOINT)
    if parsed != ENDPOINT:
        raise ContentScanManagerError("Endpoint local inválido")
    if not CLIENT_ID_RE.match(client_id or ""):
        raise ContentScanManagerError("client-id inválido")
    if not TOKEN_RE.match(token):
        raise ContentScanManagerError("Token deve ter de 40 a 256 caracteres base64url")
    value = {"endpoint": ENDPOINT, "client_id": client_id, "token": token,
             "max_bytes": 25 * 1024 * 1024, "timeout_seconds": 20}
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def scan_client_url(value):
    from urllib.parse import urlsplit
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.hostname != "matrix.hadcloud.srv.br" or \
            parsed.path != "/internal/sfox/scan" or parsed.query or parsed.fragment:
        return ""
    return value


def run_command(command, timeout=30):
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = process.communicate(timeout=timeout)[0]
    except (OSError, subprocess.TimeoutExpired) as exc:
        if "process" in locals():
            try:
                process.kill()
            except Exception:
                pass
        raise ContentScanManagerError("Falha ao executar {0}: {1}".format(command[0], exc))
    decoded = output.decode("utf-8", "replace")
    if process.returncode != 0:
        raise ContentScanManagerError("Comando falhou ({0}): {1}\n{2}".format(
            process.returncode, " ".join(command), decoded[-3000:]))
    return decoded


def _check_root(paths):
    if os.geteuid() != 0:
        raise ContentScanManagerError("Execute como root")
    for path in (paths.postfix, paths.postconf, paths.python, paths.main, paths.master):
        if not os.path.exists(path):
            raise ContentScanManagerError("Postfix/arquivo não encontrado: " + path)
    for path in (paths.source_filter, paths.source_scan_client):
        if not os.path.isfile(path):
            raise ContentScanManagerError("Arquivo do pacote ausente: " + path)


def _version(paths, runner):
    output = runner([paths.postconf, "mail_version"])
    try:
        version = output.strip().split("=", 1)[1].strip()
        parts = tuple(int(part) for part in version.split(".")[:2])
    except (IndexError, ValueError):
        raise ContentScanManagerError("Não foi possível ler a versão do Postfix")
    if parts < (3, 0):
        raise ContentScanManagerError("A integração requer Postfix 3.0 ou superior")
    return version


def _assert_no_global_filter(paths, runner):
    output = runner([paths.postconf, "-h", "content_filter"])
    # postconf also writes warnings about unrelated master.cf parameter
    # overrides to stderr. run_command combines stderr and stdout, so remove
    # only those diagnostics before checking the actual parameter value.
    value = "\n".join(
        line for line in output.splitlines()
        if not re.match(r"^(?:\S*/)?postconf: warning:", line, re.IGNORECASE)
    ).strip()
    if value:
        raise ContentScanManagerError(
            "main.cf já define content_filter={0}; a integração precisa ser encadeada pelo administrador".format(value))


def _postfix_check(paths, runner):
    output = runner([paths.postfix, "check"])
    if "fatal" in output.lower() or "error" in output.lower():
        raise ContentScanManagerError("postfix check reportou erro:\n" + output[-3000:])
    return output


def validate(paths=None, runner=run_command, preflight=True):
    paths = paths or Paths()
    if preflight:
        _check_root(paths)
    version = _version(paths, runner)
    _assert_no_global_filter(paths, runner)
    master = _read(paths.master)
    if master is None:
        raise ContentScanManagerError("master.cf ausente")
    transform_master_cf(master)
    return "Postfix {0}: candidato de captura after-queue validado; nenhum arquivo alterado".format(version)


def _service_identity(runner=run_command):
    import pwd
    try:
        account = pwd.getpwnam(SERVICE_USER)
        if account.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
            raise ContentScanManagerError("A conta had-content-scan já existe com shell de login; preservada")
        return account.pw_uid, account.pw_gid, False
    except KeyError:
        nologin = "/usr/sbin/nologin" if os.path.exists("/usr/sbin/nologin") else "/sbin/nologin"
        useradd = shutil.which("useradd") or "/usr/sbin/useradd"
        runner([useradd, "--system", "--user-group", "--no-create-home",
                "--home-dir", "/var/empty/had-content-scan", "--shell", nologin,
                SERVICE_USER])
        account = pwd.getpwnam(SERVICE_USER)
        return account.pw_uid, account.pw_gid, True


def _save_snapshot(paths, files, directories):
    if os.path.exists(paths.state):
        raise ContentScanManagerError("Snapshot anterior existe; use healthcheck/uninstall antes")
    os.makedirs(paths.state, mode=0o700)
    os.chmod(paths.state, 0o700)
    manifest = {"schema": 1, "created": int(time.time()), "status": "installing",
                "files": {}, "directories": directories, "created_service_user": False}
    for name, (path, data, meta) in files.items():
        manifest["files"][name] = {"path": path, "existed": data is not None,
                                   "sha256": _sha(data) if data is not None else None,
                                   "metadata": meta}
        if data is not None:
            _atomic_write(os.path.join(paths.state, name + ".original"), data,
                          {"mode": 0o600, "uid": 0, "gid": 0})
    _write_manifest(paths, manifest)
    return manifest


def _write_manifest(paths, manifest):
    data = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    _atomic_write(os.path.join(paths.state, "manifest.json"), data,
                  {"mode": 0o600, "uid": 0, "gid": 0})


def _load_manifest(paths):
    path = os.path.join(paths.state, "manifest.json")
    if not os.path.isfile(path):
        raise ContentScanManagerError("Snapshot/manifest ausente; não alterei arquivos")
    with open(path, "r") as stream:
        return json.load(stream)


def _original(paths, name, item):
    if not item["existed"]:
        return None
    with open(os.path.join(paths.state, name + ".original"), "rb") as stream:
        data = stream.read()
    if _sha(data) != item["sha256"]:
        raise ContentScanManagerError("Snapshot corrompido: " + name)
    return data


def _restore_files(paths, manifest):
    for name, item in manifest["files"].items():
        original = _original(paths, name, item)
        if original is None:
            try:
                os.unlink(item["path"])
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
        else:
            _atomic_write(item["path"], original, item.get("metadata"))


def _remove_created_directories(manifest):
    for directory, existed in reversed(list(manifest.get("directories", {}).items())):
        if not existed:
            try:
                os.rmdir(directory)
            except OSError:
                pass


def _assert_clean_targets(paths):
    for path in (paths.config, paths.filter, paths.scan_client, paths.upload_lock,
                 paths.upload_lock_secondary):
        if os.path.lexists(path):
            raise ContentScanManagerError("Arquivo-alvo já existe e foi preservado: " + path)
    if os.path.lexists(paths.state):
        raise ContentScanManagerError("Snapshot anterior existe; revise antes")
    for directory in (paths.config_dir, paths.lib_dir, os.path.dirname(paths.upload_lock)):
        if os.path.lexists(directory) and (not os.path.isdir(directory) or os.path.islink(directory)):
            raise ContentScanManagerError("Diretório-alvo inseguro; preservado: " + directory)


def install(client_id, token_file, paths=None, runner=run_command,
            reload_postfix=False, preflight=True):
    paths = paths or Paths()
    if preflight:
        _check_root(paths)
    _version(paths, runner)
    _assert_no_global_filter(paths, runner)
    _assert_clean_targets(paths)
    if not token_file or not os.path.isfile(token_file) or os.path.islink(token_file):
        raise ContentScanManagerError("--token-file deve apontar para arquivo regular")
    token_info = os.stat(token_file, follow_symlinks=False)
    if token_info.st_uid != 0 or (stat.S_IMODE(token_info.st_mode) & 0o077):
        raise ContentScanManagerError("Token precisa ser root-owned, modo 0600 ou mais restrito")
    with open(token_file, "r") as stream:
        token = stream.read().strip()
    candidate_config = config_bytes(client_id, token)
    master_original = _read(paths.master)
    candidate_master, changed = transform_master_cf(master_original)
    if not changed:
        raise ContentScanManagerError("Integração já configurada sem snapshot; não alterei nada")

    directory_paths = (paths.config_base, paths.config_dir, paths.lib_dir,
                       paths.upload_base, paths.upload_dir, os.path.dirname(paths.state))
    directories = {path: os.path.isdir(path) for path in directory_paths}
    files = {
        "master": (paths.master, master_original, _metadata(paths.master)),
        "config": (paths.config, _read(paths.config), _metadata(paths.config)),
        "filter": (paths.filter, _read(paths.filter), _metadata(paths.filter)),
        "scan_client": (paths.scan_client, _read(paths.scan_client), _metadata(paths.scan_client)),
        "upload_lock": (paths.upload_lock, _read(paths.upload_lock), _metadata(paths.upload_lock)),
        "upload_lock_secondary": (paths.upload_lock_secondary,
                                  _read(paths.upload_lock_secondary),
                                  _metadata(paths.upload_lock_secondary)),
    }
    manifest = _save_snapshot(paths, files, directories)
    service_user_created = False
    reload_attempted = False
    try:
        uid, gid, service_user_created = _service_identity(runner)
        manifest["created_service_user"] = service_user_created
        _write_manifest(paths, manifest)
        for path, mode in ((paths.config_base, 0o755), (paths.config_dir, 0o750),
                           (paths.lib_dir, 0o755), (paths.upload_base, 0o755),
                           (paths.upload_dir, 0o750)):
            if not os.path.isdir(path):
                os.makedirs(path, mode=mode, exist_ok=True)
                os.chmod(path, mode)
                os.chown(path, 0, gid if path in (paths.config_dir, paths.upload_dir) else 0)
            else:
                info = os.stat(path, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or \
                        stat.S_IMODE(info.st_mode) & 0o022:
                    raise ContentScanManagerError("Diretório inseguro ou gravável por não-root; preservado: " + path)
                if path in (paths.config_dir, paths.upload_dir) and info.st_gid != gid:
                    raise ContentScanManagerError("Diretório existente não pertence ao grupo do filtro; preservado: " + path)
                if path in (paths.config_dir, paths.upload_dir) and not (stat.S_IMODE(info.st_mode) & 0o010):
                    raise ContentScanManagerError("Usuário do filtro não consegue atravessar diretório existente: " + path)
        os.makedirs(os.path.dirname(paths.state), mode=0o700, exist_ok=True)
        _atomic_install(paths.source_filter, paths.filter, 0o755)
        _atomic_install(paths.source_scan_client, paths.scan_client, 0o644)
        _atomic_write(paths.config, candidate_config, {"mode": 0o640, "uid": 0, "gid": gid})
        _atomic_write(paths.upload_lock, b"", {"mode": 0o600, "uid": uid, "gid": gid})
        _atomic_write(paths.upload_lock_secondary, b"",
                      {"mode": 0o600, "uid": uid, "gid": gid})
        _atomic_write(paths.master, candidate_master, _metadata(paths.master))
        _postfix_check(paths, runner)

        manifest["status"] = "installed"
        manifest["client_id"] = client_id
        manifest["reload_pending"] = not reload_postfix
        for name, item in manifest["files"].items():
            current = _read(item["path"])
            item["installed_sha256"] = _sha(current) if current is not None else None
        _write_manifest(paths, manifest)
        if reload_postfix:
            reload_attempted = True
            runner([paths.postfix, "reload"])
            manifest["reload_pending"] = False
            _write_manifest(paths, manifest)
        return "installed; Postfix after-queue MONITOR; reload {0}".format(
            "executado" if reload_postfix else "pendente")
    except Exception as exc:
        try:
            _restore_files(paths, manifest)
            if reload_attempted:
                runner([paths.postfix, "reload"])
            shutil.rmtree(paths.state)
            _remove_created_directories(manifest)
            if service_user_created:
                runner([shutil.which("userdel") or "/usr/sbin/userdel", SERVICE_USER])
        except Exception as rollback_exc:
            raise ContentScanManagerError(
                "Instalação falhou ({0}); rollback incompleto ({1}); snapshot preservado em {2}".format(
                    exc, rollback_exc, paths.state))
        raise ContentScanManagerError("Instalação cancelada e revertida: " + str(exc))


def activate(paths=None, runner=run_command, preflight=True):
    paths = paths or Paths()
    if preflight:
        _check_root(paths)
    manifest = _load_manifest(paths)
    if manifest.get("status") != "installed":
        raise ContentScanManagerError("Não existe instalação completa para ativar")
    if manifest.get("reload_pending") is False:
        return "Postfix já está recarregado com o transporte after-queue HAD"
    _assert_no_global_filter(paths, runner)
    for name, item in manifest["files"].items():
        current = _read(item["path"])
        if (_sha(current) if current is not None else None) != item.get("installed_sha256"):
            raise ContentScanManagerError("Arquivo {0} mudou após a instalação; não recarreguei".format(item["path"]))
    _postfix_check(paths, runner)
    runner([paths.postfix, "reload"])
    manifest["reload_pending"] = False
    _write_manifest(paths, manifest)
    return "Postfix recarregado; captura de conteúdo MONITOR ativa somente no serviço SMTP"


def healthcheck(paths=None, runner=run_command, preflight=True):
    paths = paths or Paths()
    if preflight:
        _check_root(paths)
    manifest = _load_manifest(paths)
    if manifest.get("status") != "installed":
        raise ContentScanManagerError("Snapshot não representa uma instalação concluída")
    _assert_no_global_filter(paths, runner)
    _postfix_check(paths, runner)
    master = _read(paths.master) or b""
    updated, changed = transform_master_cf(master)
    if changed:
        raise ContentScanManagerError("master.cf não contém a captura HAD de conteúdo esperada")
    for name, item in manifest["files"].items():
        current = _read(item["path"])
        if (_sha(current) if current is not None else None) != item.get("installed_sha256"):
            raise ContentScanManagerError("Arquivo gerenciado mudou: " + item["path"])
    return "Postfix válido; filtro Rspamd after-queue em MONITOR; conteúdo não controla entrega"


def uninstall(paths=None, runner=run_command, requeue_all=False,
              reload_postfix=False, preflight=True):
    paths = paths or Paths()
    if preflight:
        _check_root(paths)
    if not (requeue_all and reload_postfix):
        raise ContentScanManagerError(
            "Para remover, informe --reload --requeue-all: Postfix registra o transporte no queue ID; "
            "o requeue limpa pedidos do filtro existentes")
    manifest = _load_manifest(paths)
    if manifest.get("status") != "installed":
        raise ContentScanManagerError("Snapshot não representa uma instalação concluída")
    current_files = {}
    current_meta = {}
    for name, item in manifest["files"].items():
        data = _read(item["path"])
        if (_sha(data) if data is not None else None) != item.get("installed_sha256"):
            raise ContentScanManagerError("Arquivo {0} mudou após instalação; rollback preservado".format(item["path"]))
        current_files[name] = data
        current_meta[name] = _metadata(item["path"])
    try:
        _restore_files(paths, manifest)
        _postfix_check(paths, runner)
        runner([paths.postfix, "reload"])
        runner([paths.path("/usr/sbin/postsuper"), "-r", "ALL"])
        manifest["status"] = "removed"
        _write_manifest(paths, manifest)
        os.makedirs(paths.archive, mode=0o700, exist_ok=True)
        archive_name = "install-{0}-{1}".format(int(time.time() * 1000), os.getpid())
        os.replace(paths.state, os.path.join(paths.archive, archive_name))
        return "removed; queue re-enfileirada para remover referências ao filtro"
    except Exception as exc:
        try:
            for name, item in manifest["files"].items():
                data = current_files[name]
                if data is not None:
                    _atomic_write(item["path"], data, current_meta[name])
                else:
                    try:
                        os.unlink(item["path"])
                    except OSError as restore_exc:
                        if restore_exc.errno != errno.ENOENT:
                            raise
            _postfix_check(paths, runner)
            runner([paths.postfix, "reload"])
        except Exception as rollback_exc:
            raise ContentScanManagerError(
                "Remoção falhou ({0}); restauração falhou ({1}); snapshot preservado em {2}".format(
                    exc, rollback_exc, paths.state))
        raise ContentScanManagerError("Remoção cancelada; instalação foi recomposta: " + str(exc))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "install", "activate", "healthcheck", "uninstall"))
    parser.add_argument("--client-id")
    parser.add_argument("--token-file")
    parser.add_argument("--reload", action="store_true")
    parser.add_argument("--requeue-all", action="store_true")
    args = parser.parse_args(argv)
    paths = Paths()
    try:
        if args.command == "validate":
            print(validate(paths))
        elif args.command == "install":
            if not args.client_id or not args.token_file:
                raise ContentScanManagerError("install requer --client-id e --token-file")
            print(install(args.client_id, args.token_file, paths, reload_postfix=args.reload))
        elif args.command == "activate":
            print(activate(paths))
        elif args.command == "healthcheck":
            print(healthcheck(paths))
        else:
            print(uninstall(paths, requeue_all=args.requeue_all,
                            reload_postfix=args.reload))
        return 0
    except ContentScanManagerError as exc:
        print("HAD Postfix content scan: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
