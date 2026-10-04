#!/usr/bin/env python3
"""Transactional, MONITOR-only Postfix integration for the HAD SPFBL client."""

from __future__ import print_function

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time


BEGIN = b"# BEGIN HAD-ANTISPAM-MONITOR"
END = b"# END HAD-ANTISPAM-MONITOR"
POLICY_SERVICE = "check_policy_service { unix:private/had-antispam-policy, timeout=1s, default_action=DUNNO, request_limit=1 }"
STATE = "/var/lib/had-antispam/postfix/current"
ARCHIVE = "/var/lib/had-antispam/postfix/archive"
LOCK = "/run/lock/had-antispam-postfix.lock"
MAIN_CF = "/etc/postfix/main.cf"
MASTER_CF = "/etc/postfix/master.cf"
CLIENT_CONF = "/etc/had-antispam/client.conf"
LIB_DIR = "/usr/local/libexec/had-antispam"
CLIENT_NAME = "spfbl_client.py"
POLICY_NAME = "postfix_policy.py"
MASTER_BLOCK = (
    BEGIN + b"\n"
    b"had-antispam-policy unix - n n - 16 spawn\n"
    b"  user=nobody argv=/usr/bin/python3 /usr/local/libexec/had-antispam/postfix_policy.py --config /etc/had-antispam/client.conf\n"
    + END + b"\n"
)


class ManagerError(RuntimeError):
    pass


def effective_uid():
    return os.geteuid() if hasattr(os, "geteuid") else -1


class Paths(object):
    def __init__(self, root="/"):
        self.root = os.path.abspath(root)
        self.main = self.path(MAIN_CF)
        self.master = self.path(MASTER_CF)
        self.client_conf = self.path(CLIENT_CONF)
        self.lib_dir = self.path(LIB_DIR)
        self.client = os.path.join(self.lib_dir, CLIENT_NAME)
        self.policy = os.path.join(self.lib_dir, POLICY_NAME)
        self.state = self.path(STATE)
        self.archive = self.path(ARCHIVE)
        self.lock = self.path(LOCK)
        self.postfix = self.path("/usr/sbin/postfix")
        self.postconf = self.path("/usr/sbin/postconf")
        self.python = self.path("/usr/bin/python3")
        here = os.path.dirname(os.path.abspath(__file__))
        self.source_client = os.path.join(here, "..", "common", "spfbl_client.py")
        self.source_policy = os.path.join(here, POLICY_NAME)

    def path(self, value):
        if self.root == os.path.abspath(os.sep):
            return value
        return os.path.join(self.root, value.lstrip("/"))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_optional(path):
    if not os.path.exists(path):
        return None
    if not os.path.isfile(path) or os.path.islink(path):
        raise ManagerError("Recusando caminho que não seja arquivo regular: " + path)
    with open(path, "rb") as stream:
        return stream.read()


def metadata(path):
    if not os.path.exists(path):
        return None
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise ManagerError("Recusando caminho que não seja arquivo regular: " + path)
    return {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}


def atomic_write(path, data, meta=None):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    fd, temporary = tempfile.mkstemp(prefix=".had-antispam-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, meta["mode"] if meta else 0o644)
        if meta and effective_uid() == 0 and hasattr(os, "chown"):
            os.chown(temporary, meta["uid"], meta["gid"])
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def restore(path, data, meta):
    if data is None:
        try:
            os.unlink(path)
        except OSError as exc:
            if exc.errno != 2:
                raise
    else:
        atomic_write(path, data, meta)


def run_command(command, timeout=30, input_data=None):
    process = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        output = process.communicate(input_data, timeout=timeout)[0]
    except (OSError, subprocess.TimeoutExpired) as exc:
        if process is not None:
            try:
                process.kill()
            except Exception:
                pass
        raise ManagerError("Falha ao executar {0}: {1}".format(command[0], exc))
    decoded = output.decode("utf-8", "replace")
    if process.returncode != 0:
        raise ManagerError("Comando falhou ({0}): {1}\n{2}".format(
            process.returncode, " ".join(command), decoded[-4000:]))
    return decoded


@contextlib.contextmanager
def exclusive_lock(path):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "a+b") as stream:
        if os.name == "nt":
            import msvcrt
            stream.seek(0)
            if not stream.read(1):
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _top_level_items(value):
    """Split a Postfix restriction list at commas outside nested expressions."""
    items = []
    start = 0
    braces = 0
    parentheses = 0
    for index, char in enumerate(value):
        if char == "{":
            braces += 1
        elif char == "}":
            braces -= 1
        elif char == "(":
            parentheses += 1
        elif char == ")":
            parentheses -= 1
        elif char == "," and braces == 0 and parentheses == 0:
            item = value[start:index].strip()
            if item:
                items.append(item)
            start = index + 1
        if braces < 0 or parentheses < 0:
            raise ManagerError("Lista de restrições Postfix malformada")
    if braces or parentheses:
        raise ManagerError("Lista de restrições Postfix malformada")
    tail = value[start:].strip()
    if tail:
        items.append(tail)
    return items


def _has_relay_guard(value):
    if not value:
        return False
    return any(
        item in ("reject_unauth_destination", "defer_unauth_destination")
        for item in _top_level_items(value)
    )


def add_policy_restriction(value, relay_value=None):
    items = _top_level_items(value)
    if any(item == POLICY_SERVICE for item in items):
        return value, False
    # Keep all existing ordering. The check runs directly after relay protection,
    # before a trailing permit; Postfix 3+ also enforces smtpd_relay_restrictions.
    safe_indexes = [
        index for index, item in enumerate(items)
        if item in ("reject_unauth_destination", "defer_unauth_destination")
    ]
    if safe_indexes:
        insertion = safe_indexes[-1] + 1
    elif _has_relay_guard(relay_value):
        # Postfix 2.10+ can keep relay protection in smtpd_relay_restrictions.
        # Evaluate the HAD policy before a final explicit permit, if present.
        insertion = len(items) - 1 if items and items[-1] == "permit" else len(items)
    else:
        raise ManagerError(
            "Não encontrei proteção reject_unauth_destination/defer_unauth_destination "
            "em smtpd_recipient_restrictions ou smtpd_relay_restrictions"
        )
    items.insert(insertion, POLICY_SERVICE)
    return ", ".join(items), True


def spans(data):
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
        raise ManagerError("Marcadores HAD ausentes, duplicados ou fora de ordem")
    start = data.rfind(b"\n", 0, starts[0]) + 1
    end = data.find(b"\n", ends[0])
    return start, len(data) if end < 0 else end + 1


def append_master_block(data):
    span = spans(data)
    if span:
        start, end = span
        current = data[start:end]
        if current == MASTER_BLOCK:
            return data, False
        raise ManagerError("Bloco de serviço HAD existente diverge do pacote")
    if data and not data.endswith(b"\n"):
        data += b"\n"
    return data + (b"\n" if data and not data.endswith(b"\n\n") else b"") + MASTER_BLOCK, True


def validate_restriction_value(value, relay_value=None):
    if not value:
        raise ManagerError("smtpd_recipient_restrictions está vazio")
    items = _top_level_items(value)
    if not any(item == POLICY_SERVICE for item in items):
        raise ManagerError("check_policy_service HAD não consta em smtpd_recipient_restrictions")
    if not any(item in ("reject_unauth_destination", "defer_unauth_destination") for item in items) and not _has_relay_guard(relay_value):
        raise ManagerError("Proteção de relay ausente da lista de destinatários")


def config_bytes(server, port):
    return (
        "# HAD AntiSpam Postfix integration; MONITOR only\n"
        "SERVER={0}\nPORT={1}\nFAIL_OPEN=true\nMONITOR_MODE=true\n".format(server, port)
    ).encode("ascii")


def _snapshot(paths, originals):
    if os.path.exists(paths.state):
        raise ManagerError("Snapshot anterior existe; consulte healthcheck/uninstall antes de instalar")
    os.makedirs(paths.state, mode=0o700)
    os.chmod(paths.state, 0o700)
    manifest = {
        "schema": 1,
        "created": int(time.time()),
        "status": "installing",
        "files": {},
        "directories": {
            paths.lib_dir: os.path.isdir(paths.lib_dir),
            os.path.dirname(paths.client_conf): os.path.isdir(os.path.dirname(paths.client_conf)),
        },
    }
    for name, (path, data, meta) in originals.items():
        manifest["files"][name] = {
            "path": path,
            "existed": data is not None,
            "sha256": sha256(data) if data is not None else None,
            "metadata": meta,
        }
        if data is not None:
            atomic_write(os.path.join(paths.state, name + ".original"), data,
                         {"mode": 0o600, "uid": 0, "gid": 0})
    _write_manifest(paths, manifest)
    return manifest


def _write_manifest(paths, manifest):
    data = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    atomic_write(os.path.join(paths.state, "manifest.json"), data,
                 {"mode": 0o600, "uid": 0, "gid": 0})


def _load_manifest(paths):
    manifest_path = os.path.join(paths.state, "manifest.json")
    if not os.path.isfile(manifest_path):
        raise ManagerError("Snapshot/manifest ausente; nenhum arquivo será removido")
    with open(manifest_path, "r") as stream:
        return json.load(stream)


def _original(paths, name, info):
    if not info["existed"]:
        return None
    with open(os.path.join(paths.state, name + ".original"), "rb") as stream:
        data = stream.read()
    if sha256(data) != info["sha256"]:
        raise ManagerError("Hash de snapshot divergente: " + name)
    return data


def _ensure_root(paths):
    if effective_uid() != 0:
        raise ManagerError("Execute como root")
    for path in (paths.postfix, paths.postconf, paths.python, paths.main, paths.master):
        if not os.path.exists(path):
            raise ManagerError("Postfix/arquivo não encontrado: " + path)
    for source in (paths.source_client, paths.source_policy):
        if not os.path.isfile(source):
            raise ManagerError("Arquivo do pacote ausente: " + source)


def _postfix_version(paths, runner):
    output = runner([paths.postconf, "mail_version"])
    try:
        version = output.strip().split("=", 1)[1].strip()
        parts = tuple(int(part) for part in version.split(".")[:2])
    except (IndexError, ValueError):
        raise ManagerError("Não foi possível ler mail_version do Postfix")
    if parts < (3, 0):
        raise ManagerError("Fail-open da policy requer Postfix 3.0+ (default_action=DUNNO)")
    return version


def _run_check(paths, runner):
    output = runner([paths.postfix, "check"])
    if "fatal" in output.lower() or "error" in output.lower():
        raise ManagerError("postfix check reportou erro:\n" + output[-3000:])
    return output


def _run_policy_smoke(paths, runner):
    request = (
        b"request=smtpd_access_policy\n"
        b"protocol_state=RCPT\n"
        b"client_address=192.0.2.25\n"
        b"sender=sender@example.test\n"
        b"helo_name=mx-smoke.example.test\n"
        b"recipient=recipient@example.test\n\n"
    )
    output = runner(
        [paths.python, paths.policy, "--config", paths.client_conf],
        timeout=5,
        input_data=request,
    )
    if "action=DUNNO" not in output or '"decision":"LAN"' not in output:
        raise ManagerError("Consulta sintética ao core não confirmou LAN/DUNNO\n" + output[-3000:])
    return output


def validate(paths=None, runner=run_command, preflight=True):
    paths = paths or Paths()
    if preflight:
        _ensure_root(paths)
    with exclusive_lock(paths.lock):
        version = _postfix_version(paths, runner)
        current = runner([paths.postconf, "-h", "smtpd_recipient_restrictions"]).strip()
        relay = runner([paths.postconf, "-h", "smtpd_relay_restrictions"]).strip()
        candidate, changed = add_policy_restriction(current, relay)
        if changed:
            validate_restriction_value(candidate, relay)
        master = read_optional(paths.master)
        if master is None:
            raise ManagerError("master.cf ausente")
        append_master_block(master)
        return "Postfix {0}: candidato MONITOR validado; restart/reload não executado".format(version)


def install(paths=None, server=None, port=9877, runner=run_command, reload_postfix=False, preflight=True):
    paths = paths or Paths()
    if preflight:
        _ensure_root(paths)
    try:
        import ipaddress
        server = str(ipaddress.ip_address(server))
    except (ValueError, TypeError) as exc:
        raise ManagerError("Informe --server com IPv4/IPv6 literal do endpoint SPFBL") from exc
    if not 1 <= int(port) <= 65535:
        raise ManagerError("Porta fora do intervalo TCP")
    port = int(port)

    with exclusive_lock(paths.lock):
        version = _postfix_version(paths, runner)
        main_original = read_optional(paths.main)
        master_original = read_optional(paths.master)
        if main_original is None or master_original is None:
            raise ManagerError("main.cf/master.cf ausente")
        if os.path.exists(paths.state):
            raise ManagerError("Snapshot anterior existe; use uninstall antes de atualizar")

        originals = {
            "main": (paths.main, main_original, metadata(paths.main)),
            "master": (paths.master, master_original, metadata(paths.master)),
            "config": (paths.client_conf, read_optional(paths.client_conf), metadata(paths.client_conf)),
            "client": (paths.client, read_optional(paths.client), metadata(paths.client)),
            "policy": (paths.policy, read_optional(paths.policy), metadata(paths.policy)),
        }
        manifest = _snapshot(paths, originals)
        reload_attempted = False
        try:
            restrictions = runner([paths.postconf, "-h", "smtpd_recipient_restrictions"]).strip()
            relay = runner([paths.postconf, "-h", "smtpd_relay_restrictions"]).strip()
            candidate, changed = add_policy_restriction(restrictions, relay)
            validate_restriction_value(candidate, relay)
            updated_master, master_changed = append_master_block(master_original)
            if not changed and not master_changed:
                raise ManagerError("Integração já configurada sem snapshot; verifique antes de prosseguir")

            if not os.path.isdir(paths.lib_dir):
                os.makedirs(paths.lib_dir, mode=0o755)
            shutil.copyfile(paths.source_client, paths.client)
            shutil.copyfile(paths.source_policy, paths.policy)
            os.chmod(paths.client, 0o644)
            os.chmod(paths.policy, 0o755)
            atomic_write(paths.client_conf, config_bytes(server, port), {"mode": 0o644, "uid": 0, "gid": 0})

            if changed:
                runner([paths.postconf, "-e", "smtpd_recipient_restrictions = " + candidate])
            if master_changed:
                atomic_write(paths.master, updated_master, metadata(paths.master))
            _run_check(paths, runner)
            _run_policy_smoke(paths, runner)

            # The core and policy adapter are exercised with reserved test data.
            # Installation never reloads Postfix unless --reload is supplied.
            if reload_postfix:
                reload_attempted = True
                runner([paths.postfix, "reload"])

            manifest["status"] = "installed"
            manifest["postfix_version"] = version
            manifest["server"] = server
            manifest["port"] = port
            for name, (path, _data, _meta) in originals.items():
                current = read_optional(path)
                manifest["files"][name]["installed_sha256"] = sha256(current) if current is not None else None
            _write_manifest(paths, manifest)
            return "installed; Postfix {0}; MONITOR/DUNNO; restart/reload {1}".format(
                version, "executado" if reload_postfix else "pendente")
        except Exception as exc:
            try:
                _restore_originals(paths, manifest)
                if reload_attempted:
                    runner([paths.postfix, "reload"])
                shutil.rmtree(paths.state)
            except Exception as rollback_exc:
                raise ManagerError("Instalação falhou ({0}); rollback incompleto ({1}); snapshot preservado em {2}".format(
                    exc, rollback_exc, paths.state))
            raise ManagerError("Instalação cancelada e revertida: " + str(exc))


def _restore_originals(paths, manifest):
    for name, info in manifest["files"].items():
        original = _original(paths, name, info)
        restore(info["path"], original, info.get("metadata"))
    for path, existed in manifest.get("directories", {}).items():
        if not existed:
            try:
                os.rmdir(path)
            except OSError:
                pass


def uninstall(paths=None, runner=run_command, reload_postfix=False, preflight=True):
    paths = paths or Paths()
    if preflight:
        _ensure_root(paths)
    with exclusive_lock(paths.lock):
        manifest = _load_manifest(paths)
        if manifest.get("status") != "installed":
            raise ManagerError("Snapshot não representa instalação concluída")
        for name, info in manifest["files"].items():
            current = read_optional(info["path"])
            current_hash = sha256(current) if current is not None else None
            if current_hash != info.get("installed_sha256"):
                raise ManagerError("Arquivo {0} mudou após instalação; rollback preservado sem sobrescrever".format(
                    info["path"]))
        current_files = {name: read_optional(info["path"]) for name, info in manifest["files"].items()}
        current_meta = {name: metadata(info["path"]) for name, info in manifest["files"].items()}
        try:
            _restore_originals(paths, manifest)
            _run_check(paths, runner)
            if reload_postfix:
                runner([paths.postfix, "reload"])
            manifest["status"] = "removed"
            _write_manifest(paths, manifest)
            if not os.path.isdir(paths.archive):
                os.makedirs(paths.archive, mode=0o700)
            archive_name = "install-{0}-{1}".format(int(time.time() * 1000), os.getpid())
            os.replace(paths.state, os.path.join(paths.archive, archive_name))
            return "removed-exactly; reload {0}".format("executado" if reload_postfix else "pendente")
        except Exception as exc:
            try:
                for name, info in manifest["files"].items():
                    restore(info["path"], current_files[name], current_meta[name])
                _run_check(paths, runner)
                if reload_postfix:
                    runner([paths.postfix, "reload"])
            except Exception as rollback_exc:
                raise ManagerError("Uninstall falhou ({0}); restauração do estado ativo falhou ({1}); snapshot em {2}".format(
                    exc, rollback_exc, paths.state))
            raise ManagerError("Uninstall cancelado; integração foi recomposta: " + str(exc))


def healthcheck(paths=None, runner=run_command, preflight=True):
    paths = paths or Paths()
    if preflight:
        _ensure_root(paths)
    _run_check(paths, runner)
    restrictions = runner([paths.postconf, "-h", "smtpd_recipient_restrictions"]).strip()
    relay = runner([paths.postconf, "-h", "smtpd_relay_restrictions"]).strip()
    validate_restriction_value(restrictions, relay)
    master = read_optional(paths.master) or b""
    span = spans(master)
    if not span or master[span[0]:span[1]] != MASTER_BLOCK:
        raise ManagerError("Serviço HAD MONITOR ausente ou divergente em master.cf")
    if not os.path.isfile(paths.client) or not os.path.isfile(paths.policy) or not os.path.isfile(paths.client_conf):
        raise ManagerError("Arquivos runtime/config do HAD incompletos")
    return "Postfix válido; policy HAD presente; MONITOR/DUNNO configurado"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "install", "uninstall", "healthcheck"))
    parser.add_argument("--server", help="IP literal do endpoint SPFBL; use o loopback do túnel quando aplicável")
    parser.add_argument("--port", type=int, default=9877)
    parser.add_argument("--reload", action="store_true", help="recarrega Postfix após validação; instala sem reload por padrão")
    args = parser.parse_args(argv)
    paths = Paths()
    try:
        if args.command == "validate":
            print(validate(paths))
        elif args.command == "install":
            print(install(paths, server=args.server, port=args.port, reload_postfix=args.reload))
        elif args.command == "uninstall":
            print(uninstall(paths, reload_postfix=args.reload))
        else:
            print(healthcheck(paths))
        return 0
    except ManagerError as exc:
        print("ERRO: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
