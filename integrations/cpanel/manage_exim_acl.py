#!/usr/bin/env python3
"""Transactional cPanel Exim ACL manager for HAD's MONITOR-only hook.

Compatible with the Python 3.6 runtime shipped by the homologation host.
"""
from __future__ import print_function

import argparse
import contextlib
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


BEGIN = b"# BEGIN HAD-ANTISPAM-MONITOR"
END = b"# END HAD-ANTISPAM-MONITOR"
DEFAULT_HOOK = "/usr/local/cpanel/etc/exim/acls/ACL_RECIPIENT_BLOCK/custom_begin_recipient"
DEFAULT_EXIM = "/etc/exim.conf"
DEFAULT_STATE = "/var/lib/had-antispam/cpanel-acl/current"
DEFAULT_LOCK = "/run/lock/had-antispam-exim-acl.lock"
DEFAULT_LOCALOPTS_KEY = "acl_custom_begin_recipient"


class ManagerError(RuntimeError):
    pass


def effective_uid():
    return os.geteuid() if hasattr(os, "geteuid") else -1


def effective_gid():
    return os.getegid() if hasattr(os, "getegid") else -1


class Paths(object):
    """Filesystem/command paths; root is injectable by unit tests only."""

    def __init__(self, root="/"):
        self.root = os.path.abspath(root)
        self.hook = self.path(DEFAULT_HOOK)
        self.exim = self.path(DEFAULT_EXIM)
        self.exim_local = self.path("/etc/exim.conf.local")
        self.exim_localopts = self.path("/etc/exim.conf.localopts")
        self.state = self.path(DEFAULT_STATE)
        self.archive = self.path("/var/lib/had-antispam/cpanel-acl/archive")
        self.lock = self.path(DEFAULT_LOCK)
        self.cpanel_version = self.path("/usr/local/cpanel/version")
        self.builder = self.path("/usr/local/cpanel/scripts/buildeximconf")
        self.exim_bin = self.path("/usr/sbin/exim")
        self.restart_exim = self.path("/usr/local/cpanel/scripts/restartsrv_exim")
        self.snippet = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "exim", "acl-rcpt-monitor.conf")

    def path(self, value):
        if self.root == os.path.abspath(os.sep):
            return value
        return os.path.join(self.root, value.lstrip("/"))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def hash_file(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as stream:
        return sha256(stream.read())


def read_optional(path):
    if not os.path.exists(path):
        return None
    if not os.path.isfile(path) or os.path.islink(path):
        raise ManagerError("Recusando hook que não seja arquivo regular: " + path)
    with open(path, "rb") as stream:
        return stream.read()


def file_metadata(path):
    if not os.path.exists(path):
        return None
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise ManagerError("Recusando hook que não seja arquivo regular: " + path)
    return {
        "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "atime_ns": getattr(info, "st_atime_ns", int(info.st_atime * 1000000000)),
        "mtime_ns": getattr(info, "st_mtime_ns", int(info.st_mtime * 1000000000)),
    }


def atomic_write(path, data, metadata=None):
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        os.makedirs(parent)
    fd, temporary = tempfile.mkstemp(prefix=".had-antispam-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        mode = metadata["mode"] if metadata else 0o644
        os.chmod(temporary, mode)
        if metadata and hasattr(os, "chown") and effective_uid() == 0:
            os.chown(temporary, metadata["uid"], metadata["gid"])
        os.replace(temporary, path)
        if metadata:
            os.utime(path, ns=(metadata["atime_ns"], metadata["mtime_ns"]))
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def restore(path, data, metadata):
    if data is None:
        try:
            os.unlink(path)
        except OSError as exc:
            if exc.errno != 2:
                raise
        return
    atomic_write(path, data, metadata)


def update_cpanel_option(data, key, value, allowed_current=None,
                         restore_trailing_newline=None):
    """Update exactly one cPanel localopts boolean while preserving other bytes."""
    if value not in (None, "0", "1"):
        raise ManagerError("Valor inválido para opção cPanel: " + str(value))
    key_bytes = key.encode("ascii")
    line_pattern = re.compile(
        rb"^([ \t]*" + re.escape(key_bytes) + rb"[ \t]*=[ \t]*)([01])([ \t]*(?:#.*)?)$")
    key_pattern = re.compile(rb"^[ \t]*" + re.escape(key_bytes) + rb"[ \t]*=")
    lines = data.splitlines(True)
    matches = []
    for index, line in enumerate(lines):
        body = line.rstrip(b"\r\n")
        if not key_pattern.match(body):
            continue
        match = line_pattern.match(body)
        if not match:
            raise ManagerError("Opção cPanel tem formato inesperado: " + key)
        matches.append((index, line, body, match))
    if len(matches) > 1:
        raise ManagerError("Esperada exatamente uma opção {0} em exim.conf.localopts; encontradas {1}".format(
            key, len(matches)))
    if not matches:
        current = None
        if allowed_current is not None and current not in allowed_current:
            raise ManagerError("Opção cPanel {0} mudou para ausente; alteração interrompida".format(key))
        if value is None:
            return data, current
        prefix = data
        if prefix and not prefix.endswith((b"\n", b"\r")):
            prefix += b"\n"
        return prefix + key_bytes + b"=" + value.encode("ascii") + b"\n", current
    index, line, body, match = matches[0]
    current = match.group(2).decode("ascii")
    if allowed_current is not None and current not in allowed_current:
        raise ManagerError("Opção cPanel {0} mudou para {1}; alteração interrompida".format(
            key, current))
    if current == value:
        return data, current
    if value is None:
        del lines[index]
        updated = b"".join(lines)
        if restore_trailing_newline is False and updated.endswith(b"\n"):
            updated = updated[:-1]
        return updated, current
    ending = line[len(body):]
    lines[index] = match.group(1) + value.encode("ascii") + match.group(3) + ending
    return b"".join(lines), current


def read_cpanel_option(path, key):
    data = read_optional(path)
    if data is None:
        raise ManagerError("Arquivo cPanel ausente: " + path)
    key_bytes = key.encode("ascii")
    line_pattern = re.compile(
        rb"^[ \t]*" + re.escape(key_bytes) + rb"[ \t]*=[ \t]*([01])(?:[ \t]*(?:#.*)?)?$")
    key_pattern = re.compile(rb"^[ \t]*" + re.escape(key_bytes) + rb"[ \t]*=")
    values = []
    for line in data.splitlines(True):
        body = line.rstrip(b"\r\n")
        if key_pattern.match(body):
            match = line_pattern.match(body)
            if not match:
                raise ManagerError("Opção cPanel tem formato inesperado: " + key)
            values.append(match.group(1).decode("ascii"))
    if len(values) > 1:
        raise ManagerError("Esperada exatamente uma opção {0} em exim.conf.localopts; encontradas {1}".format(
            key, len(values)))
    return values[0] if values else None


def set_cpanel_option(paths, key, value, allowed_current=None,
                      restore_trailing_newline=None):
    data = read_optional(paths.exim_localopts)
    if data is None:
        raise ManagerError("Arquivo cPanel ausente: " + paths.exim_localopts)
    updated, current = update_cpanel_option(
        data, key, value, allowed_current, restore_trailing_newline)
    if updated != data:
        metadata = file_metadata(paths.exim_localopts)
        atomic_write(paths.exim_localopts, updated, metadata)
    return current


def marker_spans(data):
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
        raise ManagerError("Marcadores HAD ausentes, duplicados ou fora de ordem no hook")
    start = data.rfind(b"\n", 0, starts[0]) + 1
    end = data.find(b"\n", ends[0])
    if end < 0:
        end = len(data)
    else:
        end += 1
    return start, end


def compose_hook(current, snippet):
    span = marker_spans(current or b"")
    if span:
        start, end = span
        if (current or b"")[start:end] == snippet:
            return current
        raise ManagerError("O hook já contém um bloco HAD diferente; revisão manual necessária")
    if not snippet.startswith(BEGIN + b"\n") or not snippet.rstrip().endswith(END):
        raise ManagerError("O snippet não contém os marcadores gerenciados esperados")
    current = current or b""
    if current and not current.endswith(b"\n"):
        current += b"\n"
    return current + snippet


def remove_hook_block(current):
    span = marker_spans(current or b"")
    if not span:
        raise ManagerError("Não existe bloco HAD para remover")
    start, end = span
    return (current or b"")[:start] + (current or b"")[end:]


def run_command(command, timeout=120, input_data=None):
    try:
        process = subprocess.Popen(command,
                                   stdin=subprocess.PIPE if input_data is not None else None,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        output = process.communicate(input_data, timeout=timeout)[0]
    except subprocess.TimeoutExpired as exc:
        try:
            process.kill()
        except Exception:
            pass
        output = exc.output or b""
        try:
            drained = process.communicate(timeout=2)[0]
            if drained is not None:
                output = drained
        except subprocess.TimeoutExpired as drain_error:
            if drain_error.output is not None:
                output = drain_error.output
        except OSError:
            pass
        partial = output.decode("utf-8", "replace")[-4000:]
        detail = "\nSaída parcial:\n" + partial if partial else "\nSem saída parcial."
        raise ManagerError("Timeout após {0}s ao executar {1}.{2}".format(
            timeout, command[0], detail))
    except OSError as exc:
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


def ensure_cpanel(paths):
    if effective_uid() != 0:
        raise ManagerError("Execute como root no servidor cPanel")
    for path in (paths.cpanel_version, paths.builder, paths.exim_bin):
        if not os.path.exists(path):
            raise ManagerError("cPanel/Exim não encontrado: " + path)


def load_snippet(paths):
    with open(paths.snippet, "rb") as stream:
        return stream.read()


def run_dry_build(paths, runner=run_command):
    output = runner([paths.builder, "--acl_dry_run"])
    if "Dry Run ok" not in output:
        raise ManagerError("O cPanel não confirmou Dry Run ok\n" + output[-3000:])
    # cPanel's --acl_dry_run reports syntax status but does not print the
    # generated candidate. Presence is checked after a full build instead.
    return output


def run_full_build(paths, runner=run_command, expect_marker=True):
    output = runner([paths.builder])
    if "Configuration file passes test!" not in output:
        raise ManagerError("O rebuild não confirmou configuração válida\n" + output[-3000:])
    generated = read_optional(paths.exim)
    has_marker = bool(generated and BEGIN in generated and END in generated)
    if has_marker != expect_marker:
        raise ManagerError("Estado do bloco no /etc/exim.conf diverge do candidato esperado")
    runner([paths.exim_bin, "-C", paths.exim, "-bV"])
    return output


def run_synthetic_smoke(paths, runner=run_command):
    """Run an Exim fake-SMTP session; it cannot deliver a message."""
    smtp = (
        b"EHLO mx-smoke.example.test\n"
        b"MAIL FROM:<>\n"
        b"RCPT TO:<root@localhost>\n"
        b"QUIT\n"
    )
    output = runner(
        [paths.exim_bin, "-C", paths.exim, "-bh", "192.0.2.25"],
        timeout=20,
        input_data=smtp,
    )
    if "SFOX MONITOR RCPT CONTINUE|decision|LAN|" not in output:
        raise ManagerError("Fake-SMTP não confirmou consulta HAD MONITOR LAN\n" + output[-3000:])
    return output


def snapshot_state(paths, current, metadata, snippet, managed_option=None):
    if os.path.exists(paths.state):
        raise ManagerError("Há snapshot de instalação anterior; execute uninstall/status primeiro")
    localopts_data = read_optional(paths.exim_localopts) if managed_option else None
    managed_option_before = (read_cpanel_option(paths.exim_localopts, managed_option)
                             if managed_option else None)
    os.makedirs(paths.state, mode=0o700)
    os.chmod(paths.state, 0o700)
    if current is not None:
        atomic_write(os.path.join(paths.state, "hook.original"), current, metadata)
    manifest = {
        "schema": 1,
        "created": int(time.time()),
        "hook_existed": current is not None,
        "hook_metadata": metadata,
        "hook_sha256": sha256(current) if current is not None else None,
        "snippet_sha256": sha256(snippet),
        "managed_block_sha256": sha256(snippet),
        "exim_sha256_before": hash_file(paths.exim),
        "exim_local_sha256_before": hash_file(paths.exim_local),
        "exim_localopts_sha256_before": hash_file(paths.exim_localopts),
        "status": "installing",
    }
    if managed_option:
        manifest["managed_localopts_option"] = {
            "key": managed_option,
            "before": managed_option_before,
            "active": "1",
            "before_terminated": localopts_data.endswith((b"\n", b"\r")),
        }
    write_manifest(paths, manifest)
    return manifest


def write_manifest(paths, manifest):
    data = json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    atomic_write(os.path.join(paths.state, "manifest.json"), data,
                 {"mode": 0o600, "uid": effective_uid(), "gid": effective_gid(),
                  "atime_ns": int(time.time() * 1000000000),
                  "mtime_ns": int(time.time() * 1000000000)})


def load_manifest(paths):
    manifest_path = os.path.join(paths.state, "manifest.json")
    if not os.path.isfile(manifest_path):
        raise ManagerError("Snapshot de instalação ausente; não removi arquivos sem backup")
    with open(manifest_path, "r") as stream:
        return json.load(stream)


def load_original(paths, manifest):
    if not manifest.get("hook_existed"):
        return None
    with open(os.path.join(paths.state, "hook.original"), "rb") as stream:
        data = stream.read()
    if sha256(data) != manifest.get("hook_sha256"):
        raise ManagerError("Hash do snapshot original diverge; rollback interrompido")
    return data


def ensure_snapshot_permissions(paths):
    if effective_uid() == 0 and hasattr(os, "chown"):
        os.chown(paths.state, 0, 0)
        os.chmod(paths.state, 0o700)
        for name in os.listdir(paths.state):
            item = os.path.join(paths.state, name)
            os.chown(item, 0, 0)
            os.chmod(item, 0o600)


def verify_exim_source_unchanged(paths, manifest):
    if hash_file(paths.exim_local) != manifest.get("exim_local_sha256_before"):
        raise ManagerError("/etc/exim.conf.local mudou durante a transação; preservado para revisão")
    option = manifest.get("managed_localopts_option")
    current_hash = hash_file(paths.exim_localopts)
    if option:
        data = read_optional(paths.exim_localopts)
        if data is None:
            raise ManagerError("/etc/exim.conf.localopts desapareceu durante a transação")
        normalized, _ = update_cpanel_option(
            data, option["key"], option["before"],
            allowed_current=(option["before"], option["active"]),
            restore_trailing_newline=option.get("before_terminated"))
        current_hash = sha256(normalized)
    if current_hash != manifest.get("exim_localopts_sha256_before"):
        raise ManagerError("/etc/exim.conf.localopts mudou durante a transação; preservado para revisão")


def rollback_install(paths, original, metadata, manifest, runner, reload_exim=False):
    verify_exim_source_unchanged(paths, manifest)
    restore(paths.hook, original, metadata)
    option = manifest.get("managed_localopts_option")
    if option:
        set_cpanel_option(paths, option["key"], option["before"],
                          allowed_current=(option["before"], option["active"]),
                          restore_trailing_newline=option.get("before_terminated"))
    if manifest.get("status") == "installing" and hash_file(paths.exim) != manifest.get("exim_sha256_before"):
        run_full_build(paths, runner=runner, expect_marker=False)
        if hash_file(paths.exim) != manifest.get("exim_sha256_before"):
            raise ManagerError("Rollback recompôs o Exim, mas o hash gerado difere do snapshot")
    if reload_exim:
        runner([paths.restart_exim])


def validate(paths=None, runner=run_command, preflight=True):
    paths = paths or Paths()
    if preflight:
        ensure_cpanel(paths)
    snippet = load_snippet(paths)
    with exclusive_lock(paths.lock):
        current = read_optional(paths.hook)
        metadata = file_metadata(paths.hook)
        candidate = compose_hook(current, snippet)
        original_option = read_cpanel_option(paths.exim_localopts, DEFAULT_LOCALOPTS_KEY)
        localopts_data = read_optional(paths.exim_localopts)
        original_terminated = localopts_data.endswith((b"\n", b"\r"))
        try:
            set_cpanel_option(paths, DEFAULT_LOCALOPTS_KEY, "1",
                              allowed_current=(original_option, "1"))
            atomic_write(paths.hook, candidate, metadata)
            output = run_dry_build(paths, runner=runner)
        finally:
            restore(paths.hook, current, metadata)
            set_cpanel_option(paths, DEFAULT_LOCALOPTS_KEY,
                              original_option, allowed_current=(original_option, "1"),
                              restore_trailing_newline=original_terminated)
        if read_optional(paths.hook) != current:
            raise ManagerError("Validação não restaurou exatamente o hook original")
        return output


def install(paths=None, runner=run_command, reload_exim=False, preflight=True):
    paths = paths or Paths()
    if preflight:
        ensure_cpanel(paths)
    snippet = load_snippet(paths)
    with exclusive_lock(paths.lock):
        current = read_optional(paths.hook)
        metadata = file_metadata(paths.hook)
        span = marker_spans(current or b"")
        if span:
            installed = compose_hook(current, snippet)
            if installed != current:
                raise ManagerError("Já existe um bloco HAD divergente no hook")
            if read_cpanel_option(paths.exim_localopts, DEFAULT_LOCALOPTS_KEY) != "1":
                raise ManagerError("Bloco HAD existe, mas acl_custom_begin_recipient está desativado; revisão do snapshot necessária")
            run_dry_build(paths, runner=runner)
            if reload_exim:
                run_full_build(paths, runner=runner, expect_marker=True)
                run_synthetic_smoke(paths, runner=runner)
                runner([paths.restart_exim])
            return "already-installed"

        manifest = snapshot_state(paths, current, metadata, snippet,
                                  managed_option=DEFAULT_LOCALOPTS_KEY)
        ensure_snapshot_permissions(paths)
        reload_attempted = False
        try:
            option = manifest["managed_localopts_option"]
            set_cpanel_option(paths, option["key"], option["active"],
                              allowed_current=(option["before"], option["active"]))
            candidate = compose_hook(current, snippet)
            atomic_write(paths.hook, candidate, metadata)
            run_dry_build(paths, runner=runner)
            run_full_build(paths, runner=runner, expect_marker=True)
            run_synthetic_smoke(paths, runner=runner)
            verify_exim_source_unchanged(paths, manifest)
            if reload_exim:
                reload_attempted = True
                runner([paths.restart_exim])
            manifest["status"] = "installed"
            manifest["hook_sha256_installed"] = sha256(candidate)
            manifest["exim_sha256_installed"] = hash_file(paths.exim)
            write_manifest(paths, manifest)
            ensure_snapshot_permissions(paths)
            return "installed"
        except Exception as exc:
            try:
                rollback_install(paths, current, metadata, manifest, runner,
                                 reload_exim=reload_attempted)
                shutil.rmtree(paths.state)
            except Exception as rollback_exc:
                raise ManagerError("Instalação falhou: {0}; rollback requer atenção: {1}; snapshot preservado em {2}".format(
                    exc, rollback_exc, paths.state))
            raise ManagerError("Instalação cancelada e revertida: " + str(exc))


def uninstall(paths=None, runner=run_command, reload_exim=False, preflight=True):
    paths = paths or Paths()
    if preflight:
        ensure_cpanel(paths)
    with exclusive_lock(paths.lock):
        manifest = load_manifest(paths)
        if manifest.get("status") != "installed":
            raise ManagerError("Snapshot não está marcado como instalação concluída")
        current = read_optional(paths.hook)
        metadata = file_metadata(paths.hook)
        span = marker_spans(current or b"")
        if not span:
            raise ManagerError("Bloco HAD não existe no hook; snapshot mantido para revisão")
        start, end = span
        if sha256((current or b"")[start:end]) != manifest.get("managed_block_sha256"):
            raise ManagerError("Bloco gerenciado mudou desde a instalação; snapshot mantido sem sobrescrever")
        original = load_original(paths, manifest)
        candidate = remove_hook_block(current)
        verify_exim_source_unchanged(paths, manifest)
        try:
            if original is None and not candidate:
                restore(paths.hook, None, None)
            else:
                atomic_write(paths.hook, candidate, metadata)
            option = manifest.get("managed_localopts_option")
            if option:
                set_cpanel_option(paths, option["key"], option["before"],
                                  allowed_current=(option["before"], option["active"]),
                                  restore_trailing_newline=option.get("before_terminated"))
            run_dry_build(paths, runner=runner)
            run_full_build(paths, runner=runner, expect_marker=False)
            verify_exim_source_unchanged(paths, manifest)
            if reload_exim:
                runner([paths.restart_exim])
            expected_hash = manifest.get("exim_sha256_before")
            exact = expected_hash is None or hash_file(paths.exim) == expected_hash
            if original == candidate:
                restore(paths.hook, original, manifest.get("hook_metadata"))
            manifest["status"] = "removed" if exact else "removed-with-exim-drift"
            manifest["exim_sha256_after_uninstall"] = hash_file(paths.exim)
            write_manifest(paths, manifest)
            ensure_snapshot_permissions(paths)
            if not os.path.isdir(paths.archive):
                os.makedirs(paths.archive, mode=0o700)
                if effective_uid() == 0 and hasattr(os, "chown"):
                    os.chown(paths.archive, 0, 0)
            archive_name = "install-{0}-{1}".format(int(time.time() * 1000), os.getpid())
            os.replace(paths.state, os.path.join(paths.archive, archive_name))
            return "removed-exactly" if exact else "removed; generated Exim differs from pre-install hash"
        except Exception as exc:
            try:
                restore(paths.hook, current, metadata)
                option = manifest.get("managed_localopts_option")
                if option:
                    set_cpanel_option(paths, option["key"], option["active"],
                                      allowed_current=(option["before"], option["active"]))
                run_full_build(paths, runner=runner, expect_marker=True)
                if reload_exim:
                    runner([paths.restart_exim])
            except Exception as rollback_exc:
                raise ManagerError("Uninstall falhou: {0}; restauração do estado ativo também falhou: {1}; snapshot preservado em {2}".format(
                    exc, rollback_exc, paths.state))
            raise ManagerError("Uninstall cancelado; estado HAD anterior foi recomposto: " + str(exc))


def healthcheck(paths=None, runner=run_command, preflight=True):
    paths = paths or Paths()
    if preflight:
        ensure_cpanel(paths)
    current = read_optional(paths.hook) or b""
    if not marker_spans(current):
        raise ManagerError("Bloco HAD não encontrado no hook RCPT")
    generated = read_optional(paths.exim) or b""
    if BEGIN not in generated or END not in generated:
        raise ManagerError("Configuração Exim gerada não contém o bloco HAD")
    runner([paths.exim_bin, "-C", paths.exim, "-bV"])
    return "SFOX MONITOR presente no hook e na configuração Exim gerada"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gerencia a ACL RCPT MONITOR do HAD no cPanel.")
    parser.add_argument("command", choices=("validate", "install", "uninstall", "healthcheck"))
    parser.add_argument("--reload", action="store_true",
                        help="reinicia o Exim somente após rebuild e teste de sintaxe aprovados")
    args = parser.parse_args(argv)
    paths = Paths()
    try:
        if args.command == "validate":
            validate(paths)
            print("Dry-run cPanel aprovado; hook original restaurado byte a byte.")
        elif args.command == "install":
            print(install(paths, reload_exim=args.reload))
        elif args.command == "uninstall":
            print(uninstall(paths, reload_exim=args.reload))
        else:
            print(healthcheck(paths))
        return 0
    except ManagerError as exc:
        print("ERRO: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
