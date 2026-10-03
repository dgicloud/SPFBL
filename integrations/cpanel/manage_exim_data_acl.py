#!/usr/bin/env python3
"""Transactional manager for the Exim DATA HEADER monitor hook."""
from __future__ import print_function

import argparse
import os
import re
import shutil
import sys
import time

from manage_exim_acl import (
    BEGIN as RCPT_BEGIN,
    END as RCPT_END,
    ManagerError,
    Paths as BasePaths,
    atomic_write,
    effective_gid,
    effective_uid,
    ensure_cpanel,
    ensure_snapshot_permissions,
    exclusive_lock,
    file_metadata,
    hash_file,
    load_manifest,
    load_original,
    read_optional,
    restore,
    run_command,
    run_dry_build,
    sha256,
    snapshot_state,
    verify_exim_source_unchanged,
    write_manifest,
)


BEGIN = b"# BEGIN HAD-ANTISPAM-HEADER-MONITOR"
END = b"# END HAD-ANTISPAM-HEADER-MONITOR"
HOOK = "/usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/custom_begin_check_message_pre"
STATE = "/var/lib/had-antispam/cpanel-data-acl/current"
ARCHIVE = "/var/lib/had-antispam/cpanel-data-acl/archive"
TEST_RECIPIENT_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


class DataPaths(BasePaths):
    def __init__(self, root="/"):
        super(DataPaths, self).__init__(root)
        self.hook = self.path(HOOK)
        self.state = self.path(STATE)
        self.archive = self.path(ARCHIVE)
        self.snippet = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "exim", "acl-data-header-monitor.conf")


def marker_spans(data):
    starts = []
    ends = []
    offset = 0
    while True:
        position = data.find(BEGIN, offset)
        if position < 0:
            break
        starts.append(position)
        offset = position + len(BEGIN)
    offset = 0
    while True:
        position = data.find(END, offset)
        if position < 0:
            break
        ends.append(position)
        offset = position + len(END)
    if not starts and not ends:
        return None
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ManagerError("Marcadores DATA HAD ausentes, duplicados ou fora de ordem")
    start = data.rfind(b"\n", 0, starts[0]) + 1
    end = data.find(b"\n", ends[0])
    return start, len(data) if end < 0 else end + 1


def compose_hook(current, snippet):
    span = marker_spans(current or b"")
    if span:
        start, end = span
        if (current or b"")[start:end] == snippet:
            return current
        raise ManagerError("Bloco DATA HAD já existe com conteúdo diferente")
    if not snippet.startswith(BEGIN + b"\n") or not snippet.rstrip().endswith(END):
        raise ManagerError("Snippet DATA não contém os marcadores esperados")
    current = current or b""
    if current and not current.endswith(b"\n"):
        current += b"\n"
    return current + snippet


def remove_hook_block(current):
    span = marker_spans(current or b"")
    if not span:
        raise ManagerError("Não existe bloco DATA HAD para remover")
    start, end = span
    return (current or b"")[:start] + (current or b"")[end:]


def load_snippet(paths):
    with open(paths.snippet, "rb") as stream:
        return stream.read()


def has_data_block(data):
    return bool(data and BEGIN in data and END in data)


def has_rcpt_block(data):
    return bool(data and RCPT_BEGIN in data and RCPT_END in data)


def run_full_build(paths, runner=run_command, expect_data=True, expect_rcpt=None):
    output = runner([paths.builder])
    if "Configuration file passes test!" not in output:
        raise ManagerError("O rebuild não confirmou configuração Exim válida\n" + output[-3000:])
    generated = read_optional(paths.exim) or b""
    if has_data_block(generated) != expect_data:
        raise ManagerError("Bloco DATA no /etc/exim.conf diverge do candidato esperado")
    if expect_rcpt is not None and has_rcpt_block(generated) != expect_rcpt:
        raise ManagerError("Rebuild DATA alterou inesperadamente o hook RCPT existente")
    runner([paths.exim_bin, "-C", paths.exim, "-bV"])
    return output


def validate_test_recipient(recipient):
    if (not isinstance(recipient, str) or len(recipient) > 254
            or not TEST_RECIPIENT_RE.match(recipient)):
        raise ManagerError("Informe --test-recipient como endereço local válido para o smoke SMTP")
    return recipient


def run_synthetic_data_smoke(paths, runner=run_command, test_recipient=None):
    """Exercise the DATA ACL with fake SMTP; this cannot queue or deliver mail."""
    test_recipient = validate_test_recipient(test_recipient)
    smtp = (
        b"EHLO had-data-smoke.invalid\n"
        b"MAIL FROM:<>\n"
        + "RCPT TO:<{0}>\n".format(test_recipient).encode("ascii")
        + b"DATA\n"
        b"From: had-data-smoke@example.invalid\n"
        b"Message-ID: <had-data-smoke@example.invalid>\n"
        b"Date: Fri, 02 Oct 2026 10:00:00 -0300\n"
        b"Subject: HAD DATA ACL smoke\n"
        b"\n.\nQUIT\n"
    )
    output = runner([paths.exim_bin, "-C", paths.exim, "-bh", "127.0.0.1"],
                    timeout=20, input_data=smtp)
    if "HAD AntiSpam MONITOR DATA CONTINUE|header|no_ticket|" not in output:
        raise ManagerError("Fake-SMTP não confirmou ACL DATA em fail-open sem ticket\n" + output[-3000:])
    return output


def validate(paths=None, runner=run_command, preflight=True):
    paths = paths or DataPaths()
    if preflight:
        ensure_cpanel(paths)
    snippet = load_snippet(paths)
    with exclusive_lock(paths.lock):
        current = read_optional(paths.hook)
        metadata = file_metadata(paths.hook)
        atomic_write(paths.hook, compose_hook(current, snippet), metadata)
        try:
            output = run_dry_build(paths, runner=runner)
        finally:
            restore(paths.hook, current, metadata)
        if read_optional(paths.hook) != current:
            raise ManagerError("Validação DATA não restaurou o hook original byte a byte")
        return output


def rollback_install(paths, original, metadata, manifest, runner, reload_exim=False):
    restore(paths.hook, original, metadata)
    if manifest.get("status") == "installing" and hash_file(paths.exim) != manifest.get("exim_sha256_before"):
        verify_exim_source_unchanged(paths, manifest)
        run_full_build(paths, runner=runner, expect_data=False,
                       expect_rcpt=manifest.get("rcpt_marker_before"))
        if hash_file(paths.exim) != manifest.get("exim_sha256_before"):
            raise ManagerError("Rollback DATA recompôs o Exim, mas o hash difere do snapshot")
    if reload_exim:
        runner([paths.restart_exim])


def install(paths=None, runner=run_command, reload_exim=False, preflight=True,
            test_recipient=None):
    paths = paths or DataPaths()
    test_recipient = validate_test_recipient(test_recipient)
    if preflight:
        ensure_cpanel(paths)
    snippet = load_snippet(paths)
    with exclusive_lock(paths.lock):
        current = read_optional(paths.hook)
        metadata = file_metadata(paths.hook)
        rcpt_before = has_rcpt_block(read_optional(paths.exim))
        span = marker_spans(current or b"")
        if span:
            if compose_hook(current, snippet) != current:
                raise ManagerError("Bloco DATA HAD divergente; instalação interrompida")
            run_dry_build(paths, runner=runner)
            if reload_exim:
                run_full_build(paths, runner=runner, expect_data=True,
                               expect_rcpt=rcpt_before)
                run_synthetic_data_smoke(paths, runner=runner,
                                         test_recipient=test_recipient)
                runner([paths.restart_exim])
            return "already-installed"

        manifest = snapshot_state(paths, current, metadata, snippet)
        manifest["rcpt_marker_before"] = has_rcpt_block(read_optional(paths.exim))
        write_manifest(paths, manifest)
        ensure_snapshot_permissions(paths)
        reload_attempted = False
        try:
            atomic_write(paths.hook, compose_hook(current, snippet), metadata)
            run_dry_build(paths, runner=runner)
            run_full_build(paths, runner=runner, expect_data=True,
                           expect_rcpt=manifest["rcpt_marker_before"])
            run_synthetic_data_smoke(paths, runner=runner,
                                     test_recipient=test_recipient)
            verify_exim_source_unchanged(paths, manifest)
            if reload_exim:
                reload_attempted = True
                runner([paths.restart_exim])
            manifest["status"] = "installed"
            manifest["hook_sha256_installed"] = sha256(read_optional(paths.hook))
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
                raise ManagerError("Instalação DATA falhou: {0}; rollback requer atenção: {1}; snapshot em {2}".format(
                    exc, rollback_exc, paths.state))
            raise ManagerError("Instalação DATA cancelada e revertida: " + str(exc))


def uninstall(paths=None, runner=run_command, reload_exim=False, preflight=True):
    paths = paths or DataPaths()
    if preflight:
        ensure_cpanel(paths)
    with exclusive_lock(paths.lock):
        manifest = load_manifest(paths)
        if manifest.get("status") != "installed":
            raise ManagerError("Snapshot DATA não está marcado como instalação concluída")
        current = read_optional(paths.hook)
        metadata = file_metadata(paths.hook)
        rcpt_before = has_rcpt_block(read_optional(paths.exim))
        span = marker_spans(current or b"")
        if not span:
            raise ManagerError("Bloco DATA ausente; snapshot mantido para revisão")
        start, end = span
        if sha256((current or b"")[start:end]) != manifest.get("managed_block_sha256"):
            raise ManagerError("Bloco DATA mudou; snapshot mantido sem sobrescrever alterações")
        original = load_original(paths, manifest)
        candidate = remove_hook_block(current)
        try:
            restore(paths.hook, candidate if candidate else None, metadata)
            run_dry_build(paths, runner=runner)
            run_full_build(paths, runner=runner, expect_data=False,
                           expect_rcpt=rcpt_before)
            verify_exim_source_unchanged(paths, manifest)
            if reload_exim:
                runner([paths.restart_exim])
            exact = hash_file(paths.exim) == manifest.get("exim_sha256_before")
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
                run_full_build(paths, runner=runner, expect_data=True,
                               expect_rcpt=rcpt_before)
                if reload_exim:
                    runner([paths.restart_exim])
            except Exception as rollback_exc:
                raise ManagerError("Uninstall DATA falhou: {0}; restauração ativa falhou: {1}; snapshot em {2}".format(
                    exc, rollback_exc, paths.state))
            raise ManagerError("Uninstall DATA cancelado; estado anterior recomposto: " + str(exc))


def healthcheck(paths=None, runner=run_command, preflight=True):
    paths = paths or DataPaths()
    if preflight:
        ensure_cpanel(paths)
    current = read_optional(paths.hook) or b""
    if not marker_spans(current):
        raise ManagerError("Bloco HAD DATA não encontrado no hook cPanel")
    if not has_data_block(read_optional(paths.exim) or b""):
        raise ManagerError("Configuração Exim gerada não contém o bloco HAD DATA")
    runner([paths.exim_bin, "-C", paths.exim, "-bV"])
    return "HAD AntiSpam HEADER/DATA presente no hook e no Exim gerado"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gerencia o hook DATA HEADER MONITOR do HAD no cPanel.")
    parser.add_argument("command", choices=("validate", "install", "uninstall", "healthcheck"))
    parser.add_argument("--reload", action="store_true",
                        help="reinicia Exim após rebuild e fake SMTP DATA aprovado")
    parser.add_argument("--test-recipient",
                        help="endereço local válido usado somente no smoke SMTP (sem entrega)")
    args = parser.parse_args(argv)
    paths = DataPaths()
    try:
        if args.command == "validate":
            validate(paths)
            print("Dry-run DATA cPanel aprovado; hook original restaurado byte a byte.")
        elif args.command == "install":
            print(install(paths, reload_exim=args.reload,
                          test_recipient=args.test_recipient))
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
