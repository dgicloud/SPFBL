#!/usr/bin/env python3
"""Restricted local firewall RPC. The core runs only the unprivileged client."""

import argparse
import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import socket
import socketserver
import struct
import sys
import tempfile
import uuid

try:
    import fcntl
    import pwd
except ImportError:  # Manager tests are portable; the RPC server requires Linux.
    fcntl = pwd = None

SOCKET = "/run/spamfox-firewall/control.sock"
ALLOWLIST = Path("/etc/spamfox/allowed-cpanels.txt")
BACKUPS = Path("/var/backups/spamfox/firewall")
MAX_REQUEST = 8192
MAX_RESPONSE = 2 * 1024 * 1024
MAX_ENTRIES = 1024
LOG = logging.getLogger("spamfox-firewall-admin")


class FirewallAdminError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


def normalize_cidr(value):
    try:
        if not isinstance(value, str) or len(value) > 80 or "%" in value:
            raise ValueError()
        network = ipaddress.ip_network(value.strip(), strict=False)
        if network.prefixlen == 0:
            raise ValueError()
        return str(network)
    except ValueError:
        raise FirewallAdminError("invalid", "Informe um IP ou CIDR válido; redes /0 não são permitidas.")


def description(value):
    if not isinstance(value, str) or len(value) > 160 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise FirewallAdminError("invalid", "Descrição inválida: use até 160 caracteres, sem quebras de linha.")
    return value.strip()


def kernel_status(entries):
    import firewall
    try:
        table = firewall._existing_table()
        if table is None:
            return {"active": False, "synchronized": False}
        actual = {str(ipaddress.ip_network(value, strict=False)) for value in
                  re.findall(r"\bip6? saddr (\S+) tcp dport 9877 accept", table)}
        expected = {entry["cidr"] for entry in entries}
        drops = all("tcp dport %s drop" % port in table for port in (9877, 9875, 8080))
        return {"active": True, "synchronized": actual == expected and drops}
    except (OSError, ValueError, firewall.FirewallError):
        return {"active": False, "synchronized": False}


def apply_file(path):
    import firewall
    firewall.apply(str(path), allow_empty=True)


class Manager:
    def __init__(self, path=ALLOWLIST, backups=BACKUPS, applier=apply_file, status=kernel_status):
        self.path, self.backups = Path(path), Path(backups)
        self.applier, self.status = applier, status

    def read(self):
        if self.path.is_symlink():
            raise FirewallAdminError("unavailable", "A allowlist deve ser um arquivo regular.")
        with self.path.open("rb") as stream:
            raw = stream.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise FirewallAdminError("unavailable", "A allowlist excede o limite de tamanho.")
        entries, comments, seen = [], [], set()
        for line in raw.decode("utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                comments.append(line)
                continue
            value, _, note = line.partition("#")
            cidr = normalize_cidr(value)
            if cidr in seen:
                raise FirewallAdminError("invalid", "A allowlist contém IPs/CIDRs duplicados; corrija o arquivo antes de editar.")
            seen.add(cidr)
            entries.append({"cidr": cidr, "description": description(note.strip())})
        if len(entries) > MAX_ENTRIES:
            raise FirewallAdminError("invalid", "Limite de 1024 IPs/CIDRs excedido.")
        return raw, entries, comments

    def snapshot(self):
        raw, entries, _ = self.read()
        return dict(ok=True, revision=hashlib.sha256(raw).hexdigest(), entries=entries, **self.status(entries))

    def request(self, request):
        if not isinstance(request, dict) or set(request) - {
                "action", "cidr", "original", "description", "revision", "actor"}:
            raise FirewallAdminError("invalid", "Solicitação inválida.")
        action = request.get("action")
        if action == "list":
            return self.snapshot()
        if action not in ("add", "update", "delete", "apply"):
            raise FirewallAdminError("invalid", "Ação inválida.")
        actor = request.get("actor", "")
        if not isinstance(actor, str) or not actor or len(actor) > 254 or any(ord(c) < 32 for c in actor):
            raise FirewallAdminError("invalid", "Administrador inválido.")
        raw, entries, comments = self.read()
        revision = hashlib.sha256(raw).hexdigest()
        if request.get("revision") != revision:
            raise FirewallAdminError("conflict", "A lista mudou. Atualize a página antes de salvar.")
        original, cidr = None, None
        if action in ("update", "delete"):
            original = normalize_cidr(request.get("original"))
            if not any(entry["cidr"] == original for entry in entries):
                raise FirewallAdminError("conflict", "O registro já foi removido. Atualize a página.")
        if action in ("add", "update"):
            cidr = normalize_cidr(request.get("cidr"))
            note = description(request.get("description", ""))
            if any(entry["cidr"] == cidr and entry["cidr"] != original for entry in entries):
                raise FirewallAdminError("conflict", "Este IP/CIDR já está cadastrado.")
            if action == "add":
                if len(entries) >= MAX_ENTRIES:
                    raise FirewallAdminError("invalid", "Limite de 1024 IPs/CIDRs atingido.")
                entries.append({"cidr": cidr, "description": note})
            else:
                entries = [{"cidr": cidr, "description": note} if entry["cidr"] == original else entry
                           for entry in entries]
        elif action == "delete":
            entries = [entry for entry in entries if entry["cidr"] != original]
        if action == "apply":
            try:
                self.applier(self.path)
            except Exception:
                raise FirewallAdminError("apply_failed", "Não foi possível reaplicar as regras. Confira o serviço do firewall.")
        else:
            candidate = ("\n".join(comments + [entry["cidr"] + (" # " + entry["description"]
                         if entry["description"] else "") for entry in entries]) + "\n").encode("utf-8")
            if len(candidate) > 256 * 1024:
                raise FirewallAdminError("invalid", "A lista excederia o limite de 256 KiB.")
            self.commit(raw, candidate)
        LOG.info(json.dumps({"event": "spamfox_firewall_change", "actor": actor, "action": action,
                            "original": original, "cidr": cidr, "entries": len(entries)}, ensure_ascii=True))
        # A successful mutation must not be reported as failed just because a later status read failed.
        return {"ok": True, "message": "Regras salvas e aplicadas."}

    def commit(self, original, candidate):
        self.backups.mkdir(mode=0o700, parents=True, exist_ok=True)
        backup = self.backups / ("allowlist-" + uuid.uuid4().hex + ".txt")
        with backup.open("xb") as stream:
            os.chmod(str(backup), 0o600)
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor, name = tempfile.mkstemp(prefix=".firewall-", dir=str(self.path.parent))
        temporary = Path(name)
        applied = False
        try:
            with os.fdopen(descriptor, "wb") as stream:
                os.chmod(str(temporary), 0o640)
                stream.write(candidate)
                stream.flush()
                os.fsync(stream.fileno())
            if self.path.read_bytes() != original or self.path.is_symlink():
                raise FirewallAdminError("conflict", "A lista mudou durante a operação. Atualize a página.")
            self.applier(temporary)
            applied = True
            if self.path.read_bytes() != original or self.path.is_symlink():
                raise FirewallAdminError("conflict", "A lista mudou durante a operação. Atualize a página.")
            os.replace(str(temporary), str(self.path))
        except Exception as error:
            if applied:
                try:
                    self.applier(self.path)
                except Exception:
                    LOG.exception("Firewall rollback failed; configuration file was preserved")
                    raise FirewallAdminError("rollback_failed", "Falha ao restaurar as regras; confira o firewall na VM imediatamente.")
            if isinstance(error, FirewallAdminError):
                raise
            raise FirewallAdminError("apply_failed", "Alteração cancelada; a configuração anterior foi preservada.")
        finally:
            if temporary.exists():
                temporary.unlink()
        try:
            for old in sorted(self.backups.glob("allowlist-*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)[50:]:
                old.unlink()
        except OSError:
            LOG.warning("Could not prune an older firewall backup")


def response_error(error):
    if isinstance(error, FirewallAdminError):
        return {"ok": False, "code": error.code, "message": error.message}
    LOG.exception("Firewall request failed")
    return {"ok": False, "code": "unavailable", "message": "Gestão do firewall indisponível. Confira o serviço na VM."}


def peer_allowed(connection, allowed_uid):
    _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return uid in (0, allowed_uid)


def create_server(manager, allowed_uid, path=SOCKET, lock_path="/run/spamfox-firewall/manager.lock"):

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(15)
            if not peer_allowed(self.connection, allowed_uid):
                return
            request = {}
            try:
                raw = self.rfile.readline(MAX_REQUEST + 1)
                if len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
                    raise FirewallAdminError("invalid", "Solicitação excede o limite.")
                request = json.loads(raw)
                with open(lock_path, "a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    result = manager.request(request)
            except Exception as error:
                result = response_error(error)
                LOG.warning(json.dumps({"event": "spamfox_firewall_failure", "code": result["code"],
                                        "actor": request.get("actor") if isinstance(request, dict) else None,
                                        "action": request.get("action") if isinstance(request, dict) else None}))
            self.wfile.write(json.dumps(result, ensure_ascii=True).encode("ascii") + b"\n")

    return socketserver.UnixStreamServer(str(path), Handler)


def serve():
    if fcntl is None or pwd is None or os.geteuid() != 0:
        raise SystemExit("--serve requires root")
    allowed_uid = pwd.getpwnam("spamfox").pw_uid
    manager = Manager()
    manager.read()
    # Reconcile a possible interruption between nft's atomic apply and file rename.
    apply_file(ALLOWLIST)

    if os.path.lexists(SOCKET):
        os.unlink(SOCKET)
    with create_server(manager, allowed_uid) as server:
        os.chmod(SOCKET, 0o660)
        server.serve_forever()


def client():
    raw = sys.stdin.buffer.readline(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST or not raw.endswith(b"\n"):
        return {"ok": False, "code": "invalid", "message": "Solicitação inválida."}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(15)
            connection.connect(SOCKET)
            connection.sendall(raw)
            with connection.makefile("rb") as stream:
                reply = stream.readline(MAX_RESPONSE + 1)
            if len(reply) > MAX_RESPONSE or not reply.endswith(b"\n"):
                raise ValueError("invalid reply")
            return json.loads(reply)
    except (OSError, ValueError):
        return {"ok": False, "code": "unavailable", "message": "Gestão do firewall indisponível. Confira spamfox-firewall-admin na VM."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.serve:
        serve()
    else:
        print(json.dumps(client(), ensure_ascii=True))
