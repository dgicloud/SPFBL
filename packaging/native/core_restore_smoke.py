#!/usr/bin/env python3
"""Restore a synthetic SPFBL state in an isolated Docker network namespace."""

import argparse
import hashlib
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from backup_restore import BackupRestore, Layout


IMAGE = "eclipse-temurin:8-jdk@sha256:6f9f640cdc1a35e64b77daf1f48fcf7527953d9aa804916c8557e1aae954ecd5"
ADMIN_PORT = 19875


class DockerCore(object):
    def __init__(self, name):
        self.name = name

    def pause_maintenance(self):
        return False

    def resume_maintenance(self, ignored):
        return None

    def active(self):
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", self.name],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True,
        )
        return result.returncode == 0 and result.stdout.strip().lower() == "true"

    def _admin(self, command):
        shell = (
            "exec 3<>/dev/tcp/127.0.0.1/{0}; "
            "printf '%s\\n' {1} >&3; "
            "while IFS= read -r -t 0.25 line <&3; do printf '%s\\n' \"$line\"; done"
        ).format(ADMIN_PORT, shlex.quote(command))
        result = subprocess.run(
            ["docker", "exec", self.name, "bash", "-lc", shell],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
            timeout=8,
        )
        if result.returncode not in (0, 142) and not result.stdout:
            raise RuntimeError("SPFBL admin command failed: " + result.stderr.strip())
        return result.stdout

    def stop(self):
        result = self._admin("SHUTDOWN")
        if "OK" not in result:
            raise RuntimeError("SPFBL shutdown did not confirm: " + result.strip())
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if not self.active():
                return
            time.sleep(0.25)
        raise RuntimeError("isolated SPFBL process did not exit")

    def start(self):
        subprocess.run(["docker", "start", self.name], check=True, stdout=subprocess.PIPE)

    def wait_ready(self):
        deadline = time.monotonic() + 90
        last_error = ""
        while time.monotonic() < deadline:
            if self.active():
                try:
                    response = self._admin("VERSION")
                    if response.strip().startswith("SPFBL-"):
                        return response.strip()
                    last_error = response.strip()
                except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
                    last_error = str(exc)
            time.sleep(0.5)
        raise RuntimeError("isolated SPFBL did not become ready: " + last_error)


def mount(path, target, readonly=False):
    source = str(Path(path).resolve()).replace("\\", "/")
    value = "type=bind,source={0},target={1}".format(source, target)
    if readonly:
        value += ",readonly"
    return value


def run(root, repository, runtime=None):
    runtime = Path(runtime) if runtime else repository / ".audit" / "runtime"
    if not (runtime / "SPFBL.jar").is_file() or not (runtime / "lib").is_dir():
        raise RuntimeError("JAR/lib ausentes no runtime informado; gere o bundle ou packaging/audit/build-upstream.sh")
    seed = repository / ".audit" / "runtime" / "data"
    if not seed.is_dir():
        seed = runtime / "data"
    if not seed.is_dir():
        seed = root / "synthetic-empty-seed"
        seed.mkdir(parents=True)
    layout = Layout(
        app=root / "opt" / "spfbl",
        etc=root / "etc" / "had-antispam",
        state=root / "var" / "lib" / "had-antispam",
        backups=root / "backups",
    )
    current = layout.app / "current"
    (current / "release").mkdir(parents=True)
    version_path = runtime / "version"
    version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else (
        "isolated-" + hashlib.sha256((runtime / "SPFBL.jar").read_bytes()).hexdigest()[:12]
    )
    (current / "release" / "version").write_text(version, encoding="ascii")
    layout.etc.mkdir(parents=True)
    (layout.etc / "spfbl.conf").write_text(
        "log_folder=/logs/\nlog_expires=1\nlog_level=INFO\nwhois_server_br=NONE\n"
        "admin_port={0}\nspfbl_port=19877\ndnsbl_port=19553\nhttp_port=18080\nhttps_port=18443\n"
        "inexistent_expires=365\nudp_max=512\n".format(ADMIN_PORT),
        encoding="ascii",
    )
    layout.state.mkdir(parents=True)
    shutil.copytree(str(seed), str(layout.state / "data"))
    (layout.state / "history").mkdir()
    logs = root / "logs"
    logs.mkdir()
    name = "had-antispam-restore-" + uuid.uuid4().hex[:10]
    service = DockerCore(name)
    manager = BackupRestore(layout, service, owner_normalizer=lambda etc, state: None)

    subprocess.run([
        "docker", "run", "--detach", "--name", name, "--network", "none",
        "--workdir", "/work", "--env", "HOME=/work",
        "--mount", mount(layout.state, "/work"),
        "--mount", mount(layout.etc / "spfbl.conf", "/work/spfbl.conf", readonly=True),
        "--mount", mount(runtime, "/opt/runtime", readonly=True),
        "--mount", mount(logs, "/logs"),
        IMAGE, "java", "-Xms128m", "-Xmx512m", "-cp",
        "/opt/runtime/SPFBL.jar:/opt/runtime/lib/*", "net.spfbl.core.Core",
    ], check=True, stdout=subprocess.PIPE)
    try:
        service.wait_ready()
        baseline_add = service._admin("CLIENT ADD 127.0.0.1/32 baseline.audit.test SPFBL postmaster@baseline.audit.test")
        if "ADDED" not in baseline_add:
            raise RuntimeError("Could not seed baseline client: " + baseline_add.strip())
        block_add = service._admin("BLOCK ADD 192.0.2.25")
        if "ADDED" not in block_add:
            raise RuntimeError("Could not seed baseline block: " + block_add.strip())
        baseline_cidr = service._admin("BLOCK FIND 192.0.2.25")
        if "CIDR=" not in baseline_cidr:
            raise RuntimeError("Core did not return the synthetic CIDR block: " + baseline_cidr.strip())
        dict_add = service._admin("DICTIONARY ADD pt-BR hadrestorebaseline")
        if "ADDED" not in dict_add:
            raise RuntimeError("Could not seed baseline dictionary: " + dict_add.strip())

        archive, digest, manifest = manager.backup()
        baseline_files = {entry["path"]: entry for entry in manifest["files"]}
        cidr_path = "var/lib/had-antispam/data/cidr.txt"
        if cidr_path not in baseline_files:
            raise RuntimeError("Core did not persist the synthetic baseline CIDR into cidr.txt")
        if not service.active():
            raise RuntimeError("backup did not restart the isolated core")
        key_before = hashlib.sha256((layout.state / "data" / "server.key").read_bytes()).hexdigest()
        if "baseline.audit.test" not in service._admin("CLIENT SHOW SPFBL"):
            raise RuntimeError("baseline client missing after backup restart")

        changed_add = service._admin("CLIENT ADD 127.0.0.2/32 changed.audit.test SPFBL postmaster@changed.audit.test")
        if "ADDED" not in changed_add:
            raise RuntimeError("Could not seed post-backup client: " + changed_add.strip())
        changed_block = service._admin("BLOCK ADD 192.0.2.26")
        if "ADDED" not in changed_block:
            raise RuntimeError("Could not seed post-backup block: " + changed_block.strip())
        changed_dict = service._admin("DICTIONARY ADD pt-BR hadrestorechanged")
        if "ADDED" not in changed_dict:
            raise RuntimeError("Could not seed post-backup dictionary: " + changed_dict.strip())

        restored = manager.restore(archive, confirm=True)
        if not service.active():
            raise RuntimeError("restore did not restart the isolated core")
        clients = service._admin("CLIENT SHOW SPFBL")
        dictionary = service._admin("DICTIONARY SHOW SET")
        key_after = hashlib.sha256((layout.state / "data" / "server.key").read_bytes()).hexdigest()
        if "baseline.audit.test" not in clients or "changed.audit.test" in clients:
            raise RuntimeError("client map does not match the pre-restore snapshot: " + clients)
        if "hadrestorebaseline" not in dictionary or "hadrestorechanged" in dictionary:
            raise RuntimeError("dictionary list does not match the pre-restore snapshot: " + dictionary)
        cidr_contents = (layout.state / "data" / "cidr.txt").read_text(encoding="utf-8")
        cidr_after = service._admin("BLOCK FIND 192.0.2.25")
        if "192.0.2.25/32" not in cidr_contents or "192.0.2.26/32" in cidr_contents \
                or "CIDR=192.0.2.25/32" not in cidr_after:
            raise RuntimeError("CIDR list did not reload from the pre-restore snapshot: {0!r}; {1!r}".format(
                cidr_contents, cidr_after))
        safety = manager.verify(restored["safety_archive"])
        safety_files = {entry["path"]: entry for entry in safety["manifest"]["files"]}
        if safety_files.get(cidr_path, {}).get("sha256") == baseline_files[cidr_path]["sha256"]:
            raise RuntimeError("pre-restore safety snapshot did not capture the post-backup CIDR change")
        if key_before != key_after:
            raise RuntimeError("server.key changed across restore")
        print("PASS core restore: version={0}, archived_files={1}, sha256={2}".format(
            manifest["source_version"], len(manifest["files"]), digest))
        print("PASS restored client.map, CIDR list, dictionary and ticket key; post-snapshot changes absent")
        print("PASS recovery snapshot: {0}".format(restored["safety_archive"]))
        return 0
    finally:
        subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-temp", action="store_true", help="preserva o diretório local após o teste")
    parser.add_argument("--runtime", help="diretório com o JAR/lib/data-seed; por padrão usa .audit/runtime")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    temporary = tempfile.TemporaryDirectory(prefix="had-antispam-core-restore-")
    root = Path(temporary.name)
    try:
        return run(root, repository, runtime=args.runtime)
    finally:
        if args.keep_temp:
            print("Temporary fixture: {0}".format(root))
            temporary._finalizer.detach()
        else:
            temporary.cleanup()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        raise SystemExit("core restore smoke failed: {0}".format(exc))
