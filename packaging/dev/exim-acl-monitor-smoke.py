#!/usr/bin/env python3
"""Exercise the HAD RCPT/DATA monitor and ticket feedback path with fake SMTP."""

from __future__ import print_function

import os
import grp
import io
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch


PRODUCTION_SOCKET = "/run/had-antispam/monitor.sock"
RESPONSE = b"CONTINUE|decision|LAN|1"
TEST_IP = "192.0.2.25"
ROOT = Path(__file__).resolve().parents[2]
ACL_FILE = ROOT / "integrations" / "cpanel" / "exim" / "acl-rcpt-monitor.conf"
DATA_ACL_FILE = ROOT / "integrations" / "cpanel" / "exim" / "acl-data-header-monitor.conf"
sys.path.insert(0, str(ROOT / "integrations" / "cpanel"))
import had_antispam_feedback as feedback_cli  # noqa: E402


class ReplyServer(threading.Thread):
    def __init__(self, path, expected_connections, response=RESPONSE, responses=None, delay=0):
        threading.Thread.__init__(self, daemon=True)
        self.path = path
        self.expected_connections = expected_connections
        self.response = response
        self.responses = responses
        self.delay = delay
        self.requests = []
        self.error = None

    def run(self):
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stage = "bind"
        try:
            server.bind(self.path)
            os.chmod(self.path, 0o660)
            server.listen(self.expected_connections)
            server.settimeout(8)
            for _ in range(self.expected_connections):
                stage = "accept"
                try:
                    connection, _ = server.accept()
                except socket.timeout:
                    break
                with connection:
                    connection.settimeout(5)
                    chunks = []
                    stage = "read"
                    while True:
                        chunk = connection.recv(1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    self.requests.append(b"".join(chunks))
                    if self.delay:
                        stage = "delay"
                        time.sleep(self.delay)
                    response = (
                        self.responses[len(self.requests) - 1]
                        if self.responses is not None
                        else self.response
                    )
                    try:
                        stage = "write"
                        connection.sendall(response)
                    except OSError:
                        # Expected for the timeout case after Exim closes its socket.
                        pass
        except Exception as exc:
            self.error = "%s: %r" % (stage, exc)
        finally:
            server.close()
            try:
                os.unlink(self.path)
            except OSError:
                pass


class TTYInput(io.StringIO):
    def isatty(self):
        return True


def find_exim():
    exim = shutil.which("exim4") or shutil.which("exim")
    if not exim:
        raise RuntimeError("Exim binary not found")
    return exim


def write_test_config(directory, socket_path, exim_user, exim_group, include_header=False):
    os.chmod(directory, 0o755)
    snippet = ACL_FILE.read_text(encoding="utf-8")
    if snippet.count(PRODUCTION_SOCKET) != 1:
        raise AssertionError("Production socket path must occur exactly once in ACL")
    snippet = snippet.replace(PRODUCTION_SOCKET, socket_path)
    data_snippet = ""
    if include_header:
        data_snippet = DATA_ACL_FILE.read_text(encoding="utf-8")
        if data_snippet.count(PRODUCTION_SOCKET) != 1:
            raise AssertionError("Production socket path must occur exactly once in DATA ACL")
        data_snippet = data_snippet.replace(PRODUCTION_SOCKET, socket_path)
        # `-bh` does not set $interface_port; simulate the production port-25 gate.
        data_snippet = data_snippet.replace(
            "condition = ${if eq{$interface_port}{25}{true}{false}}",
            "condition = ${if eq{25}{25}{true}{false}}",
        )
    config = (
        "exim_user = %s\nexim_group = %s\n" % (exim_user, exim_group)
        + "primary_hostname = had-acl-test.invalid\n"
        "qualify_domain = example.test\n"
        "hostlist recent_authed_mail_ips = 192.0.2.250\n"
        "acl_smtp_mail = had_test_mail\n"
        "acl_smtp_rcpt = had_test_rcpt\n"
        "acl_smtp_data = had_test_data\n"
        "\nbegin acl\n"
        "had_test_mail:\n"
        "  warn\n"
        "    logwrite = HAD_TEST MAIL_STATE [$acl_m_had_antispam_result]\n"
        "  accept\n"
        "had_test_rcpt:\n"
        + snippet
        + "  accept\n"
        + "had_test_data:\n"
        + data_snippet
        + "  warn\n"
        + "    logwrite = HAD_TEST DATA_TICKETS [$acl_m_had_antispam_ticket_set]\n"
        + "  accept\n"
        "\nbegin routers\n"
        "\nbegin transports\n"
        "\nbegin retry\n"
        "\nbegin rewrite\n"
        "\nbegin authenticators\n"
    )
    path = os.path.join(directory, "exim.conf")
    with open(path, "w") as config_file:
        config_file.write(config)
    os.chmod(path, 0o600)
    return path


def exim_identity(exim):
    result = subprocess.run(
        [exim, "-bP", "exim_user", "exim_group"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=5,
    )
    if result.returncode:
        raise RuntimeError("Could not read Exim runtime identity: %s" % result.stderr.strip())
    values = {}
    for line in result.stdout.splitlines():
        if " = " in line:
            key, value = line.split(" = ", 1)
            values[key.strip()] = value.strip()
    user = values.get("exim_user")
    group = values.get("exim_group")
    if not user or not group:
        raise RuntimeError("Exim user/group were missing from -bP output")
    try:
        group_id = grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise RuntimeError("Exim primary group was not found: %s" % group) from exc
    return user, group, group_id


def start_server(server, group_id):
    server.start()
    for _ in range(100):
        if os.path.exists(server.path):
            os.chown(server.path, 0, group_id)
            return
        time.sleep(0.01)
    raise RuntimeError("UDS server did not create its socket")


def run_exim(exim, config_path, arguments, smtp_input=None, timeout=15):
    command = [exim, "-C", config_path] + arguments
    result = subprocess.run(
        command,
        input=smtp_input,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=timeout,
    )
    output = result.stdout + result.stderr
    if result.returncode:
        raise RuntimeError(
            "Exim command failed (exit=%s):\n%s" % (result.returncode, output[-5000:])
        )
    return output


def fake_smtp(*commands):
    return "\n".join(commands + ("QUIT", "" ))


def check(condition, message, output=""):
    if not condition:
        raise AssertionError("%s\n%s" % (message, output[-5000:]))


def main():
    exim = find_exim()
    exim_user, exim_group, group_id = exim_identity(exim)
    version_output = subprocess.run(
        [exim, "-bV"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=5,
    )
    check(version_output.returncode == 0, "Could not query Exim version", version_output.stderr)
    version = next(
        (line.strip() for line in version_output.stdout.splitlines() if "Exim version" in line),
        "Exim version unknown",
    )

    temp_parent = os.environ.get("HAD_EXIM_TEST_TMPDIR")
    temp_prefix = (
        "exim.conf.had-antispam-acl-smoke-" if temp_parent else "had-exim-acl-smoke-"
    )
    with tempfile.TemporaryDirectory(prefix=temp_prefix, dir=temp_parent) as directory:
        socket_path = os.path.join(directory, "adapter.sock")
        config_path = write_test_config(directory, socket_path, exim_user, exim_group)
        # Syntax-check the exact ACL snippet in a disposable configuration.
        run_exim(exim, config_path, ["-bV"])

        server = ReplyServer(socket_path, 4)
        start_server(server, group_id)
        smtp_input = fake_smtp(
            "EHLO mx-a.example.test",
            "MAIL FROM:<sender-one@example.test>",
            "RCPT TO:<one@example.test>",
            "RCPT TO:<two@example.test>",
            "RSET",
            "EHLO mx-b.example.test",
            "MAIL FROM:<sender-two@example.test>",
            "RCPT TO:<three@example.test>",
            "RSET",
            "MAIL FROM:<>",
            "RCPT TO:<four@example.test>",
        )
        output = run_exim(exim, config_path, ["-bh", TEST_IP], smtp_input)
        server.join(10)
        expected = [
            b"192.0.2.25\x1fsender-one@example.test\x1fmx-a.example.test\x1fone@example.test\x1fnull",
            b"192.0.2.25\x1fsender-one@example.test\x1fmx-a.example.test\x1ftwo@example.test\x1fnull",
            b"192.0.2.25\x1fsender-two@example.test\x1fmx-b.example.test\x1fthree@example.test\x1fnull",
            b"192.0.2.25\x1f\x1fmx-b.example.test\x1ffour@example.test\x1fnull",
        ]
        check(not server.is_alive(), "UDS server did not finish")
        check(server.error is None, "UDS server error: %r" % server.error, output)
        check(
            server.requests == expected,
            "SMTP envelope fields or RSET state differ: %r" % server.requests,
            output,
        )
        check(
            len(re.findall(r"(?m)^LOG: SFOX MONITOR RCPT CONTINUE\|decision\|LAN\|1$", output)) == 4,
            "Each recipient must be observed and logged exactly once",
            output,
        )
        check(
            len(re.findall(r"(?m)^LOG: HAD_TEST MAIL_STATE \[\]$", output)) == 3,
            "Message ACL state was not empty at each MAIL transaction",
            output,
        )
        check(output.count("250 Accepted") >= 4, "MONITOR changed RCPT acceptance", output)
        print("PASS: %s; RCPT fields, multiple recipients, null sender, RSET, and MAIL reset." % version)

        missing_socket = os.path.join(directory, "missing.sock")
        missing_config = write_test_config(directory, missing_socket, exim_user, exim_group)
        output = run_exim(
            exim,
            missing_config,
            ["-bh", TEST_IP],
            fake_smtp(
                "EHLO mx.example.test",
                "MAIL FROM:<sender@example.test>",
                "RCPT TO:<recipient@example.test>",
            ),
        )
        check(
            "SFOX MONITOR RCPT CONTINUE|socket_error" in output,
            "Missing socket did not use fail-open fallback",
            output,
        )
        check("250 Accepted" in output, "Missing socket blocked the recipient", output)
        print("PASS: missing socket fell back and Exim accepted the RCPT.")

        timeout_socket = os.path.join(directory, "timeout.sock")
        timeout_config = write_test_config(directory, timeout_socket, exim_user, exim_group)
        delayed_server = ReplyServer(timeout_socket, 1, delay=1.4)
        start_server(delayed_server, group_id)
        output = run_exim(
            exim,
            timeout_config,
            ["-bh", TEST_IP],
            fake_smtp(
                "EHLO mx.example.test",
                "MAIL FROM:<sender@example.test>",
                "RCPT TO:<recipient@example.test>",
            ),
            timeout=8,
        )
        delayed_server.join(5)
        check(not delayed_server.is_alive(), "Timeout-test socket server did not finish")
        check(
            "SFOX MONITOR RCPT CONTINUE|socket_error" in output,
            "Exim readsocket timeout did not use fail-open fallback",
            output,
        )
        check("250 Accepted" in output, "Socket timeout blocked the recipient", output)
        print("PASS: readsocket timeout fell back and Exim accepted the RCPT.")

        no_ticket_socket = os.path.join(directory, "no-ticket.sock")
        no_ticket_config = write_test_config(
            directory, no_ticket_socket, exim_user, exim_group, include_header=True
        )
        no_ticket_server = ReplyServer(
            no_ticket_socket,
            2,
            responses=(
                b"CONTINUE|decision|LAN|1|-",
                b"CONTINUE|header|no_ticket|0",
            ),
        )
        start_server(no_ticket_server, group_id)
        no_ticket_output = run_exim(
            exim,
            no_ticket_config,
            ["-bh", "127.0.0.1"],
            fake_smtp(
                "EHLO had-data-smoke.invalid",
                "MAIL FROM:<>",
                "RCPT TO:<root@localhost>",
                "DATA",
                "From: had-data-smoke@example.invalid",
                "Message-ID: <had-data-smoke@example.invalid>",
                "Date: Fri, 02 Oct 2026 10:00:00 -0300",
                "Subject: HAD DATA ACL smoke",
                "",
                ".",
            ),
        )
        no_ticket_server.join(10)
        check(not no_ticket_server.is_alive(), "No-ticket DATA server did not finish", no_ticket_output)
        check(no_ticket_server.error is None, "No-ticket DATA server failed", no_ticket_output)
        check(
            "SFOX MONITOR DATA CONTINUE|header|no_ticket|0" in no_ticket_output,
            "DATA ACL did not fail open when no RCPT produced a ticket",
            no_ticket_output,
        )
        check("250 Accepted" in no_ticket_output, "No-ticket DATA hook changed SMTP acceptance", no_ticket_output)
        check(
            len(no_ticket_server.requests) == 2
            and no_ticket_server.requests[1].startswith(b"HEADER\x1f\x1f"),
            "No-ticket DATA record did not preserve empty ticket state",
            no_ticket_output,
        )
        print("PASS: DATA ACL handled empty ticket state in MONITOR and fake SMTP continued.")

        ticket_socket = os.path.join(directory, "ticket.sock")
        ticket_config = write_test_config(
            directory, ticket_socket, exim_user, exim_group, include_header=True
        )
        feedback_tokens = (b"a" * 44, b"b" * 44, b"c" * 44, b"d" * 44)
        ticket_values = tuple(
            b"CONTINUE|decision|" + decision + b"|1|" + token + b"|" + decision + b" " + token
            for decision, token in zip((b"PASS", b"WHITE", b"FLAG", b"HOLD"), feedback_tokens)
        )
        header_reply = b"CONTINUE|header|CLEAR|1"
        ticket_responses = (
            ticket_values[0], ticket_values[1], header_reply,
            ticket_values[2], header_reply, ticket_values[3], header_reply,
        )
        ticket_server = ReplyServer(
            ticket_socket,
            len(ticket_responses),
            responses=ticket_responses,
        )
        start_server(ticket_server, group_id)
        ticket_smtp = fake_smtp(
            "EHLO mx-one.example.test",
            "MAIL FROM:<sender-one@example.test>",
            "RCPT TO:<one@example.test>",
            "RCPT TO:<two@example.test>",
            "DATA",
            "From: sender-one@example.test",
            "Reply-To: reply@example.test",
            "Message-ID: <one@example.test>",
            "Date: Fri, 02 Oct 2026 10:00:00 -0300",
            "List-Unsubscribe: <mailto:unsubscribe@example.test>",
            "Subject: first message",
            "X-HAD-AntiSpam-Ticket: FLAG forged-ticket-on-multi-recipient",
            "",
            ".",
            "RSET",
            "MAIL FROM:<sender-two@example.test>",
            "RCPT TO:<three@example.test>",
            "DATA",
            "From: sender-two@example.test",
            "Message-ID: <two@example.test>",
            "Date: Fri, 02 Oct 2026 10:01:00 -0300",
            "Subject: second message",
            "",
            ".",
            "RSET",
            "MAIL FROM:<>",
            "RCPT TO:<four@example.test>",
            "DATA",
            "From: sender-three@example.test",
            "Message-ID: <three@example.test>",
            "Date: Fri, 02 Oct 2026 10:02:00 -0300",
            "Subject: third message",
            "",
            ".",
        )
        output = run_exim(exim, ticket_config, ["-bh", TEST_IP, "-d+acl"], ticket_smtp)
        ticket_log_output = re.sub(
            r"(?m)^LOG: MAIN\n  (HAD AntiSpam|HAD_TEST)",
            r"LOG: \1",
            output,
        )
        ticket_server.join(10)
        check(not ticket_server.is_alive(), "Ticket UDS server did not finish", output)
        check(ticket_server.error is None, "Ticket UDS server error: %r" % ticket_server.error, output)
        data_ticket_lines = re.findall(
            r"(?m)^LOG: HAD_TEST DATA_TICKETS \[(.*)\]$", ticket_log_output
        )
        check(
            data_ticket_lines == [
                (feedback_tokens[0] + b";" + feedback_tokens[1]).decode("ascii"),
                feedback_tokens[2].decode("ascii"),
                feedback_tokens[3].decode("ascii"),
            ],
            "DATA did not receive the accumulated per-message ticket set: %r" % data_ticket_lines,
            output,
        )
        first_removed_section = output.split("Headers removed by DATA ACL:", 1)[1]
        first_removed_section = first_removed_section.split("Headers removed by DATA ACL:", 1)[0]
        first_removed_section = first_removed_section.split("Headers added by DATA ACL:", 1)[0]
        check(
            "forged-ticket-on-multi-recipient" in first_removed_section,
            "DATA ACL did not remove the sender's feedback header on a multi-recipient message: %r"
            % first_removed_section,
            output,
        )
        monitor_lines = re.findall(
            r"(?m)^LOG: SFOX MONITOR RCPT (.*)$", ticket_log_output
        )
        check(len(monitor_lines) == 4, "Expected one sanitized monitor log per RCPT", output)
        check(
            all(ticket.decode("ascii") not in "\n".join(monitor_lines) for ticket in feedback_tokens),
            "A feedback ticket appeared in the monitor log",
            output,
        )
        data_header_lines = re.findall(
            r"(?m)^LOG: SFOX MONITOR DATA (.*)$", ticket_log_output
        )
        check(
            data_header_lines == [
                "CONTINUE|header|CLEAR|1",
                "CONTINUE|header|CLEAR|1",
                "CONTINUE|header|CLEAR|1",
            ],
            "DATA HEADER results were not reduced to safe monitor fields",
            output,
        )
        feedback_header_lines = re.findall(
            r"(?m)^LOG: SFOX MONITOR FEEDBACK-TICKET eligible single-recipient$",
            ticket_log_output,
        )
        check(
            len(feedback_header_lines) == 2,
            "Only single-recipient incoming messages should receive the feedback header",
            output,
        )
        header_records = [record for record in ticket_server.requests if record.startswith(b"HEADER\x1f")]
        check(len(header_records) == 3, "DATA did not send one HEADER record per message", output)
        split_header_records = [record.split(b"\x1f") for record in header_records]
        check(
            [record[1] for record in split_header_records]
            == [feedback_tokens[0] + b";" + feedback_tokens[1], feedback_tokens[2], feedback_tokens[3]],
            "DATA HEADER did not carry the current message ticket set",
            output,
        )
        check(
            all(len(record) == 21 for record in split_header_records)
            and b"sender-one@example.test" in split_header_records[0][3]
            and b"reply@example.test" in split_header_records[0][4]
            and b"<one@example.test>" in split_header_records[0][5]
            and b"unsubscribe@example.test" in split_header_records[0][9]
            and split_header_records[0][7]
            and b"first message" in split_header_records[0][10]
            and b"second message" in split_header_records[1][10]
            and b"third message" in split_header_records[2][10]
            and [record[16] for record in split_header_records]
            == [b"WHITE", b"FLAG", b"HOLD"],
            "DATA HEADER metadata or local categorical signals did not match each message",
            output,
        )
        check(output.count("250 Accepted") >= 4, "Ticket handoff changed RCPT acceptance", output)
        print("PASS: RCPT tickets reached DATA HEADER; feedback header was limited to one recipient and stayed out of MONITOR logs.")

        feedback_socket = os.path.join(directory, "feedback.sock")
        feedback_config = write_test_config(
            directory, feedback_socket, exim_user, exim_group, include_header=True
        )
        feedback_ticket = b"f" * 44
        feedback_server = ReplyServer(
            feedback_socket,
            2,
            responses=(
                b"CONTINUE|decision|FLAG|1|" + feedback_ticket + b"|FLAG " + feedback_ticket,
                header_reply,
            ),
        )
        start_server(feedback_server, group_id)
        feedback_output = run_exim(
            exim,
            feedback_config,
            ["-bh", TEST_IP, "-d+acl"],
            fake_smtp(
                "EHLO mx-feedback.example.test",
                "MAIL FROM:<sender@example.test>",
                "RCPT TO:<one@example.test>",
                "DATA",
                "From: sender@example.test",
                "X-HAD-AntiSpam-Ticket: PASS forged-ticket-from-sender",
                "Message-ID: <feedback@example.test>",
                "Date: Fri, 02 Oct 2026 10:03:00 -0300",
                "Subject: feedback smoke",
                "",
                ".",
            ),
        )
        feedback_server.join(10)
        check(not feedback_server.is_alive(), "Feedback UDS server did not finish", feedback_output)
        check(feedback_server.error is None, "Feedback UDS server error: %r" % feedback_server.error, feedback_output)
        added_section = feedback_output.split("Headers added by DATA ACL:", 1)[-1]
        added_section = added_section.split("calling local_scan()", 1)[0]
        added_headers = re.findall(r"(?m)^ +X-HAD-AntiSpam-Ticket: (.*)$", added_section)
        check(
            added_headers == ["FLAG " + feedback_ticket.decode("ascii")],
            "Exim did not replace a sender-supplied feedback ticket with the core ticket",
            feedback_output,
        )
        check("forged-ticket-from-sender" not in added_section,
              "Sender-supplied feedback ticket survived header replacement", feedback_output)
        check("250 OK" in feedback_output, "Feedback-ticket header changed SMTP acceptance", feedback_output)
        print("PASS: DATA replaced a sender-supplied feedback header with the validated core ticket without changing acceptance.")

        # Carry the ticket that Exim actually inserted through the operator CLI,
        # local HMAC audit and native SPAM command to a disposable local core.
        message_path = os.path.join(directory, "feedback-message.eml")
        with open(message_path, "wb") as message_file:
            message_file.write(
                b"From: sender@example.test\r\n"
                + b"X-HAD-AntiSpam-Ticket: " + added_headers[0].encode("ascii")
                + b"\r\n\r\nTest body\r\n"
            )
        os.chmod(message_path, 0o600)
        feedback_core = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        feedback_core.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        feedback_core.bind(("127.0.0.1", 0))
        feedback_core.listen(1)
        feedback_core.settimeout(5)
        feedback_commands = []

        def receive_feedback():
            try:
                connection, _ = feedback_core.accept()
                with connection:
                    connection.settimeout(2)
                    chunks = []
                    while True:
                        chunk = connection.recv(1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                        if b"\n" in chunk:
                            break
                    feedback_commands.append(b"".join(chunks))
                    connection.sendall(b"OK\n")
            except Exception as exc:
                feedback_commands.append(exc)

        feedback_thread = threading.Thread(target=receive_feedback, daemon=True)
        feedback_thread.start()
        feedback_config = os.path.join(directory, "client.conf")
        with open(feedback_config, "w") as config_file:
            config_file.write(
                "HAD_SPFBL_HOST=127.0.0.1\nHAD_SPFBL_PORT=%s\n"
                % feedback_core.getsockname()[1]
            )
        os.chmod(feedback_config, 0o600)
        audit_key_path = os.path.join(directory, "feedback-hmac.key")
        original_load_audit_key = feedback_cli.load_or_create_audit_key

        class FakeSyslog(object):
            LOG_NOTICE = 5

            def __init__(self):
                self.events = []

            def syslog(self, priority, message):
                self.events.append((priority, message))

        fake_syslog = FakeSyslog()
        feedback_stdout = io.StringIO()
        feedback_stderr = io.StringIO()
        with patch.object(
            feedback_cli,
            "load_or_create_audit_key",
            lambda: original_load_audit_key(audit_key_path),
        ):
            with patch.dict("sys.modules", {"syslog": fake_syslog}):
                with patch("sys.stdin", TTYInput("s\n")):
                    with patch("sys.stdout", feedback_stdout), patch("sys.stderr", feedback_stderr):
                        feedback_status = feedback_cli.main(
                            ["spam", message_path, "--config", feedback_config]
                        )
        feedback_thread.join(5)
        feedback_core.close()
        expected_feedback = b"SPAM " + feedback_ticket + b"\n"
        check(not feedback_thread.is_alive(), "Feedback core did not finish", feedback_output)
        check(feedback_status == 0, "Feedback CLI did not accept the disposable core ACK")
        check(feedback_commands == [expected_feedback],
              "Exim ticket did not reach the core as one SPAM command: %r" % feedback_commands)
        check(len(fake_syslog.events) == 1, "Feedback CLI did not emit one audit event")
        audit_message = fake_syslog.events[0][1]
        expected_ticket_id = feedback_cli.feedback_ticket_id(
            feedback_ticket.decode("ascii"),
            original_load_audit_key(audit_key_path),
        )
        check("ticket_id=" + expected_ticket_id in audit_message,
              "Feedback audit event omitted its keyed ticket fingerprint")
        check(feedback_ticket.decode("ascii") not in audit_message,
              "Raw feedback ticket appeared in the audit event")
        check(
            feedback_ticket.decode("ascii") not in feedback_stdout.getvalue()
            and feedback_ticket.decode("ascii") not in feedback_stderr.getvalue(),
            "Raw feedback ticket appeared in CLI output",
        )
        print("PASS: Exim-issued ticket passed through operator CLI, HMAC-only audit, and one SPAM command to the disposable core.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
