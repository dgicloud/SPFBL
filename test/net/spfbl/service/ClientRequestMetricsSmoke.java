/* SpamFox extension to SPFBL; GPL-3.0-or-later. See licence.txt. */
package net.spfbl.service;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import net.spfbl.core.Client;
import net.spfbl.core.ClientRequestMetrics;
import net.spfbl.core.Core;
import net.spfbl.core.User;

public final class ClientRequestMetricsSmoke {
    public static void main(String[] args) throws Exception {
        Client a = Client.create("192.0.2.10/32", "cpanel.example.test", "SPFBL", "postmaster@example.test");
        Client b = Client.create("2001:db8::1/128", "postfix.example.test", "SPFBL", "postmaster@example.test");
        ClientRequestMetrics.load();
        long cacheVersion = Client.getCacheVersion();
        for (int i = 0; i < 3; i++) ClientRequestMetrics.record(a, i < 2);
        for (int i = 0; i < 2; i++) ClientRequestMetrics.record(b, i < 1);
        ClientRequestMetrics.record(null, true);
        ClientRequestMetrics.Snapshot first = ClientRequestMetrics.snapshot(Arrays.asList(a, b));
        require(first.requests == 5 && first.queries == 3, "Totals do not equal server rows");
        require(first.rows.get(a.getCIDR()).requests == 3 && first.rows.get(b.getCIDR()).requests == 2,
                "Servers with the same owner were merged");
        CountDownLatch begin = new CountDownLatch(1);
        Thread[] threads = new Thread[8];
        for (int index = 0; index < threads.length; index++) {
            threads[index] = new Thread(() -> {
                try { begin.await(); } catch (InterruptedException ex) { throw new RuntimeException(ex); }
                for (int n = 0; n < 1000; n++) ClientRequestMetrics.record(a, n % 2 == 0);
            });
            threads[index].start();
        }
        begin.countDown();
        for (Thread thread : threads) thread.join();
        ClientRequestMetrics.Snapshot counted = ClientRequestMetrics.snapshot(Arrays.asList(a, b));
        require(counted.requests == 8005 && counted.queries == 4003, "Concurrent increments were lost");
        require(Client.getCacheVersion() == cacheVersion, "Telemetry invalidated the client lookup cache");
        require(ClientRequestMetrics.store(), "Metrics did not persist");
        ClientRequestMetrics.load();
        ClientRequestMetrics.Snapshot restored = ClientRequestMetrics.snapshot(Arrays.asList(a, b));
        require(restored.requests == counted.requests && restored.queries == counted.queries
                && restored.since == counted.since, "Restart lost counters or tracking start");
        require(ClientRequestMetrics.snapshot(Arrays.asList(b)).requests == 2, "Removed clients affect current totals");

        User admin = User.create("admin-metrics@example.test", "Metrics administrator");
        admin.setLocale("pt_BR"); admin.setTimeZone("America/Sao_Paulo");
        String html = BayesAdminHandler.renderRequestMetrics(admin);
        require(html.contains("8.005") && html.contains("4.003") && html.contains("cpanel.example.test")
                && html.contains("postfix.example.test") && html.contains("Última request")
                && html.contains("America/Sao_Paulo"), "Admin server counters or timezone were not rendered");
        if (args.length > 0 && !args[0].isEmpty()) {
            String page = "<!DOCTYPE html><html lang=\"pt-BR\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                    + "<title>Consultas dos servidores · SpamFox</title><link rel=\"stylesheet\" href=\"/web/style.css\">"
                    + "<script src=\"/web/theme.js\" defer></script><body class=\"bayes-admin-page\"><main class=\"bayes-admin-shell\">"
                    + "<h1>Administração · SpamFox</h1><p>Prévia local · dados de demonstração</p>" + html + "</main></body></html>";
            Files.write(Paths.get(args[0]), page.getBytes(StandardCharsets.UTF_8));
        }
        Path file = Paths.get("./data/client-request-metrics.json");
        byte[] valid = Files.readAllBytes(file);
        byte[] broken = "{broken".getBytes(StandardCharsets.UTF_8);
        Files.write(file, broken);
        ClientRequestMetrics.load();
        require(!ClientRequestMetrics.store() && Arrays.equals(broken, Files.readAllBytes(file)), "Corrupt state was overwritten");
        require(!ClientRequestMetrics.snapshot(Arrays.asList(a)).persistenceHealthy, "Load error was not visible to admin");
        Files.write(file, valid); ClientRequestMetrics.load();

        // Exercise the actual listener hook, including an empty connection and a non-query command.
        Client local = Client.create("127.0.0.1/32", "local.example.test", "SPFBL", "postmaster@example.test");
        ServerSPFBL listener = new ServerSPFBL(0, 0, null);
        listener.setDaemon(true);
        java.lang.reflect.Field socketField = ServerSPFBL.class.getDeclaredField("SERVER");
        socketField.setAccessible(true);
        int port = ((ServerSocket) socketField.get(listener)).getLocalPort();
        listener.start();
        try {
            request(port, "VERSION");
            require(request(port, "SPF '127.0.0.1' 'sender@example.test' 'helo.example.test' 'recipient@example.test'").contains("LAN"),
                    "Native SPF request did not reach reputation processing");
            request(port, "CHECK 127.0.0.1 sender@example.test helo.example.test recipient@example.test");
            request(port, "127.0.0.1 sender@example.test helo.example.test");
            String policy = "request=smtpd_access_policy\nclient_address=127.0.0.1\nsender=sender@example.test\n"
                    + "recipient=recipient@example.test\nhelo_name=helo.example.test\ninstance=metrics-test\nprotocol_state=";
            request(port, policy + "RCPT\n");
            request(port, policy + "DATA\n");
            request(port, "");
            byte[] spamdBody = ("From: sender@example.test\r\n"
                    + "To: recipient@example.test\r\n"
                    + "Subject: binary \u00ff payload\r\n\r\nbody\u00ff").getBytes(StandardCharsets.ISO_8859_1);
            String spamd = requestSpamdWithoutEof(port, spamdBody);
            require(spamd.startsWith("SPAMD/1.0 "),
                    "SPAMD must answer after the declared byte length without waiting for EOF");
            ClientRequestMetrics.Counts live = ClientRequestMetrics.snapshot(Arrays.asList(local)).rows.get(local.getCIDR());
            require(live.requests == 7 && live.queries == 4, "Live SPF/CHECK/legacy/Postfix listener counters are incorrect");
        } finally {
            java.lang.reflect.Field running = Core.class.getDeclaredField("running");
            running.setAccessible(true); running.setBoolean(null, false);
            listener.close(); listener.join(2000);
        }
        System.out.println("PASS: per-server metrics, concurrent increments, persistence, corrupt-file preservation, admin rendering and live TCP hook.");
    }

    private static String request(int port, String line) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(5000);
            socket.getOutputStream().write((line + "\n").getBytes(StandardCharsets.UTF_8));
            socket.shutdownOutput();
            return new String(FirewallAdminHandler.readBounded(socket.getInputStream(), 16384), StandardCharsets.UTF_8);
        }
    }

    private static String requestSpamdWithoutEof(int port, byte[] message) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(2000);
            String header = "REPORT SPAMC/1.2\r\nUser: postmaster@example.test\r\nContent-length: "
                    + message.length + "\r\n\r\n";
            socket.getOutputStream().write(header.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(message);
            socket.getOutputStream().flush();
            return new String(FirewallAdminHandler.readBounded(socket.getInputStream(), 16384), StandardCharsets.ISO_8859_1);
        }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new IllegalStateException(message);
    }
}
