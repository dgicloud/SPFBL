/* SpamFox extension to SPFBL; GPL-3.0-or-later. See licence.txt. */
package net.spfbl.service;

import com.sun.net.httpserver.HttpServer;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicInteger;
import javax.json.Json;
import javax.json.JsonObject;
import net.spfbl.core.Core;
import net.spfbl.core.Server;
import net.spfbl.core.User;

/** Real HTTP smoke against existing SPFBL login cookies, with a harmless RPC backend. */
public final class FirewallAdminSmoke {
    static JsonObject state() {
        return Json.createObjectBuilder().add("ok", true).add("active", true).add("synchronized", true)
                .add("revision", "test-revision").add("entries", Json.createArrayBuilder()
                .add(Json.createObjectBuilder().add("cidr", "192.0.2.10/32").add("description", "Main cPanel"))
                .add(Json.createObjectBuilder().add("cidr", "2001:db8::1/128").add("description", "<script>alert(1)</script>"))).build();
    }

    public static void main(String[] args) throws Exception {
        Core.setAdminEmail("admin@example.test");
        User.create("admin@example.test", "Administrator");
        User.create("postmaster@example.test", "Customer");
        String admin = cookie("admin@example.test");
        String customer = cookie("postmaster@example.test");
        AtomicInteger changes = new AtomicInteger();
        FirewallAdminHandler handler = new FirewallAdminHandler(false, request -> {
            if ("list".equals(request.getString("action"))) return state();
            require("admin@example.test".equals(request.getString("actor")), "Wrong audit actor");
            changes.incrementAndGet();
            return Json.createObjectBuilder().add("ok", true).build();
        });
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/admin/firewall", handler);
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        try {
            require(request(base, "GET", "/admin/firewall/", null, null, true).status == 401, "Anonymous access allowed");
            require(request(base, "GET", "/admin/firewall/", customer, null, true).status == 403, "Customer firewall access allowed");
            require(request(base, "GET", "/admin/firewall/", admin, null, false).status == 403, "Insecure access allowed");
            Reply page = request(base, "GET", "/admin/firewall/", admin, null, true);
            require(page.status == 200 && page.body.contains("Adicionar IP/CIDR") && page.body.contains("Salvar alteração")
                    && page.body.contains("Confirmo a remoção"), "CRUD controls missing");
            require(!page.body.contains("<script>alert(1)</script>") && page.body.contains("&lt;script&gt;"), "Stored description was not escaped");
            require(page.cache.contains("no-store"), "Admin page can be cached");
            String csrf = page.body.split("name=\"csrf\" value=\"")[1].split("\"")[0];
            String body = "action=add&cidr=192.0.2.11&revision=test-revision&csrf=" + csrf;
            require(request(base, "POST", "/admin/firewall/change", admin, "action=add&csrf=bad", true).status == 403, "Invalid CSRF allowed");
            require(request(base, "POST", "/admin/firewall/change", customer, body, true).status == 403, "Customer mutation allowed");
            require(changes.get() == 0, "Denied request reached privileged backend");
            require(request(base, "POST", "/admin/firewall/change", admin, body, true).status == 303, "Valid admin change failed");
            require(changes.get() == 1, "Change did not reach backend exactly once");
            require(request(base, "POST", "/admin/firewall/change", admin, body, true).status == 403, "Replayed CSRF accepted");
            require(changes.get() == 1, "Replayed request changed firewall");
            try {
                FirewallAdminHandler.parseForm("action=add&action=delete".getBytes(StandardCharsets.UTF_8));
                throw new IllegalStateException("Duplicate form fields allowed");
            } catch (IllegalArgumentException expected) { }
            if (args.length > 0 && !args[0].isEmpty()) {
                Files.write(Paths.get(args[0]), page.body.getBytes(StandardCharsets.UTF_8));
            }
        } finally { server.stop(0); }
        System.out.println("PASS: firewall CRUD renders; SPFBL admin auth, HTTPS, CSRF and replay protection enforce the privileged boundary.");
    }

    static String cookie(String email) throws Exception {
        return "login=" + Server.encrypt(Server.getNewTicketDate() + " " + email + " 127.0.0.1");
    }

    static Reply request(String base, String method, String path, String cookie, String body, boolean https) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(base + path).openConnection();
        connection.setInstanceFollowRedirects(false);
        connection.setConnectTimeout(2000); connection.setReadTimeout(5000);
        connection.setRequestMethod(method);
        if (https) connection.setRequestProperty("X-Forwarded-Proto", "https");
        if (cookie != null) connection.setRequestProperty("Cookie", cookie);
        if (body != null) {
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setDoOutput(true);
            try (java.io.OutputStream stream = connection.getOutputStream()) { stream.write(body.getBytes(StandardCharsets.UTF_8)); }
        }
        int status = connection.getResponseCode();
        java.io.InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
        String text = stream == null ? "" : new String(FirewallAdminHandler.readBounded(stream, 512 * 1024), StandardCharsets.UTF_8);
        if (stream != null) stream.close();
        String cache = connection.getHeaderField("Cache-Control");
        connection.disconnect();
        return new Reply(status, text, cache == null ? "" : cache);
    }

    static class Reply {
        final int status; final String body, cache;
        Reply(int status, String body, String cache) { this.status = status; this.body = body; this.cache = cache; }
    }
    static void require(boolean value, String message) { if (!value) throw new IllegalStateException(message); }
}
