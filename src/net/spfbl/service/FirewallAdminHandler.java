/*
 * SpamFox extension to SPFBL. Distributed under the GNU General Public
 * License, version 3 or later; see licence.txt and the SPFBL attribution.
 */
package net.spfbl.service;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import net.spfbl.core.Core;
import net.spfbl.core.Server;
import net.spfbl.core.User;
import org.apache.commons.lang3.StringEscapeUtils;

/** Admin-only UI for the distribution's restricted firewall manager. */
final class FirewallAdminHandler implements HttpHandler {
    private static final String PAGE = "/admin/firewall/";
    private static final String CHANGE = PAGE + "change";
    private static final Set<String> FIELDS = new HashSet<>(Arrays.asList(
            "csrf", "action", "cidr", "original", "description", "revision", "confirm"));
    private final boolean secured;
    private final Backend backend;

    interface Backend { JsonObject request(JsonObject request) throws IOException; }

    FirewallAdminHandler(boolean secured) {
        this(secured, new LocalBackend());
    }

    FirewallAdminHandler(boolean secured, Backend backend) {
        this.secured = secured;
        this.backend = backend;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        InetAddress peer = exchange.getRemoteAddress().getAddress();
        boolean https = secured || (peer != null && peer.isLoopbackAddress()
                && "https".equalsIgnoreCase(exchange.getRequestHeaders().getFirst("X-Forwarded-Proto")));
        if (!https) { send(exchange, 403, "Esta área exige HTTPS."); return; }
        User user = ServerHTTP.getAuthenticatedUser(exchange, true);
        if (user == null || !user.isAdmin()) {
            String login = Core.getAdminEmail();
            send(exchange, user == null ? 401 : 403, "<h1>Acesso restrito</h1><p>Entre com a conta administradora.</p>"
                    + (login == null ? "" : "<a href=\"/" + escape(login) + "\">Entrar como administrador</a>"));
            return;
        }
        String path = exchange.getRequestURI().getPath();
        if ("/admin/firewall".equals(path) && "GET".equals(exchange.getRequestMethod())) {
            redirect(exchange, PAGE); return;
        }
        if (PAGE.equals(path) && "GET".equals(exchange.getRequestMethod())) {
            display(exchange, user, null, 200); return;
        }
        if (!CHANGE.equals(path)) { send(exchange, 404, "Não encontrado."); return; }
        if (!"POST".equals(exchange.getRequestMethod())) {
            exchange.getResponseHeaders().set("Allow", "POST");
            send(exchange, 405, "Método não permitido."); return;
        }
        String type = exchange.getRequestHeaders().getFirst("Content-Type");
        if (type == null || !type.toLowerCase(java.util.Locale.ROOT).startsWith("application/x-www-form-urlencoded")) {
            send(exchange, 415, "Formato de formulário inválido."); return;
        }
        try {
            Map<String,String> fields = parseForm(readBounded(exchange.getRequestBody(), 4096));
            if (!BayesAdminHandler.consumeCsrfToken(fields.get("csrf"), user.getEmail())) {
                send(exchange, 403, "Formulário expirado ou inválido. Atualize a página."); return;
            }
            String action = fields.get("action");
            if (!Arrays.asList("add", "update", "delete", "apply").contains(action)
                    || ("delete".equals(action) && !"1".equals(fields.get("confirm")))) {
                send(exchange, 400, "Ação inválida ou remoção não confirmada."); return;
            }
            JsonObjectBuilder request = Json.createObjectBuilder().add("action", action).add("actor", user.getEmail());
            for (String name : Arrays.asList("cidr", "original", "description", "revision")) {
                if (fields.containsKey(name)) request.add(name, fields.get(name));
            }
            JsonObject reply = backend.request(request.build());
            if (!reply.getBoolean("ok", false)) {
                display(exchange, user, reply.getString("message", "Não foi possível salvar."),
                        "conflict".equals(reply.getString("code", "")) ? 409 : 400);
                return;
            }
            Server.logInfo("SpamFox firewall admin: admin=" + user.getEmail() + " action=" + action);
            redirect(exchange, PAGE + "?saved=1");
        } catch (IllegalArgumentException ex) {
            send(exchange, 400, "Formulário inválido ou excede o limite.");
        } catch (IOException ex) {
            display(exchange, user, "Gestão do firewall indisponível. Confira o serviço na VM.", 503);
        }
    }

    private void display(HttpExchange exchange, User user, String error, int status) throws IOException {
        JsonObject snapshot;
        try {
            snapshot = backend.request(Json.createObjectBuilder().add("action", "list").build());
        } catch (IOException ex) {
            snapshot = Json.createObjectBuilder().add("ok", false).build();
        }
        String csrf = BayesAdminHandler.issueCsrfToken(user.getEmail());
        if (csrf == null) { send(exchange, 503, "Painel ocupado. Tente novamente em alguns minutos."); return; }
        if (!snapshot.getBoolean("ok", false)) status = 503;
        String notice = error != null ? error : ("saved=1".equals(exchange.getRequestURI().getRawQuery())
                ? "Regras salvas e aplicadas com sucesso." : null);
        send(exchange, status, render(snapshot, csrf, notice, user.getEmail()));
    }

    static Map<String,String> parseForm(byte[] body) {
        if (body.length == 0) throw new IllegalArgumentException();
        Map<String,String> result = new HashMap<>();
        try {
            for (String pair : new String(body, StandardCharsets.UTF_8).split("&", -1)) {
                int split = pair.indexOf('=');
                if (split < 1) throw new IllegalArgumentException();
                String key = URLDecoder.decode(pair.substring(0, split), "UTF-8");
                String value = URLDecoder.decode(pair.substring(split + 1), "UTF-8");
                if (!FIELDS.contains(key) || result.put(key, value) != null) throw new IllegalArgumentException();
            }
        } catch (java.io.UnsupportedEncodingException ex) { throw new IllegalArgumentException(ex); }
        return result;
    }

    static String render(JsonObject state, String csrf, String notice, String admin) {
        boolean available = state.getBoolean("ok", false);
        String revision = state.getString("revision", "");
        StringBuilder html = new StringBuilder(8192);
        html.append("<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
                .append("<title>Firewall · SpamFox</title><link rel=\"icon\" href=\"/favicon.png\"><link rel=\"stylesheet\" href=\"/style.css?v=spamfox-firewall-1\">")
                .append("<script src=\"/theme.js?v=spamfox-ui-20261017\" defer></script></head><body class=\"bayes-admin-page firewall-admin-page\"><main class=\"bayes-admin-shell\">")
                .append("<header class=\"bayes-admin-topbar\"><a class=\"bayes-admin-brand\" href=\"/admin/bayes/\"><img src=\"/logo.png\" alt=\"SpamFox\"><span><strong>SpamFox</strong><small>Administração da VM</small></span></a>")
                .append("<nav><a href=\"/admin/bayes/\">Administração do core</a><button class=\"theme-toggle\" type=\"button\" data-theme-toggle><span data-theme-icon>☾</span><span data-theme-label>Tema escuro</span></button></nav></header>")
                .append("<section class=\"bayes-admin-heading\"><div><p class=\"bayes-eyebrow\">REDE E ACESSO</p><h1>Firewall</h1><p>Administre os IPs públicos dos servidores que consultam o SpamFox pela TCP 9877.</p></div></section>");
        if (notice != null) html.append("<section class=\"bayes-card\" role=\"status\"><p>").append(escape(notice)).append("</p></section>");
        html.append("<section class=\"bayes-card\"><h2>Status das regras</h2><p>");
        if (!available) {
            html.append("Serviço de gestão indisponível. Confira <code>spamfox-firewall-admin.service</code> na VM.</p></section>");
        } else {
            html.append(state.getBoolean("synchronized", false) ? "Regras carregadas e sincronizadas com a lista."
                    : (state.getBoolean("active", false) ? "A lista e as regras carregadas divergem. Reaplique a lista para sincronizar."
                    : "Tabela de firewall ausente ou indisponível. Reaplique a lista e confira o serviço."));
            html.append("</p><p class=\"bayes-help\">ADMIN 9875 e HTTP 8080 permanecem restritos. Esta área não altera SSH nem outras tabelas de firewall. Uma lista vazia bloqueia todas as consultas externas. CIDRs sobrepostos podem continuar permitindo um IP após remover um registro.</p>");
            formStart(html, csrf, revision, "apply", null);
            html.append("<button class=\"bayes-submit\" type=\"submit\">Reaplicar regras</button></form></section>");
            html.append("<section class=\"bayes-card\"><h2>Autorizar servidor</h2><p class=\"bayes-help\">A liberação de rede complementa o cadastro do servidor no core. Faça o cadastro de clientes em Administração do core.</p>");
            formStart(html, csrf, revision, "add", null);
            input(html, "IP público ou CIDR", "cidr", "", true, 80);
            input(html, "Descrição / servidor", "description", "", false, 160);
            html.append("<button class=\"bayes-submit\" type=\"submit\">Adicionar IP/CIDR</button></form></section>");
            html.append("<section class=\"bayes-card\"><h2>Servidores autorizados</h2><div class=\"bayes-results-wrap\"><table class=\"bayes-results\"><thead><tr><th>IP / CIDR</th><th>Descrição</th><th>Ações</th></tr></thead><tbody>");
            for (JsonValue value : state.getJsonArray("entries")) {
                JsonObject entry = (JsonObject) value;
                String cidr = entry.getString("cidr");
                String note = entry.getString("description", "");
                html.append("<tr><td><code>").append(escape(cidr)).append("</code></td><td>").append(escape(note))
                        .append("</td><td><details><summary>Editar / remover</summary>");
                formStart(html, csrf, revision, "update", cidr);
                input(html, "IP / CIDR", "cidr", cidr, true, 80);
                input(html, "Descrição", "description", note, false, 160);
                html.append("<button class=\"bayes-submit\" type=\"submit\">Salvar alteração</button></form>");
                formStart(html, csrf, revision, "delete", cidr);
                html.append("<label class=\"firewall-delete-confirm\"><input type=\"checkbox\" name=\"confirm\" value=\"1\" required> Confirmo a remoção deste IP/CIDR</label><button class=\"bayes-submit firewall-delete\" type=\"submit\">Remover</button></form></details></td></tr>");
            }
            if (state.getJsonArray("entries").isEmpty()) html.append("<tr><td colspan=\"3\">Nenhum IP autorizado. Consultas externas estão bloqueadas.</td></tr>");
            html.append("</tbody></table></div></section>");
        }
        return html.append("<footer class=\"bayes-admin-footer\"><span>SpamFox · Baseado no <a href=\"https://spfbl.net/\">SPFBL</a></span><span>")
                .append(escape(admin)).append("</span></footer></main></body></html>").toString();
    }

    private static void formStart(StringBuilder html, String csrf, String revision, String action, String original) {
        html.append("<form class=\"bayes-client-form firewall-form\" method=\"post\" action=\"").append(CHANGE).append("\">");
        hidden(html, "csrf", csrf); hidden(html, "revision", revision); hidden(html, "action", action);
        if (original != null) hidden(html, "original", original);
    }

    private static void hidden(StringBuilder html, String name, String value) {
        html.append("<input type=\"hidden\" name=\"").append(name).append("\" value=\"").append(escape(value)).append("\">");
    }

    private static void input(StringBuilder html, String label, String name, String value, boolean required, int max) {
        html.append("<label>").append(label).append("<input name=\"").append(name).append("\" value=\"")
                .append(escape(value)).append("\" maxlength=\"").append(max).append("\"")
                .append(required ? " required" : "").append("></label>");
    }

    private static String escape(String text) { return StringEscapeUtils.escapeHtml4(text == null ? "" : text); }

    static byte[] readBounded(InputStream stream, int limit) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int count;
        while ((count = stream.read(buffer)) != -1) {
            if (output.size() + count > limit) throw new IllegalArgumentException("too large");
            output.write(buffer, 0, count);
        }
        return output.toByteArray();
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(303, -1);
        exchange.close();
    }

    private static void send(HttpExchange exchange, int status, String html) throws IOException {
        byte[] body = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Content-Security-Policy", "default-src 'self'; form-action 'self'; frame-ancestors 'self'; base-uri 'none'; object-src 'none'");
        exchange.sendResponseHeaders(status, body.length);
        try (java.io.OutputStream stream = exchange.getResponseBody()) { stream.write(body); }
    }

    private static final class LocalBackend implements Backend {
        public JsonObject request(JsonObject request) throws IOException {
            Process process = new ProcessBuilder("/usr/bin/python3", "/usr/local/lib/spamfox/firewall_admin.py")
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();
            FutureTask<byte[]> reader = new FutureTask<>(() -> readBounded(process.getInputStream(), 2 * 1024 * 1024));
            Thread thread = new Thread(reader, "spamfox-firewall-rpc");
            thread.setDaemon(true);
            thread.start();
            try {
                try (java.io.OutputStream input = process.getOutputStream()) {
                    input.write((request.toString() + "\n").getBytes(StandardCharsets.UTF_8));
                }
                if (!process.waitFor(20, TimeUnit.SECONDS) || process.exitValue() != 0) throw new IOException("Firewall RPC unavailable");
                String reply = new String(reader.get(1, TimeUnit.SECONDS), StandardCharsets.UTF_8);
                try (javax.json.JsonReader json = Json.createReader(new StringReader(reply))) { return json.readObject(); }
            } catch (Exception ex) {
                if (ex instanceof InterruptedException) Thread.currentThread().interrupt();
                throw new IOException("Firewall RPC unavailable", ex);
            } finally {
                process.destroyForcibly();
                reader.cancel(true);
            }
        }
    }
}
