/*
 * This file is part of SPFBL.
 *
 * SPFBL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SPFBL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SPFBL. If not, see <http://www.gnu.org/licenses/>.
 */
package net.spfbl.service;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.spfbl.core.Core;
import net.spfbl.core.Client;
import net.spfbl.core.ClientRequestMetrics;
import net.spfbl.core.ProcessException;
import net.spfbl.core.Server;
import net.spfbl.core.User;
import net.spfbl.data.ContentBayes;
import org.apache.commons.lang3.StringEscapeUtils;

/** Native Bayes administration and customer training endpoints. */
final class BayesAdminHandler implements HttpHandler {

    private static final String PAGE_PATH = "/admin/bayes/";
    private static final String UPLOAD_PATH = "/admin/bayes/learn";
    private static final String CLIENT_PATH = "/admin/bayes/client";
    private static final String CUSTOMER_PAGE_PATH = "/account/bayes/";
    private static final String CUSTOMER_UPLOAD_PATH = "/account/bayes/learn";
    private static final int MAX_FILE_BYTES = 5 * 1024 * 1024;
    private static final int MAX_FILES = 10;
    private static final int MAX_BATCH_BYTES = 20 * 1024 * 1024;
    private static final int MAX_REQUEST_BYTES = MAX_BATCH_BYTES + 256 * 1024;
    private static final long CSRF_TTL_MILLIS = 30L * 60L * 1000L;
    private static final int MAX_CSRF_TOKENS = 4096;
    private static final long CUSTOMER_UPLOAD_WINDOW_MILLIS = 24L * 60L * 60L * 1000L;
    private static final int MAX_CUSTOMER_UPLOAD_FILES_PER_WINDOW = 100;
    private static final Pattern BOUNDARY_PATTERN = Pattern.compile(
            "(?i)(?:^|;)\\s*boundary=(?:\"([^\"]+)\"|([^;\\s]+))"
    );
    private static final Pattern PARAMETER_PATTERN = Pattern.compile(
            "(?i)(?:^|;)\\s*([a-z0-9_-]+)\\s*=\\s*\"((?:\\\\.|[^\"])*)\""
    );
    private static final ConcurrentHashMap<String,CsrfGrant> CSRF_TOKENS = new ConcurrentHashMap<>();
    private static final Map<String,ArrayDeque<Long>> CUSTOMER_UPLOADS = new HashMap<>();

    private final boolean secured;
    private final boolean customerMode;

    BayesAdminHandler(boolean secured) {
        this(secured, false);
    }

    BayesAdminHandler(boolean secured, boolean customerMode) {
        this.secured = secured;
        this.customerMode = customerMode;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        boolean secureRequest = secured || isTrustedSecureProxy(exchange);
        if (!secureRequest) {
            send(exchange, 403, "text/plain; charset=UTF-8",
                    "Esta área exige HTTPS.\n");
            return;
        }
        exchange.getResponseHeaders().set("Strict-Transport-Security", "max-age=31536000");
        String pagePath = customerMode ? CUSTOMER_PAGE_PATH : PAGE_PATH;
        String uploadPath = customerMode ? CUSTOMER_UPLOAD_PATH : UPLOAD_PATH;
        if (pagePath.substring(0, pagePath.length() - 1).equals(path)) {
            exchange.getResponseHeaders().set("Location", pagePath);
            exchange.sendResponseHeaders(301, -1);
            return;
        }
        if (!pagePath.equals(path) && !uploadPath.equals(path)
                && !( !customerMode && CLIENT_PATH.equals(path))) {
            send(exchange, 404, "text/plain; charset=UTF-8", "Não encontrado.\n");
            return;
        }
        User user = ServerHTTP.getAuthenticatedUser(exchange, secureRequest);
        boolean authorized = customerMode
                ? user != null && hasRegisteredClient(user.getEmail())
                : user != null && user.isAdmin();
        if (!authorized) {
            send(exchange, user == null ? 401 : 403, "text/html; charset=UTF-8",
                    renderAccessDenied(user == null, customerMode));
            return;
        }
        if (pagePath.equals(path) && "GET".equals(exchange.getRequestMethod())) {
            if (customerMode) {
                String token = issueCsrfToken(user.getEmail());
                if (token == null) {
                    send(exchange, 503, "text/plain; charset=UTF-8",
                            "Painel ocupado; tente novamente em alguns minutos.\n");
                    return;
                }
                send(exchange, 200, "text/html; charset=UTF-8",
                        renderCustomerDashboard(user, token, null));
                return;
            }
            DashboardTokens tokens = issueDashboardTokens(user.getEmail());
            if (tokens == null) {
                send(exchange, 503, "text/plain; charset=UTF-8",
                        "Painel ocupado; tente novamente em alguns minutos.\n");
                return;
            }
            send(exchange, 200, "text/html; charset=UTF-8",
                    renderDashboard(user, tokens, null, null));
            return;
        }
        if (uploadPath.equals(path) && "POST".equals(exchange.getRequestMethod())) {
            handleUpload(exchange, user);
            return;
        }
        if (!customerMode && CLIENT_PATH.equals(path) && "POST".equals(exchange.getRequestMethod())) {
            handleClientRegistration(exchange, user);
            return;
        }
        exchange.getResponseHeaders().set("Allow", "GET, POST");
        send(exchange, 405, "text/plain; charset=UTF-8", "Método não permitido.\n");
    }

    private static boolean isTrustedSecureProxy(HttpExchange exchange) {
        InetAddress peer = exchange.getRemoteAddress().getAddress();
        String forwardedProtocol = exchange.getRequestHeaders().getFirst("X-Forwarded-Proto");
        return peer != null && peer.isLoopbackAddress()
                && forwardedProtocol != null
                && "https".equalsIgnoreCase(forwardedProtocol.trim());
    }

    static boolean hasRegisteredClient(String email) {
        if (email == null || email.trim().isEmpty()) return false;
        String normalized = email.trim().toLowerCase(Locale.ROOT);
        for (Client client : Client.getSet()) {
            String owner = client.getEmail();
            if (owner != null && normalized.equals(owner.trim().toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    static synchronized boolean reserveCustomerTrainingSlots(String email, int files) {
        if (email == null || files < 1 || files > MAX_FILES) return false;
        long now = System.currentTimeMillis();
        long cutoff = now - CUSTOMER_UPLOAD_WINDOW_MILLIS;
        String key = email.trim().toLowerCase(Locale.ROOT);
        CUSTOMER_UPLOADS.entrySet().removeIf(entry -> {
            if (key.equals(entry.getKey())) return false;
            ArrayDeque<Long> oldTimestamps = entry.getValue();
            while (!oldTimestamps.isEmpty() && oldTimestamps.peekFirst() < cutoff) {
                oldTimestamps.removeFirst();
            }
            return oldTimestamps.isEmpty();
        });
        ArrayDeque<Long> timestamps = CUSTOMER_UPLOADS.computeIfAbsent(key, ignored -> new ArrayDeque<Long>());
        while (!timestamps.isEmpty() && timestamps.peekFirst() < cutoff) {
            timestamps.removeFirst();
        }
        if (timestamps.size() + files > MAX_CUSTOMER_UPLOAD_FILES_PER_WINDOW) return false;
        for (int index = 0; index < files; index++) timestamps.addLast(now);
        return true;
    }

    static CustomerKpis summarizeCustomerResults(Iterable<String> results) {
        CustomerKpis kpis = new CustomerKpis();
        if (results == null) return kpis;
        for (String result : results) {
            kpis.total++;
            if ("WHITE".equals(result) || "ACCEPT".equals(result)) {
                kpis.accepted++;
            } else if ("FLAG".equals(result)) {
                kpis.suspicious++;
            } else if ("HOLD".equals(result) || "GREYLIST".equals(result)
                    || "LISTED".equals(result) || "QUEUE".equals(result)) {
                kpis.pending++;
            } else if (isRejectedResult(result)) {
                kpis.rejected++;
            }
        }
        return kpis;
    }

    private static boolean isRejectedResult(String result) {
        return "REJECT".equals(result) || "BLOCK".equals(result) || "BLOCKED".equals(result)
                || "FAIL".equals(result) || "FAILED".equals(result) || "INVALID".equals(result)
                || "INEXISTENT".equals(result) || "NXDOMAIN".equals(result)
                || "NXSENDER".equals(result) || "SPAMTRAP".equals(result) || "TRAP".equals(result);
    }

    static final class CustomerKpis {
        long total;
        long accepted;
        long rejected;
        long suspicious;
        long pending;

        long other() {
            return Math.max(0, total - accepted - rejected - suspicious - pending);
        }
    }

    static String renderCustomerDashboard(User user, String csrfToken, UploadReport report) {
        Locale locale = user.getLocale();
        boolean english = locale != null && "en".equalsIgnoreCase(locale.getLanguage());
        TreeMap<Long,User.Query> recent = user.getQueryMap(null, null);
        ArrayList<String> results = new ArrayList<>();
        if (recent != null) {
            for (User.Query query : recent.values()) {
                if (query != null) results.add(query.getResult());
            }
        }
        CustomerKpis kpis = summarizeCustomerResults(results);
        StringBuilder html = new StringBuilder(9000);
        html.append("<!DOCTYPE html><html lang=\"").append(english ? "en" : "pt-BR")
                .append("\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
                .append("<link rel=\"icon\" href=\"/favicon.png\"><title>")
                .append(english ? "Customer dashboard · SpamFox" : "Painel do cliente · SpamFox")
                .append("</title><link rel=\"stylesheet\" href=\"/style.css?v=spamfox-ui-20261017-3\">")
                .append("<script src=\"/theme.js?v=spamfox-ui-20261017\" defer></script></head>")
                .append("<body class=\"bayes-admin-page\"><main class=\"bayes-admin-shell\">")
                .append("<header class=\"bayes-admin-topbar\"><a class=\"bayes-admin-brand\" href=\"")
                .append(CUSTOMER_PAGE_PATH).append("\"><img src=\"/logo.png\" alt=\"SpamFox\"><span><strong>SpamFox</strong><small>")
                .append(english ? "Customer area · SPFBL core" : "Área do cliente · core SPFBL")
                .append("</small></span></a><nav><a href=\"/").append(escapeAttribute(user.getEmail())).append("\">")
                .append(english ? "Email statuses" : "Lista e status dos e-mails")
                .append("</a><button class=\"theme-toggle\" type=\"button\" data-theme-toggle><span data-theme-icon>☾</span><span data-theme-label>")
                .append(english ? "Dark theme" : "Tema escuro")
                .append("</span></button></nav></header>")
                .append("<section class=\"bayes-admin-heading\"><div><p class=\"bayes-eyebrow\">")
                .append(english ? "CUSTOMER ACCOUNT" : "CONTA DO CLIENTE")
                .append("</p><h1>").append(english ? "Email activity and Bayes training" : "Atividade de e-mails e treinamento Bayes")
                .append("</h1><p>")
                .append(english ? "Recent statuses belong to your account. Upload confirmed messages to train the shared model."
                        : "Os status recentes pertencem à sua conta. Envie mensagens confirmadas para treinar o modelo compartilhado.")
                .append("</p></div><span class=\"bayes-live-pill is-active\"><i></i>")
                .append(english ? "Account linked" : "Conta vinculada")
                .append("</span></section>")
                .append("<section class=\"bayes-kpi-grid customer-kpi-grid\" aria-label=\"")
                .append(english ? "Recent account email indicators" : "Indicadores recentes de e-mail da conta")
                .append("\">");
        appendKpi(html, english ? "Recent events" : "Eventos recentes", String.valueOf(kpis.total), "blue", "✉");
        appendKpi(html, english ? "Accepted" : "Aceitos", String.valueOf(kpis.accepted), "green", "✓");
        appendKpi(html, english ? "Rejected" : "Rejeitados", String.valueOf(kpis.rejected), "coral", "⛔");
        appendKpi(html, english ? "Suspicious" : "Suspeitos", String.valueOf(kpis.suspicious), "purple", "⚠");
        appendKpi(html, english ? "Pending" : "Pendentes", String.valueOf(kpis.pending), "blue", "◷");
        html.append("</section><p class=\"bayes-customer-scope\">")
                .append(english ? "Counts follow the recent message records available to your mail account in the core. Other statuses: "
                        : "Os indicadores usam os registros recentes da sua conta disponíveis no core. Outros status: ")
                .append(kpis.other()).append(".</p>");
        if (report != null) {
            html.append("<section class=\"bayes-card bayes-report ")
                    .append(report.error ? "is-error" : "is-success").append("\"><h2>")
                    .append(english ? "Training result" : "Resultado do treinamento")
                    .append("</h2><p>").append(escapeHtml(report.notice)).append("</p>");
            if (report.results != null && !report.results.isEmpty()) {
                html.append("<div class=\"bayes-results-wrap\"><table class=\"bayes-results\"><thead><tr><th>")
                        .append(english ? "File" : "Arquivo").append("</th><th>")
                        .append(english ? "Result" : "Resultado").append("</th></tr></thead><tbody>");
                for (LearnResult result : report.results) {
                    html.append("<tr><td>").append(escapeHtml(result.filename)).append("</td><td>")
                            .append(escapeHtml(statusLabel(result.status, english))).append("</td></tr>");
                }
                html.append("</tbody></table></div>");
            }
            html.append("</section>");
        }
        html.append("<section class=\"bayes-card bayes-training-card customer-training-card\"><div class=\"bayes-card-heading\"><div><p class=\"bayes-eyebrow\">")
                .append(english ? "SHARED MODEL" : "MODELO COMPARTILHADO")
                .append("</p><h2>").append(english ? "Label .eml messages" : "Classificar mensagens .eml")
                .append("</h2></div><span class=\"bayes-card-icon\">⇧</span></div><p class=\"bayes-help\">")
                .append(english ? "Your SPAM/HAM label is added immediately to the Bayes model shared by enrolled servers. It can affect later classifications for every customer. Only submit reviewed examples; originals are not retained."
                        : "Seu rótulo SPAM/HAM é adicionado imediatamente ao Bayes compartilhado pelos servidores cadastrados e pode afetar classificações futuras de todos os clientes. Envie apenas exemplos revisados; os arquivos originais não são guardados.")
                .append("</p><form class=\"bayes-upload-form\" method=\"post\" enctype=\"multipart/form-data\" action=\"")
                .append(CUSTOMER_UPLOAD_PATH).append("\"><input type=\"hidden\" name=\"csrf\" value=\"")
                .append(escapeAttribute(csrfToken)).append("\"><fieldset><legend>")
                .append(english ? "Message label" : "Classificação das mensagens")
                .append("</legend><label class=\"bayes-label-option spam-label\"><input type=\"radio\" name=\"label\" value=\"SPAM\" required><span><b>SPAM</b><small>")
                .append(english ? "Unwanted or malicious" : "Indesejada ou maliciosa")
                .append("</small></span></label><label class=\"bayes-label-option ham-label\"><input type=\"radio\" name=\"label\" value=\"HAM\" required><span><b>HAM</b><small>")
                .append(english ? "Confirmed legitimate message" : "Mensagem legítima confirmada")
                .append("</small></span></label></fieldset><label class=\"bayes-file-picker\"><span class=\"bayes-file-symbol\">＋</span><span><b>")
                .append(english ? "Select .eml files" : "Selecionar arquivos .eml")
                .append("</b><small>").append(english ? "Up to 10 files · 5 MiB each · 20 MiB per batch · 100 files per 24 hours"
                        : "Até 10 arquivos · 5 MiB cada · 20 MiB por lote · 100 arquivos por 24 horas")
                .append("</small><input type=\"file\" name=\"eml\" accept=\".eml,message/rfc822\" multiple required></span></label><button class=\"bayes-submit\" type=\"submit\">")
                .append(english ? "Train shared Bayes" : "Treinar Bayes compartilhado")
                .append("</button></form></section><footer class=\"bayes-admin-footer\"><span>")
                .append(english ? "Native Bayes model powered by the SPFBL core." : "Bayes nativo executado pelo core SPFBL.")
                .append("</span><span>").append(escapeHtml(user.getEmail())).append("</span></footer></main></body></html>");
        return html.toString();
    }

    private void handleUpload(HttpExchange exchange, User user) throws IOException {
        try {
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            String boundary = getBoundary(contentType);
            if (boundary == null) {
                send(exchange, 415, "text/plain; charset=UTF-8",
                        "Envie os arquivos usando multipart/form-data.\n");
                return;
            }
            String lengthHeader = exchange.getRequestHeaders().getFirst("Content-Length");
            if (lengthHeader != null) {
                try {
                    if (Long.parseLong(lengthHeader) > MAX_REQUEST_BYTES) {
                        send(exchange, 413, "text/plain; charset=UTF-8",
                                "Lote excede o limite de 20 MiB.\n");
                        return;
                    }
                } catch (NumberFormatException ex) {
                    send(exchange, 400, "text/plain; charset=UTF-8", "Content-Length inválido.\n");
                    return;
                }
            }
            byte[] body = readBounded(exchange, MAX_REQUEST_BYTES);
            MultipartForm form = parseMultipart(body, boundary);
            if (!consumeCsrfToken(form.csrfToken, user.getEmail())) {
                send(exchange, 403, "text/plain; charset=UTF-8",
                        "Sessão do formulário expirada. Atualize a página e tente novamente.\n");
                return;
            }
            if (!ContentBayes.isPersistenceWritable()) {
                send(exchange, 503, "text/plain; charset=UTF-8",
                        "Persistência do modelo Bayes indisponível; treinamento bloqueado.\n");
                return;
            }
            boolean spam;
            if ("SPAM".equals(form.label)) {
                spam = true;
            } else if ("HAM".equals(form.label)) {
                spam = false;
            } else {
                renderUploadResult(exchange, user, null,
                        "Escolha se os arquivos são SPAM ou HAM.", true);
                return;
            }
            if (form.files.isEmpty()) {
                renderUploadResult(exchange, user, null,
                        "Selecione pelo menos um arquivo .eml.", true);
                return;
            }
            if (form.files.size() > MAX_FILES) {
                renderUploadResult(exchange, user, null,
                        "O limite é de " + MAX_FILES + " arquivos por lote.", true);
                return;
            }
            for (UploadedEml file : form.files) {
                if (!file.filename.toLowerCase(Locale.ROOT).endsWith(".eml")) {
                    renderUploadResult(exchange, user, null,
                            "Todos os arquivos precisam ter extensão .eml.", true);
                    return;
                }
                if (file.bytes.length == 0 || file.bytes.length > MAX_FILE_BYTES) {
                    renderUploadResult(exchange, user, null,
                            "Cada arquivo deve ter entre 1 byte e 5 MiB.", true);
                    return;
                }
            }
            if (customerMode && !reserveCustomerTrainingSlots(user.getEmail(), form.files.size())) {
                renderUploadResult(exchange, user, null,
                        "Limite atingido: cada conta pode enviar até "
                                + MAX_CUSTOMER_UPLOAD_FILES_PER_WINDOW
                                + " arquivos .eml em 24 horas.", true);
                return;
            }

            List<LearnResult> results = new ArrayList<>();
            int added = 0;
            for (UploadedEml file : form.files) {
                ContentBayes.LearnStatus status;
                try {
                    status = ContentBayes.learn(file.bytes, spam);
                } catch (Exception ex) {
                    status = null;
                    Server.logError("Native Bayes web training rejected malformed EML: "
                            + ex.getClass().getSimpleName());
                }
                if (status == ContentBayes.LearnStatus.ADDED) {
                    added++;
                }
                results.add(new LearnResult(file.filename, status));
            }
            boolean stored = added == 0 || ContentBayes.store();
            String label = spam ? "SPAM" : "HAM";
            if (stored) {
                Server.logInfo("Native Bayes web training: actor="
                        + (customerMode ? "customer:" : "admin:") + user.getEmail()
                        + " label=" + label + " files=" + form.files.size() + " added=" + added);
                renderUploadResult(exchange, user, results,
                        stored ? "Lote " + label + " processado. " + added
                                + " nova(s) mensagem(ns) incorporada(s) ao modelo."
                                : "Falha ao salvar o modelo Bayes.", false);
            } else {
                Server.logError("Native Bayes web training could not persist the model.");
                renderUploadResult(exchange, user, results,
                        "O treinamento foi processado em memória, mas o modelo não pôde ser salvo. "
                                + "Não reinicie o serviço até corrigir a persistência.", true);
            }
        } catch (UploadException ex) {
            send(exchange, ex.statusCode, "text/plain; charset=UTF-8", ex.getMessage() + "\n");
        } catch (Exception ex) {
            Server.logError("Native Bayes web upload failed: " + ex.getClass().getSimpleName());
            send(exchange, 400, "text/plain; charset=UTF-8", "Arquivo ou formulário inválido.\n");
        }
    }

    private void renderUploadResult(HttpExchange exchange, User user,
            List<LearnResult> results, String notice, boolean error) throws IOException {
        if (customerMode) {
            String token = issueCsrfToken(user.getEmail());
            if (token == null) {
                send(exchange, 503, "text/plain; charset=UTF-8",
                        "Treinamento concluído, mas não foi possível abrir um novo formulário.\n");
                return;
            }
            send(exchange, 200, "text/html; charset=UTF-8",
                    renderCustomerDashboard(user, token,
                            new UploadReport(results, notice, error)));
            return;
        }
        DashboardTokens tokens = issueDashboardTokens(user.getEmail());
        if (tokens == null) {
            send(exchange, 503, "text/plain; charset=UTF-8",
                    "Treinamento concluído, mas não foi possível abrir um novo formulário.\n");
            return;
        }
        send(exchange, 200, "text/html; charset=UTF-8",
                renderDashboard(user, tokens, new UploadReport(results, notice, error), null));
    }

    private static void handleClientRegistration(HttpExchange exchange, User user) throws IOException {
        try {
            String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
            if (contentType == null || !contentType.toLowerCase(Locale.ROOT)
                    .startsWith("application/x-www-form-urlencoded")) {
                send(exchange, 415, "text/plain; charset=UTF-8", "Formato de formulário inválido.\n");
                return;
            }
        byte[] body = readBounded(exchange, 16 * 1024);
            Map<String,String> fields = parseUrlEncodedForm(body);
            if (!consumeCsrfToken(fields.get("csrf"), user.getEmail())) {
                send(exchange, 403, "text/plain; charset=UTF-8",
                        "Sessão do formulário expirada. Atualize a página e tente novamente.\n");
                return;
            }
            String action = fields.get("action");
            String email = fields.get("customer_email");
            String customerName = fields.get("customer_name");
            String cidr = fields.get("cidr");
            String hostname = fields.get("hostname");
            String permission = fields.get("permission");
            if ("decision-enable".equals(action) || "decision-disable".equals(action)) {
                if (cidr == null || email != null || customerName != null || hostname != null || permission != null) {
                    renderClientResult(exchange, user,
                            "Informe somente o IP/CIDR do servidor para alterar a decisão Bayes.", true);
                    return;
                }
                String result = updateBayesDecisionClient(action, cidr.trim());
                String normalizedCIDR = cidr.trim();
                try {
                    Client registered = Client.getByCIDR(normalizedCIDR);
                    if (registered != null) normalizedCIDR = registered.getCIDR();
                } catch (ProcessException ignored) {
                    // The update result below will report an invalid or unregistered CIDR.
                }
                boolean error = !("ACTIVE".equals(result) || "INACTIVE".equals(result)
                        || "ALREADY_ACTIVE".equals(result) || "ALREADY_INACTIVE".equals(result));
                if ("ACTIVE".equals(result) || "INACTIVE".equals(result)) {
                    Server.logInfo("Native Bayes decision scope: admin=" + user.getEmail()
                            + " action=" + action + " cidr=" + normalizedCIDR);
                }
                renderClientResult(exchange, user,
                        decisionClientNotice(result, normalizedCIDR, user.getLocale()), error);
                return;
            }
            if (email == null || cidr == null || hostname == null || permission == null) {
                renderClientResult(exchange, user,
                        "Preencha o e-mail do cliente, o IP/CIDR, o hostname e a permissão.", true);
                return;
            }
            email = email.trim();
            cidr = cidr.trim();
            hostname = hostname.trim();
            permission = permission.trim().toUpperCase(Locale.ROOT);
            if (!"SPFBL".equals(permission) && !"DNSBL".equals(permission)
                    && !"NONE".equals(permission)) {
                renderClientResult(exchange, user, "Permissão inválida.", true);
                return;
            }
            TreeSet<String> registeredEmails = Client.getEmailSet();
            if ("register".equals(action) && registeredEmails.contains(email.toLowerCase(Locale.ROOT))) {
                renderClientResult(exchange, user,
                        "Este e-mail já tem servidores cadastrados. Use “Adicionar servidor” para vinculá-lo.", true);
                return;
            } else if ("add-server".equals(action) && !registeredEmails.contains(email.toLowerCase(Locale.ROOT))) {
                renderClientResult(exchange, user,
                        "Selecione um cliente já cadastrado ou cadastre o cliente com o primeiro servidor.", true);
                return;
            } else if (!"register".equals(action) && !"add-server".equals(action)) {
                renderClientResult(exchange, user, "Ação de cadastro inválida.", true);
                return;
            }
            User customerUser = User.get(email);
            boolean newUser = customerUser == null;
            if (newUser && (customerName == null || customerName.trim().isEmpty())) {
                renderClientResult(exchange, user,
                        "Informe o nome do cliente para criar o acesso web e enviar a chave TOTP.", true);
                return;
            }
            Client created;
            try {
                created = Client.create(cidr, hostname, permission, email);
            } catch (ProcessException ex) {
                renderClientResult(exchange, user, clientErrorMessage(ex.getMessage()), true);
                return;
            }
            if (created == null) {
                renderClientResult(exchange, user,
                        "O IP/CIDR já está cadastrado com essa permissão.", true);
                return;
            }
            if (newUser) {
                try {
                    customerUser = User.create(email, customerName.trim());
                } catch (ProcessException ex) {
                    Client.drop(created.getCIDR());
                    Client.storeNow();
                    renderClientResult(exchange, user, "Não foi possível criar o usuário: "
                            + clientErrorMessage(ex.getMessage()), true);
                    return;
                }
                if (customerUser == null || !User.storeMap()) {
                    Client.drop(created.getCIDR());
                    if (customerUser != null) User.drop(email.toLowerCase(Locale.ROOT));
                    Client.storeNow();
                    renderClientResult(exchange, user,
                            "Não foi possível persistir a conta do cliente; o cadastro do servidor foi revertido.", true);
                    return;
                }
            }
            if (!Client.storeNow()) {
                Client.drop(created.getCIDR());
                Client.storeNow();
                if (newUser) {
                    User.drop(email.toLowerCase(Locale.ROOT));
                    User.storeMap();
                }
                renderClientResult(exchange, user,
                        "Não foi possível persistir o cadastro; a criação do servidor e da nova conta foi revertida.", true);
                return;
            }
            String notice = "Servidor " + created.getDomain() + " (" + created.getCIDR()
                    + ") cadastrado para " + created.getEmail() + " com permissão "
                    + created.getPermission().name() + ".";
            if (newUser) {
                boolean totpSent;
                try {
                    totpSent = customerUser.sendTOTP();
                } catch (RuntimeException ex) {
                    Server.logError("Native customer TOTP enrollment failed: " + ex.getClass().getSimpleName());
                    totpSent = false;
                }
                boolean totpStateStored = User.storeMap();
                if (totpSent && totpStateStored) {
                    notice += " Acesso web criado e chave inicial TOTP enviada para " + email + ".";
                } else if (totpSent) {
                    notice += " A chave TOTP foi enviada, mas o estado de autenticação não pôde ser persistido; "
                            + "verifique o armazenamento do core antes do próximo reinício.";
                } else {
                    notice += " Acesso web criado, mas o e-mail TOTP não foi enviado. "
                            + "Verifique o SMTP e reenvie pelo comando nativo `spfbl user send-totp " + email + "`.";
                }
            } else {
                notice += " A conta web já existia; nenhuma chave TOTP foi redefinida ou reenviada.";
            }
            Server.logInfo("Native client admin: admin=" + user.getEmail() + " action=" + action
                    + " cidr=" + created.getCIDR() + " permission=" + created.getPermission().name());
            renderClientResult(exchange, user, notice, false);
        } catch (UploadException ex) {
            send(exchange, ex.statusCode, "text/plain; charset=UTF-8", ex.getMessage() + "\n");
        } catch (Exception ex) {
            Server.logError("Native client admin request failed: " + ex.getClass().getSimpleName());
            send(exchange, 400, "text/plain; charset=UTF-8", "Formulário de cadastro inválido.\n");
        }
    }

    /**
     * Opts a registered SPFBL server into or out of content-based delivery decisions.
     * Enabling also enrolls the CIDR in the Bayes content-client allowlist required by the core.
     */
    static synchronized String updateBayesDecisionClient(String action, String cidr) {
        final boolean activate;
        if ("decision-enable".equals(action)) {
            activate = true;
        } else if ("decision-disable".equals(action)) {
            activate = false;
        } else {
            return "INVALID_ACTION";
        }
        if (cidr == null || cidr.trim().isEmpty()) return "INVALID_CIDR";
        final Client client;
        try {
            client = Client.getByCIDR(cidr.trim());
        } catch (ProcessException ex) {
            return "INVALID_CIDR";
        }
        if (client == null) return "NOT_REGISTERED";
        if (!client.isPermission("SPFBL")) return "SPFBL_REQUIRED";
        String normalizedCIDR = client.getCIDR();
        if (!ContentBayes.isPersistenceWritable()) return "STORE_FAILED";

        if (activate) {
            if (ContentBayes.hasDecisionClient(normalizedCIDR)) return "ALREADY_ACTIVE";
            boolean addedContentClient = false;
            if (!ContentBayes.hasAllowedClient(normalizedCIDR)) {
                if (!ContentBayes.addAllowedClient(normalizedCIDR)) return "LIMIT_REACHED";
                addedContentClient = true;
            }
            if (!ContentBayes.addDecisionClient(normalizedCIDR)) {
                if (addedContentClient) {
                    ContentBayes.dropAllowedClient(normalizedCIDR);
                    ContentBayes.store();
                }
                return "LIMIT_REACHED";
            }
            if (!ContentBayes.store()) {
                ContentBayes.dropDecisionClient(normalizedCIDR);
                if (addedContentClient) ContentBayes.dropAllowedClient(normalizedCIDR);
                ContentBayes.store();
                return "STORE_FAILED";
            }
            return "ACTIVE";
        }

        if (!ContentBayes.hasDecisionClient(normalizedCIDR)) return "ALREADY_INACTIVE";
        if (!ContentBayes.dropDecisionClient(normalizedCIDR)) return "ALREADY_INACTIVE";
        if (!ContentBayes.store()) {
            ContentBayes.addDecisionClient(normalizedCIDR);
            ContentBayes.store();
            return "STORE_FAILED";
        }
        return "INACTIVE";
    }

    private static String decisionClientNotice(String result, String cidr, Locale locale) {
        boolean english = locale != null && "en".equalsIgnoreCase(locale.getLanguage());
        if ("ACTIVE".equals(result)) {
            return english ? "Bayes delivery decisions enabled for " + cidr + "."
                    : "Decisão de entrega Bayes ativada para " + cidr + ".";
        } else if ("INACTIVE".equals(result)) {
            return english ? "Bayes delivery decisions disabled for " + cidr + "."
                    : "Decisão de entrega Bayes desativada para " + cidr + ".";
        } else if ("ALREADY_ACTIVE".equals(result)) {
            return english ? "Bayes delivery decisions are already enabled for " + cidr + "."
                    : "A decisão de entrega Bayes já está ativa para " + cidr + ".";
        } else if ("ALREADY_INACTIVE".equals(result)) {
            return english ? "Bayes delivery decisions are already disabled for " + cidr + "."
                    : "A decisão de entrega Bayes já está inativa para " + cidr + ".";
        } else if ("NOT_REGISTERED".equals(result)) {
            return english ? "Register this server in the SPFBL core first."
                    : "Cadastre este servidor no core SPFBL antes de habilitar o Bayes.";
        } else if ("SPFBL_REQUIRED".equals(result)) {
            return english ? "Only servers registered with SPFBL permission can use Bayes delivery decisions."
                    : "Somente servidores com permissão SPFBL podem usar decisões de entrega Bayes.";
        } else if ("LIMIT_REACHED".equals(result)) {
            return english ? "The Bayes client limit was reached; no change was saved."
                    : "O limite de clientes Bayes foi atingido; nenhuma alteração foi salva.";
        } else if ("STORE_FAILED".equals(result)) {
            return english ? "Bayes storage is unavailable; the change was rolled back."
                    : "O armazenamento Bayes está indisponível; a alteração foi revertida.";
        } else if ("INVALID_CIDR".equals(result)) {
            return english ? "Invalid IP or CIDR. No change was saved."
                    : "IP ou CIDR inválido. Nenhuma alteração foi salva.";
        }
        return english ? "Invalid Bayes client action." : "Ação Bayes inválida.";
    }

    private static String clientErrorMessage(String error) {
        if ("INVALID CIDR".equals(error)) return "IP ou CIDR inválido.";
        if ("INVALID CLIENT".equals(error)) return "Hostname ou IP/CIDR inválido.";
        if ("INVALID DOMAIN".equals(error)) return "Hostname inválido.";
        if ("INVALID EMAIL".equals(error) || "INVALID E-MAIL".equals(error)) return "E-mail inválido.";
        if ("INVALID PERMISSION".equals(error)) return "Permissão inválida.";
        return "O core recusou o cadastro: " + (error == null ? "erro desconhecido" : error);
    }

    private static void renderClientResult(HttpExchange exchange, User user, String notice,
            boolean error) throws IOException {
        DashboardTokens tokens = issueDashboardTokens(user.getEmail());
        if (tokens == null) {
            send(exchange, 503, "text/plain; charset=UTF-8",
                    "Cadastro processado, mas não foi possível abrir um novo formulário.\n");
            return;
        }
        ClientReport report = new ClientReport(notice, error);
        send(exchange, 200, "text/html; charset=UTF-8",
                renderDashboard(user, tokens, null, report));
    }

    private static DashboardTokens issueDashboardTokens(String email) {
        String trainingToken = issueCsrfToken(email);
        String clientToken = issueCsrfToken(email);
        if (trainingToken == null || clientToken == null) {
            if (trainingToken != null) CSRF_TOKENS.remove(trainingToken);
            if (clientToken != null) CSRF_TOKENS.remove(clientToken);
            return null;
        }
        return new DashboardTokens(trainingToken, clientToken);
    }

    static Map<String,String> parseUrlEncodedForm(byte[] body) throws UploadException {
        if (body == null || body.length == 0) throw new UploadException(400, "Formulário vazio.");
        String encoded = new String(body, StandardCharsets.UTF_8);
        Map<String,String> result = new HashMap<>();
        try {
            for (String pair : encoded.split("&", -1)) {
                int separator = pair.indexOf('=');
                if (separator <= 0) throw new UploadException(400, "Campo de formulário inválido.");
                String key = URLDecoder.decode(pair.substring(0, separator), "UTF-8");
                String value = URLDecoder.decode(pair.substring(separator + 1), "UTF-8");
                if (!"csrf".equals(key) && !"action".equals(key) && !"customer_email".equals(key)
                        && !"customer_name".equals(key)
                        && !"cidr".equals(key) && !"hostname".equals(key) && !"permission".equals(key)) {
                    throw new UploadException(400, "Campo de formulário desconhecido.");
                }
                if (result.put(key, value) != null) throw new UploadException(400, "Campo repetido.");
            }
        } catch (IllegalArgumentException ex) {
            throw new UploadException(400, "Codificação do formulário inválida.");
        } catch (java.io.UnsupportedEncodingException ex) {
            throw new UploadException(400, "Codificação do formulário inválida.");
        }
        return result;
    }

    static String renderDashboard(User user, DashboardTokens tokens,
            UploadReport report, ClientReport clientReport) {
        Locale locale = user.getLocale();
        boolean english = locale != null && "en".equalsIgnoreCase(locale.getLanguage());
        Map<String,String> stats = parseStats(ContentBayes.stats());
        String spamDocs = value(stats, "SPAM_DOCUMENTS", "0");
        String hamDocs = value(stats, "HAM_DOCUMENTS", "0");
        String vocabulary = value(stats, "VOCABULARY", "0");
        String allowed = value(stats, "ALLOWED_CLIENTS", "0");
        String decision = value(stats, "DECISION_CLIENTS", "0");
        String minimum = value(stats, "MIN_DOCUMENTS_PER_CLASS", "25");
        String threshold = value(stats, "SPAM_THRESHOLD", "0.995");
        boolean enabled = Boolean.parseBoolean(value(stats, "ENABLED", "false"));
        boolean writable = ContentBayes.isPersistenceWritable();
        StringBuilder html = new StringBuilder(12000);
        html.append("<!DOCTYPE html>\n<html lang=\"")
                .append(english ? "en" : "pt-BR").append("\">\n<head>\n")
                .append("<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n")
                .append("<link rel=\"icon\" href=\"/favicon.png\"><title>")
                .append(english ? "SpamFox Bayes administration" : "Administração Bayes · SpamFox")
                .append("</title><link rel=\"stylesheet\" href=\"/style.css?v=spamfox-bayes-decisions-1\">\n")
                .append("<script src=\"/theme.js?v=spamfox-ui-20261017\" defer></script>\n")
                .append("</head><body class=\"bayes-admin-page\"><main class=\"bayes-admin-shell\">\n")
                .append("<header class=\"bayes-admin-topbar\"><a class=\"bayes-admin-brand\" href=\"/admin/bayes/\"><img src=\"/logo.png\" alt=\"SpamFox\"><span><strong>SpamFox</strong><small>")
                .append(english ? "Native SPFBL core · content Bayes" : "Core nativo SPFBL · Bayes de conteúdo")
                .append("</small></span></a><nav><a href=\"/")
                .append(escapeAttribute(user.getEmail())).append("\">")
                .append(english ? "Mail panel" : "Painel de e-mails")
                .append("</a><a href=\"/admin/firewall/\">Firewall</a><button class=\"theme-toggle\" type=\"button\" data-theme-toggle><span data-theme-icon>☾</span><span data-theme-label>")
                .append(english ? "Dark theme" : "Tema escuro")
                .append("</span></button></nav></header>\n")
                .append("<section class=\"bayes-admin-heading\"><div><p class=\"bayes-eyebrow\">")
                .append(english ? "ADMINISTRATOR" : "ADMINISTRADOR")
                .append("</p><h1>").append(english ? "Core administration" : "Administração do core")
                .append("</h1><p>")
                .append(english ? "Monitor the native Bayes model, enroll customers and mail servers, and label RFC822 messages."
                        : "Acompanhe o Bayes nativo, cadastre clientes e servidores e classifique mensagens RFC822.")
                .append("</p></div><span class=\"bayes-live-pill ").append(enabled ? "is-active" : "is-idle")
                .append("\"><i></i>").append(enabled ? (english ? "Classifier active" : "Classificador ativo")
                        : (english ? "Classifier disabled" : "Classificador desativado"))
                .append("</span></section>\n")
                .append(renderRequestMetrics(user))
                .append("<section class=\"bayes-kpi-grid\" aria-label=\"")
                .append(english ? "Bayes key indicators" : "Indicadores do Bayes")
                .append("\">\n");
        appendKpi(html, english ? "SPAM samples" : "Amostras SPAM", spamDocs, "coral", "✉");
        appendKpi(html, english ? "HAM samples" : "Amostras HAM", hamDocs, "green", "✓");
        appendKpi(html, english ? "Known features" : "Termos conhecidos", vocabulary, "blue", "⌕");
        appendKpi(html, english ? "Content-enabled clients" : "Clientes habilitados para conteúdo", allowed, "purple", "⌘");
        html.append("</section>\n<section class=\"bayes-admin-grid\"><article class=\"bayes-card bayes-status-card\"><div class=\"bayes-card-heading\"><div><p class=\"bayes-eyebrow\">")
                .append(english ? "CORE HEALTH" : "SAÚDE DO CORE")
                .append("</p><h2>").append(english ? "Service status" : "Status do serviço")
                .append("</h2></div><span class=\"bayes-status-dot\"></span></div><dl class=\"bayes-status-list\">");
        appendStatus(html, english ? "SPFBL core" : "Core SPFBL", english ? "Online" : "Online", "ok");
        appendStatus(html, english ? "Bayes model" : "Modelo Bayes",
                enabled ? (english ? "Enabled" : "Habilitado") : (english ? "Disabled" : "Desabilitado"),
                enabled ? "ok" : "warn");
        appendStatus(html, english ? "Model storage" : "Persistência do modelo",
                writable ? (english ? "Writable" : "Gravável") : (english ? "Read only / failed" : "Somente leitura / falha"),
                writable ? "ok" : "bad");
        appendStatus(html, english ? "Minimum per class" : "Mínimo por classe", minimum, "neutral");
        appendStatus(html, english ? "Spam confidence threshold" : "Limite de confiança SPAM", threshold, "neutral");
        appendStatus(html, english ? "Decision-enabled clients" : "Clientes com decisão habilitada", decision, "neutral");
        html.append("</dl><p class=\"bayes-help\">")
                .append(english ? "Register a content client first; enable delivery decisions only after its SPAMD integration was validated."
                        : "Cadastre primeiro o cliente de conteúdo; habilite decisões de entrega somente após validar sua integração SPAMD.")
                .append("</p></article>\n")
                .append("<article class=\"bayes-card bayes-training-card\"><div class=\"bayes-card-heading\"><div><p class=\"bayes-eyebrow\">")
                .append(english ? "MANUAL LABELING" : "ROTULAGEM MANUAL")
                .append("</p><h2>").append(english ? "Train from .eml files" : "Treinar com arquivos .eml")
                .append("</h2></div><span class=\"bayes-card-icon\">⇧</span></div>")
                .append("<p class=\"bayes-help\">")
                .append(english ? "Choose the correct label. Messages are processed in memory and their original files are not retained."
                        : "Escolha o rótulo correto. As mensagens são processadas em memória e os arquivos originais não são guardados.")
                .append("</p><form class=\"bayes-upload-form\" method=\"post\" enctype=\"multipart/form-data\" action=\"/admin/bayes/learn\">")
                .append("<input type=\"hidden\" name=\"csrf\" value=\"").append(escapeAttribute(tokens.training)).append("\">")
                .append("<fieldset><legend>").append(english ? "Message label" : "Classificação das mensagens")
                .append("</legend><label class=\"bayes-label-option spam-label\"><input type=\"radio\" name=\"label\" value=\"SPAM\" required><span><b>SPAM</b><small>")
                .append(english ? "Unwanted or malicious" : "Indesejada ou maliciosa")
                .append("</small></span></label><label class=\"bayes-label-option ham-label\"><input type=\"radio\" name=\"label\" value=\"HAM\" required><span><b>HAM</b><small>")
                .append(english ? "Legitimate message" : "Mensagem legítima")
                .append("</small></span></label></fieldset><label class=\"bayes-file-picker\"><span class=\"bayes-file-symbol\">＋</span><span><b>")
                .append(english ? "Select .eml files" : "Selecionar arquivos .eml")
                .append("</b><small>").append(english ? "Up to 10 files · 5 MiB each · 20 MiB per batch"
                        : "Até 10 arquivos · 5 MiB por arquivo · 20 MiB por lote")
                .append("</small><input type=\"file\" name=\"eml\" accept=\".eml,message/rfc822\" multiple required></span></label><button class=\"bayes-submit\" type=\"submit\">")
                .append(english ? "Train native Bayes" : "Treinar Bayes nativo")
                .append("</button></form></article></section>\n");
        if (report != null) {
            html.append("<section class=\"bayes-card bayes-report ").append(report.error ? "is-error" : "is-success")
                    .append("\"><h2>").append(english ? "Training result" : "Resultado do treinamento")
                    .append("</h2><p>").append(escapeHtml(report.notice)).append("</p>");
            if (report.results != null && !report.results.isEmpty()) {
                html.append("<div class=\"bayes-results-wrap\"><table class=\"bayes-results\"><thead><tr><th>")
                        .append(english ? "File" : "Arquivo").append("</th><th>")
                        .append(english ? "Result" : "Resultado").append("</th></tr></thead><tbody>");
                for (LearnResult result : report.results) {
                    html.append("<tr><td>").append(escapeHtml(result.filename)).append("</td><td>")
                            .append(escapeHtml(statusLabel(result.status, english))).append("</td></tr>");
                }
                html.append("</tbody></table></div>");
            }
            html.append("</section>\n");
        }
        appendClientManagement(html, tokens.clients, clientReport, english);
        appendClientList(html, english ? "Clients eligible for content inspection" : "Clientes elegíveis para inspeção de conteúdo",
                ContentBayes.allowedClients(), english);
        appendClientList(html, english ? "Clients with active delivery decisions" : "Clientes com decisão de entrega ativa",
                ContentBayes.decisionClients(), english);
        html.append("<footer class=\"bayes-admin-footer\"><span>")
                .append(english ? "SpamFox content controls powered by the SPFBL core." : "Controle de conteúdo SpamFox executado pelo core SPFBL.")
                .append("</span><span>").append(escapeHtml(user.getEmail())).append("</span></footer></main></body></html>");
        return html.toString();
    }

    static String renderRequestMetrics(User user) {
        boolean english = user.getLocale() != null && "en".equalsIgnoreCase(user.getLocale().getLanguage());
        ArrayList<Client> clients = Client.getSet();
        ClientRequestMetrics.Snapshot metrics = ClientRequestMetrics.snapshot(clients);
        java.text.NumberFormat numbers = java.text.NumberFormat.getIntegerInstance(user.getLocale() == null
                ? Locale.forLanguageTag("pt-BR") : user.getLocale());
        StringBuilder html = new StringBuilder(4096);
        html.append("<section class=\"bayes-card bayes-request-metrics\" id=\"requests\"><div class=\"bayes-card-heading\"><div><p class=\"bayes-eyebrow\">")
                .append(english ? "REGISTERED SERVER TRAFFIC" : "TRÁFEGO DOS SERVIDORES CADASTRADOS")
                .append("</p><h2>").append(english ? "Requests and reputation queries" : "Requests e consultas de reputação")
                .append("</h2></div><form method=\"get\" action=\"/admin/bayes/#requests\"><button class=\"bayes-submit\" type=\"submit\">")
                .append(english ? "Refresh" : "Atualizar").append("</button></form></div>")
                .append("<div class=\"bayes-kpi-grid request-kpi-grid\">");
        appendKpi(html, english ? "Total TCP requests" : "Total de requests TCP", numbers.format(metrics.requests), "blue", "↗");
        appendKpi(html, english ? "Total reputation queries" : "Total de consultas de reputação", numbers.format(metrics.queries), "purple", "⌕");
        appendKpi(html, english ? "Registered servers" : "Servidores cadastrados", numbers.format(metrics.rows.size()), "green", "⌘");
        html.append("</div><p class=\"bayes-help\">")
                .append(english ? "Accumulated since " : "Acumulado desde ").append(metricTime(metrics.since, user))
                .append(english ? ". Totals equal the currently registered server rows. Older logs are not imported. TCP requests include VERSION and feedback; reputation queries count SPF, CHECK, legacy commands and Postfix RCPT checks. Retries count again; these are not unique emails."
                        : ". O total corresponde às linhas dos servidores atualmente cadastrados. Logs anteriores não são importados. Requests incluem VERSION e feedback; consultas de reputação contam SPF, CHECK, formato legado e verificações RCPT do Postfix. Tentativas repetidas contam novamente; não são e-mails únicos.")
                .append("</p><p class=\"bayes-help\">")
                .append(english ? "Counters refresh on page load and are saved every 60 seconds and by the core STORE operation. An abrupt failure may lose the last unsaved interval. Time zone: "
                        : "Os contadores são atualizados ao carregar a página e salvos a cada 60 segundos e pelo STORE do core. Uma falha abrupta pode perder o último intervalo ainda não salvo. Fuso: ")
                .append(escapeHtml((user.getTimeZone() == null ? java.util.TimeZone.getDefault() : user.getTimeZone()).getID()))
                .append(".</p>");
        if (!metrics.persistenceHealthy) html.append("<p class=\"bayes-client-notice is-error\" role=\"alert\">")
                .append(english ? "Metrics collection or persistence failed. Check core logs; the existing file is preserved if loading failed."
                        : "Falha na coleta ou persistência dos contadores. Confira os logs do core; um arquivo que falhou ao carregar é preservado.").append("</p>");
        html.append("<div class=\"bayes-results-wrap\"><table class=\"bayes-results\"><thead><tr><th>Hostname</th><th>IP / CIDR</th><th>")
                .append(english ? "Customer" : "Cliente").append("</th><th>Requests TCP</th><th>")
                .append(english ? "Reputation queries" : "Consultas de reputação").append("</th><th>")
                .append(english ? "Last request" : "Última request").append("</th></tr></thead><tbody>");
        for (Client client : clients) {
            ClientRequestMetrics.Counts counts = metrics.rows.get(client.getCIDR());
            html.append("<tr><td>").append(escapeHtml(client.getDomain())).append("</td><td><code>")
                    .append(escapeHtml(client.getCIDR())).append("</code></td><td>")
                    .append(escapeHtml(client.getEmail() == null ? "—" : client.getEmail()))
                    .append("</td><td class=\"request-number\">").append(numbers.format(counts.requests))
                    .append("</td><td class=\"request-number\">").append(numbers.format(counts.queries))
                    .append("</td><td>").append(counts.last == 0 ? "—" : metricTime(counts.last, user)).append("</td></tr>");
        }
        if (clients.isEmpty()) html.append("<tr><td colspan=\"6\">")
                .append(english ? "No servers registered." : "Nenhum servidor cadastrado.").append("</td></tr>");
        html.append("</tbody><tfoot><tr><th colspan=\"3\">Total</th><td class=\"request-number\">")
                .append(numbers.format(metrics.requests)).append("</td><td class=\"request-number\">")
                .append(numbers.format(metrics.queries)).append("</td><td>—</td></tr></tfoot></table></div></section>");
        return html.toString();
    }

    private static String metricTime(long timestamp, User user) {
        java.util.TimeZone zone = user.getTimeZone() == null ? java.util.TimeZone.getDefault() : user.getTimeZone();
        return java.time.Instant.ofEpochMilli(timestamp).atZone(zone.toZoneId())
                .format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss"));
    }

    private static void appendClientManagement(StringBuilder html, String csrfToken,
            ClientReport report, boolean english) {
        ArrayList<Client> clients = Client.getSet();
        TreeSet<String> customers = Client.getEmailSet();
        html.append("<section class=\"bayes-card bayes-client-management\"><div class=\"bayes-card-heading\"><div><p class=\"bayes-eyebrow\">")
                .append(english ? "CUSTOMER ACCESS" : "ACESSO DOS CLIENTES")
                .append("</p><h2>").append(english ? "Customers and mail servers" : "Clientes e servidores de e-mail")
                .append("</h2></div><span class=\"bayes-client-count\">").append(clients.size()).append("</span></div><p class=\"bayes-help\">")
                .append(english
                        ? "This uses native CLIENT ADD and creates a web user when needed. New accounts receive the core's TOTP setup email; existing credentials are left alone. Bayes delivery decisions can be enabled per SPFBL server below; they may reject high-confidence spam only while the global model is enabled and the server routes eligible messages to this core."
                        : "O cadastro usa CLIENT ADD e cria o usuário web quando necessário. Contas novas recebem o e-mail de configuração TOTP do core; credenciais existentes não são alteradas. A decisão Bayes pode ser habilitada por servidor abaixo; mensagens com alta confiança de SPAM poderão ser rejeitadas quando o modelo global estiver ativo e o servidor enviar mensagens elegíveis para este core.")
                .append("</p>");
        if (report != null) {
            html.append("<div class=\"bayes-client-notice ").append(report.error ? "is-error" : "is-success")
                    .append("\" role=\"status\">").append(escapeHtml(report.notice)).append("</div>");
        }
        html.append("<div class=\"bayes-client-form-grid\"><form class=\"bayes-client-form\" method=\"post\" action=\"")
                .append(CLIENT_PATH).append("\"><input type=\"hidden\" name=\"csrf\" value=\"")
                .append(escapeAttribute(csrfToken)).append("\"><input type=\"hidden\" name=\"action\" value=\"register\"><h3>")
                .append(english ? "Register customer and first server" : "Cadastrar cliente e primeiro servidor")
                .append("</h3><label>").append(english ? "Customer contact email" : "E-mail de contato do cliente")
                .append("<input type=\"email\" name=\"customer_email\" maxlength=\"320\" autocomplete=\"email\" required></label>")
                .append(clientInput(english ? "Customer name for web access" : "Nome do cliente para acesso web", "customer_name", "Example Company", 120, true))
                .append(clientInput(english ? "Server hostname" : "Hostname do servidor", "hostname", "mail.example.com", 253))
                .append(clientInput(english ? "Public IP or CIDR" : "IP público ou CIDR", "cidr", "203.0.113.10/32", 80))
                .append(permissionSelect(english)).append("<button class=\"bayes-submit\" type=\"submit\">")
                .append(english ? "Register customer" : "Cadastrar cliente").append("</button></form>")
                .append("<form class=\"bayes-client-form\" method=\"post\" action=\"").append(CLIENT_PATH)
                .append("\"><input type=\"hidden\" name=\"csrf\" value=\"").append(escapeAttribute(csrfToken))
                .append("\"><input type=\"hidden\" name=\"action\" value=\"add-server\"><h3>")
                .append(english ? "Add another server" : "Adicionar outro servidor").append("</h3><label>")
                .append(english ? "Customer" : "Cliente").append("<select name=\"customer_email\" required>");
        if (customers.isEmpty()) {
            html.append("<option value=\"\" disabled selected>")
                    .append(english ? "Register the first customer first" : "Cadastre primeiro um cliente")
                    .append("</option>");
        } else {
            for (String email : customers) {
                html.append("<option value=\"").append(escapeAttribute(email)).append("\">")
                        .append(escapeHtml(email)).append("</option>");
            }
        }
        html.append("</select></label>")
                .append(clientInput(english ? "Customer name if web access is new" : "Nome do cliente se o acesso web ainda não existir", "customer_name", "Example Company", 120, false))
                .append(clientInput(english ? "Server hostname" : "Hostname do servidor", "hostname", "mx2.example.com", 253))
                .append(clientInput(english ? "Public IP or CIDR" : "IP público ou CIDR", "cidr", "203.0.113.11/32", 80))
                .append(permissionSelect(english)).append("<button class=\"bayes-submit\" type=\"submit\"")
                .append(customers.isEmpty() ? " disabled" : "").append(">")
                .append(english ? "Add server" : "Adicionar servidor").append("</button></form></div>")
                .append("<div class=\"bayes-results-wrap bayes-server-table-wrap\"><table class=\"bayes-results bayes-server-table\"><thead><tr><th>")
                .append(english ? "Customer" : "Cliente").append("</th><th>")
                .append(english ? "Hostname" : "Hostname").append("</th><th>")
                .append(english ? "IP / CIDR" : "IP / CIDR").append("</th><th>")
                .append(english ? "Access" : "Acesso").append("</th><th>")
                .append(english ? "Bayes delivery decision" : "Decisão de entrega Bayes")
                .append("</th></tr></thead><tbody>");
        for (Client client : clients) {
            boolean spfblPermission = client.isPermission("SPFBL");
            boolean decisionEnabled = ContentBayes.hasDecisionClient(client.getCIDR());
            boolean bayesEnabled = ContentBayes.isEnabled();
            html.append("<tr><td>").append(escapeHtml(client.getEmail() == null
                    ? (english ? "Unassigned" : "Sem cliente associado") : client.getEmail()))
                    .append("</td><td>").append(escapeHtml(client.getDomain())).append("</td><td><code>")
                    .append(escapeHtml(client.getCIDR())).append("</code></td><td><span class=\"bayes-permission-tag\">")
                    .append(escapeHtml(client.isAdministrator() ? "ADMIN" : client.getPermission().name()))
                    .append("</span></td><td class=\"bayes-decision-cell\">");
            if (!spfblPermission) {
                html.append("<span class=\"bayes-decision-state is-unavailable\">")
                        .append(english ? "Requires SPFBL permission" : "Exige permissão SPFBL")
                        .append("</span>");
            } else {
                String stateClass = decisionEnabled ? (bayesEnabled ? "is-enabled" : "is-paused") : "is-disabled";
                String stateLabel = decisionEnabled
                        ? (bayesEnabled
                                ? (english ? "Active" : "Ativa")
                                : (english ? "Configured · model paused" : "Configurada · modelo pausado"))
                        : (english ? "Inactive" : "Inativa");
                String decisionAction = decisionEnabled ? "decision-disable" : "decision-enable";
                String buttonLabel = decisionEnabled
                        ? (english ? "Disable" : "Desativar")
                        : (english ? "Enable" : "Ativar");
                html.append("<span class=\"bayes-decision-state ").append(stateClass).append("\">")
                        .append(stateLabel).append("</span><form class=\"bayes-decision-form\" method=\"post\" action=\"")
                        .append(CLIENT_PATH).append("\"><input type=\"hidden\" name=\"csrf\" value=\"")
                        .append(escapeAttribute(csrfToken)).append("\"><input type=\"hidden\" name=\"action\" value=\"")
                        .append(decisionAction).append("\"><input type=\"hidden\" name=\"cidr\" value=\"")
                        .append(escapeAttribute(client.getCIDR())).append("\"><button class=\"bayes-submit bayes-small-submit")
                        .append(decisionEnabled ? " is-danger" : "").append("\" type=\"submit\">")
                        .append(buttonLabel).append("</button></form>");
            }
            html.append("</td></tr>");
        }
        if (clients.isEmpty()) {
            html.append("<tr><td colspan=\"5\" class=\"bayes-empty\">")
                    .append(english ? "No customer servers registered." : "Nenhum servidor de cliente cadastrado.")
                    .append("</td></tr>");
        }
        html.append("</tbody></table></div></section>");
    }

    private static String clientInput(String label, String name, String placeholder, int maxLength) {
        return clientInput(label, name, placeholder, maxLength, true);
    }

    private static String clientInput(String label, String name, String placeholder,
            int maxLength, boolean required) {
        return "<label>" + label + "<input type=\"text\" name=\"" + name + "\" maxlength=\""
                + maxLength + "\" placeholder=\"" + escapeAttribute(placeholder) + "\""
                + (required ? " required" : "") + "></label>";
    }

    private static String permissionSelect(boolean english) {
        return "<label>" + (english ? "Permission" : "Permissão")
                + "<select name=\"permission\" required><option value=\"SPFBL\" selected>SPFBL</option>"
                + "<option value=\"DNSBL\">DNSBL</option><option value=\"NONE\">NONE</option></select></label>";
    }

    private static void appendKpi(StringBuilder html, String label, String value, String color, String icon) {
        html.append("<article class=\"bayes-kpi bayes-kpi-").append(color)
                .append("\"><span class=\"bayes-kpi-icon\" aria-hidden=\"true\">").append(icon)
                .append("</span><span class=\"bayes-kpi-copy\"><small>").append(label)
                .append("</small><strong>").append(escapeHtml(value)).append("</strong></span></article>");
    }

    private static void appendStatus(StringBuilder html, String label, String value, String status) {
        html.append("<div class=\"bayes-status-row\"><dt>").append(label)
                .append("</dt><dd class=\"status-").append(status).append("\">")
                .append(escapeHtml(value)).append("</dd></div>");
    }

    private static void appendClientList(StringBuilder html, String title, String entries, boolean english) {
        String[] clients = entries.trim().isEmpty() || "EMPTY".equals(entries.trim())
                ? new String[0] : entries.trim().split("\\R");
        html.append("<section class=\"bayes-card bayes-client-card\"><div class=\"bayes-card-heading\"><h2>")
                .append(title).append("</h2><span class=\"bayes-client-count\">").append(clients.length)
                .append("</span></div><div class=\"bayes-client-list\">");
        if (clients.length == 0) {
            html.append("<p class=\"bayes-empty\">").append(english ? "No clients enrolled." : "Nenhum cliente cadastrado.").append("</p>");
        } else {
            for (String client : clients) {
                html.append("<code>").append(escapeHtml(client)).append("</code>");
            }
        }
        html.append("</div></section>");
    }

    private static String renderAccessDenied(boolean loginRequired, boolean customerMode) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"UTF-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Acesso restrito · SpamFox</title>")
                .append("<link rel=\"stylesheet\" href=\"/style.css?v=spamfox-ui-20261017-2\"><script src=\"/theme.js?v=spamfox-ui-20261017\" defer></script>")
                .append("</head><body class=\"bayes-admin-page\"><main class=\"bayes-access-card\"><img src=\"/logo.png\" alt=\"SpamFox\"><h1>Acesso restrito</h1><p>")
                .append(loginRequired
                        ? (customerMode ? "Entre primeiro pelo painel de e-mails da sua conta e acesse esta área novamente."
                                : "Entre com uma conta administradora do SPFBL para abrir este painel.")
                        : (customerMode ? "Esta conta não possui servidores de e-mail cadastrados no core."
                                : "Esta área está disponível somente para administradores do SPFBL."))
                .append("</p>");
        String adminEmail = Core.getAdminEmail();
        if (loginRequired && !customerMode && adminEmail != null) {
            html.append("<a class=\"bayes-submit\" href=\"/").append(escapeAttribute(adminEmail)).append("\">Entrar como administrador</a>");
        }
        html.append("</main></body></html>");
        return html.toString();
    }

    private static String statusLabel(ContentBayes.LearnStatus status, boolean english) {
        if (status == null) return english ? "Invalid message" : "Mensagem inválida";
        switch (status) {
            case ADDED: return english ? "Added to Bayes" : "Adicionada ao Bayes";
            case DUPLICATE: return english ? "Already learned with this label" : "Já treinada com este rótulo";
            case LABEL_CONFLICT: return english ? "Already registered with the opposite label" : "Já cadastrada com o rótulo oposto";
            case TOO_SMALL: return english ? "Not enough text to learn" : "Texto insuficiente para aprendizado";
            default: return english ? "Model limit reached" : "Limite do modelo atingido";
        }
    }

    private static Map<String,String> parseStats(String text) {
        Map<String,String> result = new HashMap<>();
        for (String line : text.split("\\R")) {
            int index = line.indexOf(' ');
            if (index > 0) result.put(line.substring(0, index), line.substring(index + 1).trim());
        }
        return result;
    }

    private static String value(Map<String,String> values, String key, String fallback) {
        String value = values.get(key);
        return value == null ? fallback : value;
    }

    private static String getBoundary(String contentType) {
        if (contentType == null || !contentType.toLowerCase(Locale.ROOT).startsWith("multipart/form-data")) {
            return null;
        }
        Matcher matcher = BOUNDARY_PATTERN.matcher(contentType);
        if (!matcher.find()) return null;
        String boundary = matcher.group(1) == null ? matcher.group(2) : matcher.group(1);
        if (boundary == null || boundary.length() < 1 || boundary.length() > 70
                || !boundary.matches("[A-Za-z0-9'()+_,./:=?-]+")) {
            return null;
        }
        return boundary;
    }

    static MultipartForm parseMultipart(byte[] body, String boundary) throws UploadException {
        if (body == null || body.length == 0 || boundary == null) {
            throw new UploadException(400, "Formulário de upload vazio.");
        }
        byte[] marker = ("--" + boundary).getBytes(StandardCharsets.US_ASCII);
        byte[] separator = ("\r\n--" + boundary).getBytes(StandardCharsets.US_ASCII);
        if (!matchesAt(body, 0, marker)) {
            throw new UploadException(400, "Formato multipart inválido.");
        }
        MultipartForm form = new MultipartForm();
        int cursor = marker.length;
        int totalFilesBytes = 0;
        boolean closed = false;
        while (cursor < body.length) {
            if (hasClosingMarker(body, cursor)) {
                closed = true;
                break;
            }
            if (!matchesAt(body, cursor, new byte[]{13, 10})) {
                throw new UploadException(400, "Separador multipart inválido.");
            }
            int headerStart = cursor + 2;
            int headerEnd = indexOf(body, new byte[]{13, 10, 13, 10}, headerStart);
            if (headerEnd < 0) throw new UploadException(400, "Cabeçalho multipart incompleto.");
            int dataStart = headerEnd + 4;
            int nextPart = indexOf(body, separator, dataStart);
            if (nextPart < 0) throw new UploadException(400, "Parte multipart sem fechamento.");
            String headers = new String(body, headerStart, headerEnd - headerStart, StandardCharsets.ISO_8859_1);
            Map<String,String> disposition = parseDisposition(headers);
            String name = disposition.get("name");
            String filename = disposition.get("filename");
            int dataLength = nextPart - dataStart;
            if (dataLength < 0) throw new UploadException(400, "Parte multipart inválida.");
            if (filename != null && !filename.isEmpty()) {
                if (!"eml".equals(name)) throw new UploadException(400, "Campo de arquivo inválido.");
                if (form.files.size() >= MAX_FILES) throw new UploadException(413, "O limite é de 10 arquivos por lote.");
                if (dataLength == 0 || dataLength > MAX_FILE_BYTES) {
                    throw new UploadException(413, "Cada arquivo deve ter entre 1 byte e 5 MiB.");
                }
                totalFilesBytes += dataLength;
                if (totalFilesBytes > MAX_BATCH_BYTES) {
                    throw new UploadException(413, "O lote excede o limite de 20 MiB.");
                }
                String safeName = filename.replace('\\', '/');
                safeName = safeName.substring(safeName.lastIndexOf('/') + 1);
                if (safeName.length() > 180 || containsControl(safeName)) {
                    throw new UploadException(400, "Nome de arquivo inválido.");
                }
                byte[] fileBytes = new byte[dataLength];
                System.arraycopy(body, dataStart, fileBytes, 0, dataLength);
                form.files.add(new UploadedEml(safeName, fileBytes));
            } else {
                if (dataLength > 4096) throw new UploadException(400, "Campo de formulário grande demais.");
                String value = new String(body, dataStart, dataLength, StandardCharsets.UTF_8);
                if ("csrf".equals(name)) {
                    if (form.csrfToken != null) throw new UploadException(400, "Token repetido.");
                    form.csrfToken = value.trim();
                } else if ("label".equals(name)) {
                    if (form.label != null) throw new UploadException(400, "Rótulo repetido.");
                    form.label = value.trim();
                } else {
                    throw new UploadException(400, "Campo de formulário desconhecido.");
                }
            }
            cursor = nextPart + separator.length;
            if (hasClosingMarker(body, cursor)) {
                closed = true;
                break;
            }
        }
        if (!closed) throw new UploadException(400, "Fechamento multipart ausente.");
        if (form.csrfToken == null || form.label == null) {
            throw new UploadException(400, "Formulário incompleto.");
        }
        return form;
    }

    private static Map<String,String> parseDisposition(String headers) throws UploadException {
        String disposition = null;
        for (String line : headers.split("\\r\\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-disposition:")) {
                disposition = line.substring(line.indexOf(':') + 1).trim();
                break;
            }
        }
        if (disposition == null || !disposition.toLowerCase(Locale.ROOT).startsWith("form-data")) {
            throw new UploadException(400, "Content-Disposition inválido.");
        }
        Map<String,String> result = new HashMap<>();
        Matcher matcher = PARAMETER_PATTERN.matcher(disposition);
        while (matcher.find()) result.put(matcher.group(1).toLowerCase(Locale.ROOT), unescapeQuoted(matcher.group(2)));
        if (!result.containsKey("name")) throw new UploadException(400, "Campo multipart sem nome.");
        return result;
    }

    private static String unescapeQuoted(String value) {
        return value.replace("\\\"", "\"").replace("\\\\", "\\");
    }

    private static boolean containsControl(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (Character.isISOControl(value.charAt(index))) return true;
        }
        return false;
    }

    private static boolean hasClosingMarker(byte[] source, int offset) {
        if (!matchesAt(source, offset, new byte[]{45, 45})) {
            return false;
        }
        int end = offset + 2;
        return end == source.length
                || (matchesAt(source, end, new byte[]{13, 10}) && end + 2 == source.length);
    }

    private static boolean matchesAt(byte[] source, int offset, byte[] target) {
        if (offset < 0 || offset + target.length > source.length) return false;
        for (int index = 0; index < target.length; index++) {
            if (source[offset + index] != target[index]) return false;
        }
        return true;
    }

    private static int indexOf(byte[] source, byte[] target, int offset) {
        for (int index = Math.max(0, offset); index <= source.length - target.length; index++) {
            if (matchesAt(source, index, target)) return index;
        }
        return -1;
    }

    private static byte[] readBounded(HttpExchange exchange, int maxBytes) throws IOException, UploadException {
        try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = exchange.getRequestBody().read(buffer)) != -1) {
                if (output.size() + count > maxBytes) {
                    throw new UploadException(413, "O lote excede o limite de 20 MiB.");
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    static String issueCsrfToken(String email) {
        long now = System.currentTimeMillis();
        CSRF_TOKENS.entrySet().removeIf(entry -> entry.getValue().expiresAt < now);
        if (CSRF_TOKENS.size() >= MAX_CSRF_TOKENS) return null;
        String token = UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        CSRF_TOKENS.put(token, new CsrfGrant(email, now + CSRF_TTL_MILLIS));
        return token;
    }

    static boolean consumeCsrfToken(String token, String email) {
        if (token == null) return false;
        CsrfGrant grant = CSRF_TOKENS.remove(token);
        return grant != null && grant.expiresAt >= System.currentTimeMillis()
                && grant.email.equals(email);
    }

    private static String escapeHtml(String value) {
        return StringEscapeUtils.escapeHtml4(value == null ? "" : value);
    }

    private static String escapeAttribute(String value) {
        return escapeHtml(value).replace("`", "&#96;");
    }

    private static void send(HttpExchange exchange, int code, String type, String text) throws IOException {
        byte[] body = text.getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        headers.set("Content-Type", type);
        headers.set("Cache-Control", "no-store, max-age=0");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
        if (exchange.getRequestMethod().equals("HEAD")) {
            exchange.sendResponseHeaders(code, -1);
        } else {
            exchange.sendResponseHeaders(code, body.length);
            try (OutputStream output = exchange.getResponseBody()) {
                output.write(body);
            }
        }
    }

    static final class MultipartForm {
        String csrfToken;
        String label;
        final List<UploadedEml> files = new ArrayList<>();
    }

    static final class DashboardTokens {
        final String training;
        final String clients;
        DashboardTokens(String training, String clients) {
            this.training = training;
            this.clients = clients;
        }
    }

    static final class ClientReport {
        private final String notice;
        private final boolean error;
        private ClientReport(String notice, boolean error) {
            this.notice = notice;
            this.error = error;
        }
    }

    static final class UploadedEml {
        final String filename;
        final byte[] bytes;
        UploadedEml(String filename, byte[] bytes) { this.filename = filename; this.bytes = bytes; }
    }

    static final class UploadException extends Exception {
        final int statusCode;
        UploadException(int statusCode, String message) { super(message); this.statusCode = statusCode; }
    }

    private static final class CsrfGrant {
        private final String email;
        private final long expiresAt;
        private CsrfGrant(String email, long expiresAt) { this.email = email; this.expiresAt = expiresAt; }
    }

    private static final class LearnResult {
        private final String filename;
        private final ContentBayes.LearnStatus status;
        private LearnResult(String filename, ContentBayes.LearnStatus status) {
            this.filename = filename;
            this.status = status;
        }
    }

    private static final class UploadReport {
        private final List<LearnResult> results;
        private final String notice;
        private final boolean error;
        private UploadReport(List<LearnResult> results, String notice, boolean error) {
            this.results = results;
            this.notice = notice;
            this.error = error;
        }
    }
}
