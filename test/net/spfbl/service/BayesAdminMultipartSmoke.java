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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import net.spfbl.core.Client;
import net.spfbl.core.User;
import net.spfbl.data.ContentBayes;

/** Focused smoke tests for the admin upload parser. */
public final class BayesAdminMultipartSmoke {

    private static final String BOUNDARY = "----SpamFoxBoundary8d6c15";

    private BayesAdminMultipartSmoke() {
    }

    public static void main(String[] args) throws Exception {
        byte[] eml = ("From: sender@example.test\r\n"
                + "To: abuse@example.test\r\n"
                + "Subject: multipart parser control\r\n"
                + "\r\n"
                + "Message body with boundary-like text --not-the-boundary\r\n")
                .getBytes(StandardCharsets.UTF_8);
        byte[] body = multipart("eml", "C:\\\\mail\\\\spam.eml", eml, true);
        BayesAdminHandler.MultipartForm form = BayesAdminHandler.parseMultipart(body, BOUNDARY);
        require("csrf-smoke-token".equals(form.csrfToken), "CSRF field was not parsed.");
        require("SPAM".equals(form.label), "Label field was not parsed.");
        require(form.files.size() == 1, "Expected exactly one uploaded file.");
        require("spam.eml".equals(form.files.get(0).filename), "Client path was not reduced to a basename.");
        require(Arrays.equals(eml, form.files.get(0).bytes), "Uploaded RFC822 bytes changed.");

        expectError(multipart("eml", "ham.eml", eml, false), 400,
                "Missing multipart close marker was accepted.");
        expectError(multipart("eml", "empty.eml", new byte[0], true), 413,
                "Empty upload was accepted.");
        expectError(multipart("unknown", "message.eml", eml, true), 400,
                "Unknown upload field was accepted.");
        java.util.Map<String,String> clientForm = BayesAdminHandler.parseUrlEncodedForm(
                ("csrf=token&action=register&customer_email=abuse%40example.test"
                + "&customer_name=Example%20Company&cidr=203.0.113.10%2F32&hostname=mx1.example.test&permission=SPFBL")
                .getBytes(StandardCharsets.UTF_8));
        require("abuse@example.test".equals(clientForm.get("customer_email")),
                "Client contact email was not decoded correctly.");
        require("203.0.113.10/32".equals(clientForm.get("cidr")),
                "CIDR was not decoded correctly.");
        java.util.Map<String,String> decisionForm = BayesAdminHandler.parseUrlEncodedForm(
                "csrf=token&action=decision-enable&cidr=203.0.113.10%2F32".getBytes(StandardCharsets.UTF_8));
        require("decision-enable".equals(decisionForm.get("action"))
                && "203.0.113.10/32".equals(decisionForm.get("cidr")),
                "Bayes decision client action was not parsed correctly.");
        expectClientFormError("csrf=token&action=register&action=add-server", 400,
                "Repeated client form field was accepted.");
        expectClientFormError("csrf=token&unknown=value", 400,
                "Unknown client form field was accepted.");
        Client firstServer = Client.create("203.0.113.10/32", "mx1.example.test",
                "SPFBL", "abuse@example.test");
        require(firstServer != null, "First native client server was not created.");
        require("abuse@example.test".equals(firstServer.getEmail()), "Client owner email was not stored.");
        require("mx1.example.test".equals(firstServer.getDomain()), "Server hostname was not stored.");
        require("SPFBL".equals(firstServer.getPermission().name()), "Server permission was not stored.");
        require(Client.create("203.0.113.10/32", "mx1.example.test",
                "SPFBL", "abuse@example.test") == null, "Duplicate native client CIDR was accepted.");
        require(BayesAdminHandler.hasRegisteredClient("ABUSE@example.test"),
                "Registered customer email was not matched case-insensitively.");
        require(!BayesAdminHandler.hasRegisteredClient("unmapped@example.test"),
                "An account without an enrolled mail server passed customer authorization.");
        require(Client.storeNow(), "Native client registration did not persist.");
        require(new java.io.File("./data/client.map").isFile(), "Native client map was not written.");
        User user = User.create("abuse@example.test", "Example Company");
        require(user != null && "abuse@example.test".equals(user.getEmail()),
                "Native web user was not created for the customer.");
        require(!user.hasPassword() && !user.hasSecretOTP(),
                "New customer account must not be assigned a static password or secret without TOTP onboarding.");
        require(User.storeMap(), "Native user account did not persist.");
        require(new java.io.File("./data/user.map").isFile(), "Native user map was not written.");
        ContentBayes.load();
        String adminPage = BayesAdminHandler.renderDashboard(user,
                new BayesAdminHandler.DashboardTokens("training-token", "client-token"), null, null);
        require((adminPage.contains("Decisão de entrega Bayes")
                || adminPage.contains("Bayes delivery decision"))
                && adminPage.contains("value=\"decision-enable\"")
                && adminPage.contains("value=\"203.0.113.10/32\""),
                "Admin server table did not render its per-server Bayes decision control.");
        require("ACTIVE".equals(BayesAdminHandler.updateBayesDecisionClient(
                "decision-enable", "203.0.113.10/32")),
                "Admin could not activate a registered SPFBL server for Bayes decisions.");
        require(ContentBayes.hasAllowedClient("203.0.113.10/32")
                && ContentBayes.hasDecisionClient("203.0.113.10/32"),
                "Bayes activation did not persist both content eligibility and delivery decision scope.");
        require("ALREADY_ACTIVE".equals(BayesAdminHandler.updateBayesDecisionClient(
                "decision-enable", "203.0.113.10/32")),
                "Repeated Bayes activation was not idempotent.");
        require("INACTIVE".equals(BayesAdminHandler.updateBayesDecisionClient(
                "decision-disable", "203.0.113.10/32")),
                "Admin could not disable a server's Bayes delivery decision.");
        require(!ContentBayes.hasDecisionClient("203.0.113.10/32")
                && ContentBayes.hasAllowedClient("203.0.113.10/32"),
                "Disabling delivery decisions should retain passive content eligibility only.");
        Client dnsblServer = Client.create("203.0.113.11/32", "mx-dnsbl.example.test",
                "DNSBL", "abuse@example.test");
        require(dnsblServer != null && Client.storeNow(), "DNSBL-only fixture was not created.");
        require("SPFBL_REQUIRED".equals(BayesAdminHandler.updateBayesDecisionClient(
                "decision-enable", "203.0.113.11/32")),
                "Bayes decision activation accepted a server without SPFBL permission.");
        require(!ContentBayes.hasAllowedClient("203.0.113.11/32")
                && !ContentBayes.hasDecisionClient("203.0.113.11/32"),
                "Rejected DNSBL-only activation changed Bayes client state.");
        Client.drop("203.0.113.11/32");
        require(Client.storeNow(), "DNSBL-only test fixture could not be removed.");
        String customerDashboard = BayesAdminHandler.renderCustomerDashboard(user, "single-use-token", null);
        require(customerDashboard.contains("action=\"/account/bayes/learn\""),
                "Customer dashboard did not post training to the customer-only endpoint.");
        require((customerDashboard.contains("Lista e status dos e-mails")
                || customerDashboard.contains("Email statuses"))
                && (customerDashboard.contains("Eventos recentes")
                || customerDashboard.contains("Recent events"))
                && (customerDashboard.contains("Treinar Bayes compartilhado")
                || customerDashboard.contains("Train shared Bayes")),
                "Customer dashboard is missing account KPIs or shared Bayes training controls.");
        require(!customerDashboard.contains("/admin/bayes/learn")
                && !customerDashboard.contains("Amostras SPAM"),
                "Customer dashboard exposed administrative Bayes controls or model internals.");
        BayesAdminHandler.CustomerKpis kpis = BayesAdminHandler.summarizeCustomerResults(
                Arrays.asList("ACCEPT", "WHITE", "REJECT", "BLOCK", "FLAG", "HOLD", "GREYLIST", "OTHER"));
        require(kpis.total == 8 && kpis.accepted == 2 && kpis.rejected == 2
                && kpis.suspicious == 1 && kpis.pending == 2 && kpis.other() == 1,
                "Customer email status KPIs were not grouped correctly.");
        for (int batch = 0; batch < 10; batch++) {
            require(BayesAdminHandler.reserveCustomerTrainingSlots("abuse@example.test", 10),
                    "Customer training quota rejected one of its 10-file batches.");
        }
        require(!BayesAdminHandler.reserveCustomerTrainingSlots("abuse@example.test", 1),
                "Customer training quota exceeded 100 files in the rolling window.");
        require(BayesAdminHandler.reserveCustomerTrainingSlots("other@example.test", 1),
                "Customer training quota was not isolated by account.");
        System.out.println("PASS: native Bayes admin multipart parser preserves EML and rejects malformed forms.");
        System.out.println("PASS: native client admin form parser validates fields and decodes CIDRs safely.");
        System.out.println("PASS: native client registration matches CLIENT ADD and persists client.map.");
        System.out.println("PASS: administrator can enable or disable Bayes delivery decisions per registered SPFBL server.");
        System.out.println("PASS: Bayes decision enrollment is idempotent, persists, and rejects non-SPFBL servers.");
        System.out.println("PASS: native customer user is created and persisted without a static password.");
        System.out.println("PASS: customer dashboard renders account KPIs and the shared-model upload without admin controls.");
        System.out.println("PASS: customer Bayes access requires an enrolled client email and account KPIs classify delivery states.");
        System.out.println("PASS: customer global Bayes training quota is limited and isolated by account.");
    }

    private static byte[] multipart(String fileField, String filename, byte[] eml, boolean close) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        write(output, "--" + BOUNDARY + "\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\ncsrf-smoke-token\r\n");
        write(output, "--" + BOUNDARY + "\r\nContent-Disposition: form-data; name=\"label\"\r\n\r\nSPAM\r\n");
        write(output, "--" + BOUNDARY + "\r\nContent-Disposition: form-data; name=\"" + fileField
                + "\"; filename=\"" + filename + "\"\r\n");
        write(output, "Content-Type: message/rfc822\r\n\r\n");
        output.write(eml);
        write(output, "\r\n--" + BOUNDARY + (close ? "--\r\n" : "\r\n"));
        return output.toByteArray();
    }

    private static void write(ByteArrayOutputStream output, String value) throws Exception {
        output.write(value.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static void expectError(byte[] body, int status, String message) throws Exception {
        try {
            BayesAdminHandler.parseMultipart(body, BOUNDARY);
            throw new IllegalStateException(message);
        } catch (BayesAdminHandler.UploadException ex) {
            require(ex.statusCode == status, "Expected HTTP " + status + " but got " + ex.statusCode);
        }
    }

    private static void expectClientFormError(String value, int status, String message) throws Exception {
        try {
            BayesAdminHandler.parseUrlEncodedForm(value.getBytes(StandardCharsets.UTF_8));
            throw new IllegalStateException(message);
        } catch (BayesAdminHandler.UploadException ex) {
            require(ex.statusCode == status, "Expected HTTP " + status + " but got " + ex.statusCode);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
