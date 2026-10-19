/*
 * This file is part of SPFBL.
 *
 * SPFBL is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
package net.spfbl.data;

import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.lang.reflect.Method;
import java.net.InetAddress;
import net.spfbl.core.AdministrationTCP;
import net.spfbl.core.Client;

public final class ContentBayesSmoke {

    private ContentBayesSmoke() {
    }

    public static void main(String[] args) throws Exception {
        File data = new File("data");
        if (!data.isDirectory() && !data.mkdirs()) {
            throw new IllegalStateException("Could not create isolated test data directory.");
        }
        ContentBayes.load();
        require(ContentBayes.stats().contains("ENABLED false\n"), "Bayes must start disabled.");
        verifyClassVocabularyReservation();
        ContentBayes.load();

        byte[] firstSpam = message(true, 0);
        require(ContentBayes.learn(firstSpam, true) == ContentBayes.LearnStatus.ADDED,
                "First spam sample must be learned.");
        require(ContentBayes.learn(firstSpam, true) == ContentBayes.LearnStatus.DUPLICATE,
                "Repeated sample must be deduplicated.");
        require(ContentBayes.learn(firstSpam, false) == ContentBayes.LearnStatus.LABEL_CONFLICT,
                "Conflicting sample label must be rejected.");

        File spamDirectory = new File("learn/spam");
        File hamDirectory = new File("learn/ham");
        if ((!spamDirectory.isDirectory() && !spamDirectory.mkdirs())
                || (!hamDirectory.isDirectory() && !hamDirectory.mkdirs())) {
            throw new IllegalStateException("Could not create Bayes training directories.");
        }
        for (int index = 1; index < 30; index++) {
            Files.write(new File(spamDirectory, "spam-" + index + ".eml").toPath(), message(true, index));
        }
        for (int index = 0; index < 30; index++) {
            Files.write(new File(hamDirectory, "ham-" + index + ".eml").toPath(), message(false, index));
        }
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES LEARN SPAM").contains("ADDED 29\n"),
                "BAYES LEARN SPAM command did not train the corpus.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES LEARN HAM").contains("ADDED 30\n"),
                "BAYES LEARN HAM command did not train the corpus.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES CLIENT SHOW").equals("EMPTY\n"),
                "Bayes client scope must be empty by default.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES DECISION SHOW").equals("EMPTY\n"),
                "Bayes decision scope must be empty by default.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES CLIENT ADD invalid")
                .equals("INVALID PARAMETERS\n"), "Bayes client allowlist must reject invalid CIDRs.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES CLIENT ADD 198.51.100.25/32")
                .equals("ADDED\n"), "Bayes client scope could not be enrolled.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES CLIENT ADD 198.51.100.25/32")
                .equals("ALREADY EXISTS\n"), "Bayes client scope must reject duplicates.");
        byte[] unknownCharset = new String(message(true, 9000), StandardCharsets.UTF_8)
                .replace("charset=UTF-8", "charset=amazonses").getBytes(StandardCharsets.UTF_8);
        require(ContentBayes.learn(unknownCharset, true) == ContentBayes.LearnStatus.ADDED,
                "Unknown MIME charset must fall back safely instead of rejecting the sample.");
        require(ContentBayes.classify(parse(message(true, 1000))) == null,
                "A trained but disabled model must not affect mail decisions.");
        require(ContentBayes.classifyForClient(parse(message(true, 1000)), "198.51.100.25/32") == null,
                "Bayes must remain inactive for client mail until enabled.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES ENABLE").equals("ENABLED\n"),
                "BAYES ENABLE admin command failed after the minimum corpus was trained.");

        ContentBayes.Prediction spam = ContentBayes.classify(parse(message(true, 1000)));
        ContentBayes.Prediction ham = ContentBayes.classify(parse(message(false, 1000)));
        require(spam != null && spam.isConfidentSpam(), "Spam fixture should score above threshold.");
        require(ham != null && ham.isConfidentHam(), "Ham fixture should score below the ham threshold.");
        spam = ContentBayes.classifyForClient(parse(message(true, 1000)), "198.51.100.25/32");
        require(spam == null, "Passive enrollment must not enable a mail decision.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES DECISION ADD 198.51.100.26/32")
                .equals("NOT ENROLLED\n"), "Decision scope must require content enrollment first.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES DECISION ADD 198.51.100.25/32")
                .equals("ADDED\n"), "Bayes decision scope could not be explicitly enrolled.");
        spam = ContentBayes.classifyForClient(parse(message(true, 1000)), "198.51.100.25/32");
        require(spam != null && spam.isConfidentSpam(), "Enrolled client should receive a Bayes decision.");
        require(ContentBayes.classifyForClient(parse(message(true, 1000)), "198.51.100.26/32") == null,
                "Unenrolled client must not receive a Bayes decision.");
        require(adminCommand(InetAddress.getByName("192.0.2.50"), "BAYES CLIENT ADD 198.51.100.26/32")
                .equals("NOT ADMIN\n"), "Remote unauthenticated client scope change must be denied.");
        require(ContentBayes.store(), "Model persistence failed.");
        File testDirectory = new File("learn/test");
        if (!testDirectory.isDirectory() && !testDirectory.mkdirs()) {
            throw new IllegalStateException("Could not create Bayes test sample directory.");
        }
        Files.write(new File(testDirectory, "spam.eml").toPath(), message(true, 1002));
        require(ContentBayes.scoreFile(new File(testDirectory, "spam.eml")) != null,
                "Offline score must expose a probability for benchmark analysis.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES TEST spam.eml")
                .startsWith("SPAM PROBABILITY "), "BAYES TEST command did not classify the sample.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES TEST ../outside.eml")
                .equals("INVALID PARAMETERS\n"), "BAYES TEST must reject path traversal.");
        require(adminCommand(InetAddress.getByName("192.0.2.50"), "BAYES STATS")
                .equals("NOT ADMIN\n"), "Remote unauthenticated Bayes admin access must be denied.");

        String persisted = new String(Files.readAllBytes(new File("data/content-bayes.db").toPath()),
                StandardCharsets.UTF_8);
        require(!persisted.contains("casino") && !persisted.contains("meeting"),
                "Model must not contain clear-text message terms.");
        ContentBayes.load();
        require(ContentBayes.stats().contains("ENABLED true\n"), "Enabled state must persist.");
        require(ContentBayes.isClientAllowed("198.51.100.25/32"), "Allowed client scope must persist.");
        require(ContentBayes.isDecisionClientAllowed("198.51.100.25/32"), "Decision scope must persist.");
        spam = ContentBayes.classify(parse(message(true, 1001)));
        require(spam != null && spam.isConfidentSpam(), "Spam prediction must survive reload.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES CLIENT DROP 198.51.100.25/32")
                .equals("DROPPED\n"), "Bayes client scope could not be withdrawn.");
        require(!ContentBayes.isClientAllowed("198.51.100.25/32"),
                "Withdrawn client must stop receiving Bayes decisions immediately.");
        require(!ContentBayes.hasDecisionClient("198.51.100.25/32"),
                "Withdrawing passive scope must also clear the decision scope.");
        require(ContentBayes.store(), "Client scope removal did not persist.");
        require(adminCommand(InetAddress.getLoopbackAddress(), "BAYES DISABLE").equals("DISABLED\n"),
                "BAYES DISABLE admin command failed.");
        ContentBayes.load();
        require(ContentBayes.stats().contains("ENABLED false\n"), "Disabled state must persist.");
        System.out.println("PASS: native Bayes train, classify, protect admin, persist and disable.");
    }

    private static void verifyClassVocabularyReservation() throws Exception {
        int nextFeature = 0;
        int learnedSpam = 0;
        boolean spamLimitReached = false;
        for (int sample = 0; sample < 240; sample++) {
            StringBuilder body = new StringBuilder();
            for (int index = 0; index < 1400; index++) {
                body.append("sfoxspamword").append(String.format("%08d", nextFeature++)).append(' ');
            }
            ContentBayes.LearnStatus status = ContentBayes.learn(
                    message("capacity-spam-" + sample, "Capacity check", body.toString()), true
            );
            if (status == ContentBayes.LearnStatus.LIMIT_REACHED) {
                spamLimitReached = true;
                break;
            }
            require(status == ContentBayes.LearnStatus.ADDED,
                    "Capacity stress message was rejected before a model limit was reached.");
            learnedSpam++;
        }
        require(spamLimitReached && learnedSpam >= 25,
                "Spam class did not reach its isolated feature cap.");
        byte[] ham = message("capacity-ham", "Legitimate planning", "agenda meeting office project review calendar "
                + "contract invoice delivery report schedule team");
        require(ContentBayes.learn(ham, false) == ContentBayes.LearnStatus.ADDED,
                "Spam vocabulary must not consume the reserved HAM feature capacity.");
        require(ContentBayes.stats().contains("HAM_DOCUMENTS 1\n"),
                "HAM sample must be represented after the SPAM feature cap is reached.");
    }

    private static byte[] message(String id, String subject, String body) {
        String value = "From: " + id + "@example.invalid\r\n"
                + "To: recipient@example.invalid\r\n"
                + "Subject: " + subject + "\r\n"
                + "Message-ID: <" + id + "@example.invalid>\r\n"
                + "MIME-Version: 1.0\r\n"
                + "Content-Type: text/plain; charset=UTF-8\r\n"
                + "\r\n" + body + "\r\n";
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] message(boolean spam, int index) {
        String subject = spam ? "Urgent casino bonus investment" : "Project meeting schedule agenda";
        String body = spam
                ? "casino bonus cryptocurrency wallet claim reward payout offer investment bitcoin lottery"
                : "agenda planning team meeting project minutes schedule office review calendar";
        return message("sample-" + (spam ? "spam" : "ham") + "-" + index,
                subject, body + " referencecode" + index);
    }

    private static javax.mail.internet.MimeMessage parse(byte[] raw) throws Exception {
        return new javax.mail.internet.MimeMessage(
                javax.mail.Session.getInstance(new java.util.Properties()),
                new java.io.ByteArrayInputStream(raw)
        );
    }

    private static String adminCommand(InetAddress address, String command) throws Exception {
        Method method = AdministrationTCP.class.getDeclaredMethod(
                "processCommand", InetAddress.class, Client.class, String.class, OutputStream.class
        );
        method.setAccessible(true);
        return (String) method.invoke(null, address, null, command, null);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
