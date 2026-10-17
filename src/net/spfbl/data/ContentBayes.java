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
 * along with SPFBL.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.spfbl.data;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.charset.Charset;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.mail.Multipart;
import javax.mail.Part;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.ContentType;
import net.spfbl.core.Server;
import net.spfbl.whois.Subnet;
import org.jsoup.Jsoup;
import static net.spfbl.core.Regex.isValidCIDR;

/**
 * Classificador Bayesiano local para o conteúdo de mensagens.
 * Os termos e as mensagens são persistidos somente como hashes.
 */
public final class ContentBayes {

    private static final String VERSION = "SFOX_CONTENT_BAYES\t3";
    private static final String LEGACY_VERSION_1 = "SFOX_CONTENT_BAYES\t1";
    private static final String LEGACY_VERSION_2 = "SFOX_CONTENT_BAYES\t2";
    private static final File STORE_FILE = new File("data/content-bayes.db");
    private static final long MAX_STORE_BYTES = 128L * 1024L * 1024L;
    private static final int MAX_MESSAGE_BYTES = 5 * 1024 * 1024;
    private static final int MAX_TEXT_CHARS = 500000;
    private static final int MAX_FEATURES = 1500;
    private static final int MIN_CLASS_DOCUMENTS = 25;
    private static final int MIN_KNOWN_FEATURES = 8;
    private static final int MAX_DOCUMENTS = 100000;
    private static final int MAX_VOCABULARY = 500000;
    private static final int MAX_CLASS_FEATURES = 300000;
    private static final int MAX_ALLOWED_CLIENTS = 10000;
    private static final double COMMON_IN_BOTH_CLASSES_FRACTION = 0.80d;
    private static final int MAX_TRAINING_FILES = 2000;
    private static final long MAX_TRAINING_BYTES = 128L * 1024L * 1024L;
    private static final double SPAM_THRESHOLD = 0.995d;
    private static final Pattern TOKEN_PATTERN = Pattern.compile("[\\p{L}\\p{N}]{3,40}");

    private static final Object LOCK = new Object();
    private static final Object STORE_LOCK = new Object();
    private static final TreeMap<String,Boolean> DOCUMENTS = new TreeMap<>();
    private static final TreeMap<String,Long> SPAM_TERMS = new TreeMap<>();
    private static final TreeMap<String,Long> HAM_TERMS = new TreeMap<>();
    private static final TreeSet<String> ALLOWED_CLIENTS = new TreeSet<>();
    private static final TreeSet<String> DECISION_CLIENTS = new TreeSet<>();
    private static long spamTokenTotal = 0;
    private static long hamTokenTotal = 0;
    private static long spamDocumentTotal = 0;
    private static int vocabularySize = 0;
    private static boolean loaded = false;
    private static boolean enabled = false;
    private static boolean persistenceWritable = true;
    private static boolean dirty = false;
    private static long generation = 0;

    private ContentBayes() {
    }

    public enum LearnStatus {
        ADDED, DUPLICATE, LABEL_CONFLICT, TOO_SMALL, LIMIT_REACHED
    }

    public static final class Prediction {
        private final double spamProbability;
        private final int knownFeatures;

        private Prediction(double spamProbability, int knownFeatures) {
            this.spamProbability = spamProbability;
            this.knownFeatures = knownFeatures;
        }

        public double getSpamProbability() {
            return spamProbability;
        }

        public int getKnownFeatures() {
            return knownFeatures;
        }

        public boolean isConfidentSpam() {
            return spamProbability >= SPAM_THRESHOLD;
        }

        public boolean isConfidentHam() {
            return spamProbability <= 1.0d - SPAM_THRESHOLD;
        }
    }

    public static final class LearnSummary {
        public int added;
        public int duplicate;
        public int conflict;
        public int invalid;
        public int tooSmall;
        public int skipped;
    }

    public static Prediction classify(MimeMessage message) {
        return classify(message, true, true, null);
    }

    /** Applies the model only to separately opted-in SPAMD decision CIDRs. */
    public static Prediction classifyForClient(MimeMessage message, String clientCIDR) {
        if (!isDecisionClientAllowed(clientCIDR)) {
            return null;
        }
        return classify(message, true, true, Subnet.normalizeCIDR(clientCIDR));
    }

    /** Returns a passive score for an enrolled client without changing mail decisions. */
    public static Prediction scoreForClient(MimeMessage message, String clientCIDR) {
        if (!isClientAllowed(clientCIDR)) {
            return null;
        }
        return classify(message, true, false, Subnet.normalizeCIDR(clientCIDR));
    }

    private static Prediction classify(MimeMessage message, boolean requireEnabled,
            boolean confidentOnly, String requiredClientCIDR) {
        if (message == null) {
            return null;
        }
        try {
            Set<String> features = extractFeatures(message);
            synchronized (LOCK) {
                if (!loaded || (requireEnabled && (!enabled
                        || (requiredClientCIDR != null && !ALLOWED_CLIENTS.contains(requiredClientCIDR))))
                        || DOCUMENTS.size() < MIN_CLASS_DOCUMENTS * 2) {
                    return null;
                }
                long spamDocuments = spamDocumentTotal;
                long hamDocuments = DOCUMENTS.size() - spamDocuments;
                if (spamDocuments < MIN_CLASS_DOCUMENTS || hamDocuments < MIN_CLASS_DOCUMENTS) {
                    return null;
                }
                double spamDenominator = spamDocuments + 2.0d;
                double hamDenominator = hamDocuments + 2.0d;
                double spamLog = Math.log((spamDocuments + 1.0d) / (DOCUMENTS.size() + 2.0d));
                double hamLog = Math.log((hamDocuments + 1.0d) / (DOCUMENTS.size() + 2.0d));
                int known = 0;
                for (String feature : features) {
                    Long spamCount = SPAM_TERMS.get(feature);
                    Long hamCount = HAM_TERMS.get(feature);
                    if (spamCount == null && hamCount == null) {
                        continue;
                    }
                    if (spamCount != null && hamCount != null
                            && spamCount > spamDocuments * COMMON_IN_BOTH_CLASSES_FRACTION
                            && hamCount > hamDocuments * COMMON_IN_BOTH_CLASSES_FRACTION) {
                        continue;
                    }
                    known++;
                    spamLog += Math.log((spamCount == null ? 0L : spamCount) + 1.0d) - Math.log(spamDenominator);
                    hamLog += Math.log((hamCount == null ? 0L : hamCount) + 1.0d) - Math.log(hamDenominator);
                }
                if (known < MIN_KNOWN_FEATURES) {
                    return null;
                }
                double difference = hamLog - spamLog;
                double probability;
                if (difference > 700) {
                    probability = 1.0d;
                } else if (difference < -700) {
                    probability = 0.0d;
                } else {
                    probability = 1.0d / (1.0d + Math.exp(difference));
                }
                if (!confidentOnly || probability >= SPAM_THRESHOLD || probability <= 1.0d - SPAM_THRESHOLD) {
                    return new Prediction(probability, known);
                }
                return null;
            }
        } catch (Exception ex) {
            Server.logError("Bayes classification failed: " + ex.getClass().getSimpleName());
            return null;
        }
    }

    public static LearnStatus learn(byte[] rawMessage, boolean spam) throws Exception {
        if (rawMessage == null || rawMessage.length == 0 || rawMessage.length > MAX_MESSAGE_BYTES) {
            return LearnStatus.LIMIT_REACHED;
        }
        String fingerprint = digest(rawMessage);
        MimeMessage message;
        try (InputStream inputStream = new ByteArrayInputStream(rawMessage)) {
            message = new MimeMessage(Session.getInstance(new Properties()), inputStream);
        }
        Set<String> features = extractFeatures(message);
        if (features.size() < MIN_KNOWN_FEATURES) {
            return LearnStatus.TOO_SMALL;
        }
        synchronized (LOCK) {
            Boolean previous = DOCUMENTS.get(fingerprint);
            if (previous != null) {
                return previous.booleanValue() == spam ? LearnStatus.DUPLICATE : LearnStatus.LABEL_CONFLICT;
            }
            if (DOCUMENTS.size() >= MAX_DOCUMENTS) {
                return LearnStatus.LIMIT_REACHED;
            }
            TreeMap<String,Long> target = spam ? SPAM_TERMS : HAM_TERMS;
            int newTerms = 0;
            int newClassTerms = 0;
            for (String feature : features) {
                if (!target.containsKey(feature)) {
                    newClassTerms++;
                }
                if (!SPAM_TERMS.containsKey(feature) && !HAM_TERMS.containsKey(feature)) {
                    newTerms++;
                }
            }
            if (target.size() + newClassTerms > MAX_CLASS_FEATURES
                    || vocabularySize + newTerms > MAX_VOCABULARY) {
                return LearnStatus.LIMIT_REACHED;
            }
            for (String feature : features) {
                Long count = target.get(feature);
                target.put(feature, count == null ? 1L : count + 1L);
            }
            vocabularySize += newTerms;
            if (spam) {
                spamTokenTotal += features.size();
                spamDocumentTotal++;
            } else {
                hamTokenTotal += features.size();
            }
            DOCUMENTS.put(fingerprint, Boolean.valueOf(spam));
            generation++;
            dirty = true;
            loaded = true;
            return LearnStatus.ADDED;
        }
    }

    public static LearnSummary learnDirectory(File directory, boolean spam) {
        LearnSummary summary = new LearnSummary();
        File learningRoot = new File("learn");
        if (Files.isSymbolicLink(learningRoot.toPath())) {
            summary.invalid++;
            return summary;
        }
        if (directory == null || (!directory.exists() && !directory.mkdirs()) || !directory.isDirectory()) {
            summary.invalid++;
            return summary;
        }
        try {
            File trainingRoot = new File("learn").getCanonicalFile();
            File canonicalDirectory = directory.getCanonicalFile();
            if (Files.isSymbolicLink(learningRoot.toPath())
                    || !canonicalDirectory.getPath().startsWith(trainingRoot.getPath() + File.separator)
                    || Files.isSymbolicLink(directory.toPath())) {
                summary.invalid++;
                return summary;
            }
        } catch (Exception ex) {
            summary.invalid++;
            return summary;
        }
        File[] files = directory.listFiles();
        if (files == null) {
            summary.invalid++;
            return summary;
        }
        List<File> candidates = new ArrayList<>();
        for (File file : files) {
            if (file.isFile() && !Files.isSymbolicLink(file.toPath())
                    && file.getName().toLowerCase(Locale.ROOT).endsWith(".eml")) {
                candidates.add(file);
            }
        }
        Collections.sort(candidates, (left, right) -> left.getName().compareToIgnoreCase(right.getName()));
        if (candidates.size() > MAX_TRAINING_FILES) {
            summary.skipped += candidates.size() - MAX_TRAINING_FILES;
            candidates = candidates.subList(0, MAX_TRAINING_FILES);
        }
        long batchBytes = 0;
        for (File file : candidates) {
            try {
                long length = file.length();
                if (length <= 0 || length > MAX_MESSAGE_BYTES
                        || batchBytes + length > MAX_TRAINING_BYTES) {
                    summary.invalid++;
                    continue;
                }
                batchBytes += length;
                byte[] rawMessage = Files.readAllBytes(file.toPath());
                LearnStatus status = learn(rawMessage, spam);
                switch (status) {
                    case ADDED:
                        summary.added++;
                        break;
                    case DUPLICATE:
                        summary.duplicate++;
                        break;
                    case LABEL_CONFLICT:
                        summary.conflict++;
                        break;
                    case TOO_SMALL:
                        summary.tooSmall++;
                        break;
                    default:
                        summary.invalid++;
                        break;
                }
            } catch (Exception ex) {
                summary.invalid++;
                Server.logError("Bayes training skipped: " + ex.getClass().getSimpleName());
            }
        }
        return summary;
    }

    public static String stats() {
        synchronized (LOCK) {
            long spamDocuments = spamDocumentTotal;
            long hamDocuments = DOCUMENTS.size() - spamDocuments;
            return "ENABLED " + enabled + "\n"
                    + "SPAM_DOCUMENTS " + spamDocuments + "\n"
                    + "HAM_DOCUMENTS " + hamDocuments + "\n"
                    + "VOCABULARY " + vocabularySize + "\n"
                    + "ALLOWED_CLIENTS " + ALLOWED_CLIENTS.size() + "\n"
                    + "DECISION_CLIENTS " + DECISION_CLIENTS.size() + "\n"
                    + "MIN_DOCUMENTS_PER_CLASS " + MIN_CLASS_DOCUMENTS + "\n"
                    + "SPAM_THRESHOLD " + SPAM_THRESHOLD + "\n";
        }
    }

    public static boolean isClientAllowed(String cidr) {
        if (cidr == null || !isValidCIDR(cidr)) {
            return false;
        }
        String normalized = Subnet.normalizeCIDR(cidr);
        if (normalized == null) {
            return false;
        }
        synchronized (LOCK) {
            return enabled && ALLOWED_CLIENTS.contains(normalized);
        }
    }

    public static boolean hasAllowedClient(String cidr) {
        if (cidr == null || !isValidCIDR(cidr)) {
            return false;
        }
        String normalized = Subnet.normalizeCIDR(cidr);
        synchronized (LOCK) {
            return normalized != null && ALLOWED_CLIENTS.contains(normalized);
        }
    }

    /** A separate, explicit opt-in is required before Bayes can affect SPAMD delivery decisions. */
    public static boolean isDecisionClientAllowed(String cidr) {
        if (cidr == null || !isValidCIDR(cidr)) {
            return false;
        }
        String normalized = Subnet.normalizeCIDR(cidr);
        if (normalized == null) {
            return false;
        }
        synchronized (LOCK) {
            return enabled && DECISION_CLIENTS.contains(normalized);
        }
    }

    public static boolean hasDecisionClient(String cidr) {
        if (cidr == null || !isValidCIDR(cidr)) {
            return false;
        }
        String normalized = Subnet.normalizeCIDR(cidr);
        synchronized (LOCK) {
            return normalized != null && DECISION_CLIENTS.contains(normalized);
        }
    }

    public static boolean addDecisionClient(String cidr) {
        if (cidr == null || !isValidCIDR(cidr)) {
            return false;
        }
        String normalized = Subnet.normalizeCIDR(cidr);
        if (normalized == null) {
            return false;
        }
        synchronized (LOCK) {
            if (!ALLOWED_CLIENTS.contains(normalized) || DECISION_CLIENTS.contains(normalized)
                    || DECISION_CLIENTS.size() >= MAX_ALLOWED_CLIENTS) {
                return false;
            }
            DECISION_CLIENTS.add(normalized);
            generation++;
            dirty = true;
            return true;
        }
    }

    public static boolean dropDecisionClient(String cidr) {
        if (cidr == null || !isValidCIDR(cidr)) {
            return false;
        }
        String normalized = Subnet.normalizeCIDR(cidr);
        synchronized (LOCK) {
            if (normalized == null || !DECISION_CLIENTS.remove(normalized)) {
                return false;
            }
            generation++;
            dirty = true;
            return true;
        }
    }

    public static String decisionClients() {
        synchronized (LOCK) {
            if (DECISION_CLIENTS.isEmpty()) {
                return "EMPTY\n";
            }
            StringBuilder result = new StringBuilder();
            for (String cidr : DECISION_CLIENTS) {
                result.append(cidr).append('\n');
            }
            return result.toString();
        }
    }

    public static boolean addAllowedClient(String cidr) {
        if (cidr == null || !isValidCIDR(cidr)) {
            return false;
        }
        String normalized = Subnet.normalizeCIDR(cidr);
        if (normalized == null) {
            return false;
        }
        synchronized (LOCK) {
            if (ALLOWED_CLIENTS.contains(normalized) || ALLOWED_CLIENTS.size() >= MAX_ALLOWED_CLIENTS) {
                return false;
            }
            ALLOWED_CLIENTS.add(normalized);
            generation++;
            dirty = true;
            return true;
        }
    }

    public static boolean dropAllowedClient(String cidr) {
        if (cidr == null || !isValidCIDR(cidr)) {
            return false;
        }
        String normalized = Subnet.normalizeCIDR(cidr);
        synchronized (LOCK) {
            if (normalized == null || !ALLOWED_CLIENTS.remove(normalized)) {
                return false;
            }
            DECISION_CLIENTS.remove(normalized);
            generation++;
            dirty = true;
            return true;
        }
    }

    public static String allowedClients() {
        synchronized (LOCK) {
            if (ALLOWED_CLIENTS.isEmpty()) {
                return "EMPTY\n";
            }
            StringBuilder result = new StringBuilder();
            for (String cidr : ALLOWED_CLIENTS) {
                result.append(cidr).append('\n');
            }
            return result.toString();
        }
    }

    public static Prediction classifyFile(File file) throws Exception {
        return readAndClassifyFile(file, true);
    }

    /** Returns a bounded feature score for offline evaluation; it has no effect on mail decisions. */
    public static Prediction scoreFile(File file) throws Exception {
        return readAndClassifyFile(file, false);
    }

    private static Prediction readAndClassifyFile(File file, boolean confidentOnly) throws Exception {
        if (file == null || !file.isFile() || file.length() <= 0 || file.length() > MAX_MESSAGE_BYTES) {
            throw new IllegalArgumentException("Arquivo inválido ou fora do limite de 5 MiB.");
        }
        try (InputStream inputStream = new FileInputStream(file)) {
            MimeMessage message = new MimeMessage(Session.getInstance(new Properties()), inputStream);
            return classify(message, false, confidentOnly, null);
        }
    }

    public static boolean enable() {
        synchronized (LOCK) {
            long spamDocuments = spamDocumentTotal;
            long hamDocuments = DOCUMENTS.size() - spamDocuments;
            if (!loaded || spamDocuments < MIN_CLASS_DOCUMENTS || hamDocuments < MIN_CLASS_DOCUMENTS) {
                return false;
            }
            if (!enabled) {
                enabled = true;
                generation++;
                dirty = true;
            }
            return true;
        }
    }

    public static void disable() {
        synchronized (LOCK) {
            if (enabled) {
                enabled = false;
                generation++;
                dirty = true;
            }
        }
    }

    public static boolean isEnabled() {
        synchronized (LOCK) {
            return enabled;
        }
    }

    public static boolean isPersistenceWritable() {
        synchronized (LOCK) {
            File parent = STORE_FILE.getParentFile();
            return persistenceWritable && parent != null && parent.isDirectory()
                    && parent.canWrite() && (!STORE_FILE.exists() || STORE_FILE.canWrite());
        }
    }

    public static void load() {
        synchronized (LOCK) {
            DOCUMENTS.clear();
            SPAM_TERMS.clear();
            HAM_TERMS.clear();
            ALLOWED_CLIENTS.clear();
            DECISION_CLIENTS.clear();
            spamTokenTotal = 0;
            hamTokenTotal = 0;
            spamDocumentTotal = 0;
            vocabularySize = 0;
            enabled = false;
            persistenceWritable = true;
            dirty = false;
            generation++;
            loaded = true;
        }
        if (!STORE_FILE.exists()) {
            return;
        }
        if (STORE_FILE.length() > MAX_STORE_BYTES) {
            Server.logError("Bayes model exceeds the 128 MiB load limit.");
            synchronized (LOCK) {
                persistenceWritable = false;
            }
            return;
        }
        TreeMap<String,Boolean> documents = new TreeMap<>();
        TreeMap<String,Long> spamTerms = new TreeMap<>();
        TreeMap<String,Long> hamTerms = new TreeMap<>();
        TreeSet<String> allowedClients = new TreeSet<>();
        TreeSet<String> decisionClients = new TreeSet<>();
        long[] totals = new long[2];
        boolean[] enabledState = new boolean[]{false};
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(STORE_FILE), StandardCharsets.UTF_8))) {
            String line = reader.readLine();
            boolean versionThree = VERSION.equals(line);
            boolean versionTwo = LEGACY_VERSION_2.equals(line);
            boolean versionOne = LEGACY_VERSION_1.equals(line);
            if (!versionThree && !versionTwo && !versionOne) {
                throw new IllegalStateException("Unsupported Bayes model version.");
            }
            int rows = 0;
            while ((line = reader.readLine()) != null) {
            if (++rows > MAX_DOCUMENTS + MAX_VOCABULARY * 2 + MAX_ALLOWED_CLIENTS * 2 + 10) {
                    throw new IllegalStateException("Bayes model row limit exceeded.");
                }
                String[] fields = line.split("\\t", -1);
                if (fields.length == 2 && "ENABLED".equals(fields[0])
                        && ("true".equals(fields[1]) || "false".equals(fields[1]))) {
                    enabledState[0] = Boolean.parseBoolean(fields[1]);
                } else if ((versionThree || versionTwo) && fields.length == 2 && "CLIENT".equals(fields[0])
                        && isValidCIDR(fields[1])) {
                    String cidr = Subnet.normalizeCIDR(fields[1]);
                    if (cidr == null || !fields[1].equals(cidr) || !allowedClients.add(cidr)
                            || allowedClients.size() > MAX_ALLOWED_CLIENTS) {
                        throw new IllegalStateException("Invalid Bayes client allowlist row.");
                    }
                    if (versionTwo) {
                        // Preserve any pre-existing explicit SPAMD scope when upgrading v2.
                        if (decisionClients.size() >= MAX_ALLOWED_CLIENTS) {
                            throw new IllegalStateException("Bayes decision client limit exceeded.");
                        }
                        decisionClients.add(cidr);
                    }
                } else if (versionThree && fields.length == 2 && "DECISION_CLIENT".equals(fields[0])
                        && isValidCIDR(fields[1])) {
                    String cidr = Subnet.normalizeCIDR(fields[1]);
                    if (cidr == null || !fields[1].equals(cidr) || !decisionClients.add(cidr)
                            || decisionClients.size() > MAX_ALLOWED_CLIENTS) {
                        throw new IllegalStateException("Invalid Bayes decision client row.");
                    }
                } else if (fields.length == 3 && "DOC".equals(fields[0])
                        && ("S".equals(fields[1]) || "H".equals(fields[1]))
                        && fields[2].matches("[0-9a-f]{64}")) {
                    if (documents.put(fields[2], Boolean.valueOf("S".equals(fields[1]))) != null) {
                        throw new IllegalStateException("Duplicate Bayes document fingerprint.");
                    }
                } else if (fields.length == 4 && "TERM".equals(fields[0])
                        && ("S".equals(fields[1]) || "H".equals(fields[1]))
                        && fields[2].matches("[0-9a-f]{64}")) {
                    long count = Long.parseLong(fields[3]);
                    if (count < 1 || count > MAX_DOCUMENTS) {
                        throw new IllegalStateException("Invalid Bayes token count.");
                    }
                    if (("S".equals(fields[1]) ? spamTerms : hamTerms).put(fields[2], count) != null) {
                        throw new IllegalStateException("Duplicate Bayes token fingerprint.");
                    }
                    totals["S".equals(fields[1]) ? 0 : 1] += count;
                } else {
                    throw new IllegalStateException("Invalid Bayes model row.");
                }
            }
            if (documents.size() > MAX_DOCUMENTS
                    || spamTerms.size() > MAX_CLASS_FEATURES
                    || hamTerms.size() > MAX_CLASS_FEATURES
                    || unionSize(spamTerms, hamTerms) > MAX_VOCABULARY
                    || decisionClients.size() > MAX_ALLOWED_CLIENTS
                    || !allowedClients.containsAll(decisionClients)) {
                throw new IllegalStateException("Bayes model limit exceeded.");
            }
            synchronized (LOCK) {
                DOCUMENTS.putAll(documents);
                SPAM_TERMS.putAll(spamTerms);
                HAM_TERMS.putAll(hamTerms);
                ALLOWED_CLIENTS.addAll(allowedClients);
                DECISION_CLIENTS.addAll(decisionClients);
                spamTokenTotal = totals[0];
                hamTokenTotal = totals[1];
                vocabularySize = unionSize(SPAM_TERMS, HAM_TERMS);
                for (Boolean spam : DOCUMENTS.values()) {
                    if (spam.booleanValue()) {
                        spamDocumentTotal++;
                    }
                }
                enabled = enabledState[0]
                        && spamDocumentTotal >= MIN_CLASS_DOCUMENTS
                        && DOCUMENTS.size() - spamDocumentTotal >= MIN_CLASS_DOCUMENTS;
                dirty = false;
            }
        } catch (Exception ex) {
            synchronized (LOCK) {
                DOCUMENTS.clear();
                SPAM_TERMS.clear();
                HAM_TERMS.clear();
                ALLOWED_CLIENTS.clear();
            DECISION_CLIENTS.clear();
                spamTokenTotal = 0;
                hamTokenTotal = 0;
                spamDocumentTotal = 0;
                vocabularySize = 0;
                enabled = false;
                persistenceWritable = false;
                dirty = false;
            }
            Server.logError(ex);
        }
    }

    public static boolean store() {
        synchronized (STORE_LOCK) {
            return storeLocked();
        }
    }

    private static boolean storeLocked() {
        final TreeMap<String,Boolean> documents;
        final TreeMap<String,Long> spamTerms;
        final TreeMap<String,Long> hamTerms;
        final TreeSet<String> allowedClientsSnapshot;
        final TreeSet<String> decisionClientsSnapshot;
        final boolean enabledSnapshot;
        final long generationSnapshot;
        synchronized (LOCK) {
            if (!persistenceWritable) {
                return false;
            }
            if (!dirty) {
                return true;
            }
            documents = new TreeMap<>(DOCUMENTS);
            spamTerms = new TreeMap<>(SPAM_TERMS);
            hamTerms = new TreeMap<>(HAM_TERMS);
            allowedClientsSnapshot = new TreeSet<>(ALLOWED_CLIENTS);
            decisionClientsSnapshot = new TreeSet<>(DECISION_CLIENTS);
            enabledSnapshot = enabled;
            generationSnapshot = generation;
        }
        File parent = STORE_FILE.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            Server.logError("Could not create Bayes model directory.");
            return false;
        }
        Path temporaryPath = null;
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream((temporaryPath = Files.createTempFile(
                        parent.toPath(), ".content-bayes-", ".tmp",
                        PosixFilePermissions.asFileAttribute(EnumSet.of(
                                PosixFilePermission.OWNER_READ,
                                PosixFilePermission.OWNER_WRITE
                        )))).toFile()), StandardCharsets.UTF_8))) {
            writer.write(VERSION);
            writer.newLine();
            writer.write("ENABLED\t");
            writer.write(Boolean.toString(enabledSnapshot));
            writer.newLine();
            for (String cidr : allowedClientsSnapshot) {
                writer.write("CLIENT\t");
                writer.write(cidr);
                writer.newLine();
            }
            for (String cidr : decisionClientsSnapshot) {
                writer.write("DECISION_CLIENT\t");
                writer.write(cidr);
                writer.newLine();
            }
            for (Map.Entry<String,Boolean> entry : documents.entrySet()) {
                writer.write("DOC\t");
                writer.write(entry.getValue().booleanValue() ? "S\t" : "H\t");
                writer.write(entry.getKey());
                writer.newLine();
            }
            writeTerms(writer, "S", spamTerms);
            writeTerms(writer, "H", hamTerms);
        } catch (Exception ex) {
            if (temporaryPath != null) {
                try {
                    Files.deleteIfExists(temporaryPath);
                } catch (Exception ignored) {
                    // Preserve the original persistence error in the log.
                }
            }
            Server.logError(ex);
            return false;
        }
        try {
            try {
                Files.move(temporaryPath, STORE_FILE.toPath(),
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temporaryPath, STORE_FILE.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
            synchronized (LOCK) {
                if (generation == generationSnapshot) {
                    dirty = false;
                }
            }
            return true;
        } catch (Exception ex) {
            try {
                Files.deleteIfExists(temporaryPath);
            } catch (Exception ignored) {
                // Preserve the original persistence error in the log.
            }
            Server.logError(ex);
            return false;
        }
    }

    private static void writeTerms(BufferedWriter writer, String label, TreeMap<String,Long> terms) throws Exception {
        for (Map.Entry<String,Long> entry : terms.entrySet()) {
            writer.write("TERM\t");
            writer.write(label);
            writer.write('\t');
            writer.write(entry.getKey());
            writer.write('\t');
            writer.write(Long.toString(entry.getValue()));
            writer.newLine();
        }
    }

    private static Set<String> extractFeatures(MimeMessage message) throws Exception {
        Set<String> tokens = new LinkedHashSet<>();
        String subject = message.getSubject();
        if (subject != null) {
            addTokens(tokens, subject);
        }
        StringBuilder plain = new StringBuilder();
        StringBuilder html = new StringBuilder();
        appendBody(message, plain, html);
        addTokens(tokens, plain.length() > 0 ? plain.toString() : html.toString());
        TreeSet<String> hashed = new TreeSet<>();
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        int count = 0;
        for (String token : tokens) {
            if (count++ >= MAX_FEATURES) {
                break;
            }
            messageDigest.reset();
            hashed.add(digest(messageDigest, token.getBytes(StandardCharsets.UTF_8)));
        }
        return hashed;
    }

    private static void appendBody(Part part, StringBuilder plain, StringBuilder html) throws Exception {
        if (plain.length() + html.length() >= MAX_TEXT_CHARS) {
            return;
        }
        String disposition = part.getDisposition();
        if (Part.ATTACHMENT.equalsIgnoreCase(disposition) || part.getFileName() != null) {
            return;
        }
        Object content;
        try {
            content = part.getContent();
        } catch (Exception ex) {
            String type = part.getContentType().toLowerCase(Locale.ROOT);
            if (type.startsWith("text/plain") || type.startsWith("text/html")) {
                try {
                    String text = decodeText(part, part.getInputStream());
                    if (type.startsWith("text/plain")) {
                        appendBounded(plain, html, text);
                    } else {
                        appendBounded(html, plain, Jsoup.parse(text).text());
                    }
                } catch (Exception fallbackException) {
                    // Skip only this undecodable text part; never fail the whole message.
                }
            }
            return;
        }
        if (content instanceof Multipart) {
            Multipart multipart = (Multipart) content;
            for (int index = 0; index < multipart.getCount(); index++) {
                appendBody(multipart.getBodyPart(index), plain, html);
            }
        } else if (content instanceof Part) {
            appendBody((Part) content, plain, html);
        } else if (content instanceof String || content instanceof InputStream || content instanceof byte[]) {
            String type = part.getContentType().toLowerCase(Locale.ROOT);
            String text = content instanceof String
                    ? (String) content : decodeText(part, content);
            if (type.startsWith("text/plain")) {
                appendBounded(plain, html, text);
            } else if (type.startsWith("text/html")) {
                appendBounded(html, plain, Jsoup.parse(text).text());
            }
        }
    }

    private static String decodeText(Part part, Object content) throws Exception {
        byte[] bytes;
        if (content instanceof byte[]) {
            bytes = (byte[]) content;
        } else if (content instanceof InputStream) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            InputStream input = (InputStream) content;
            byte[] buffer = new byte[8192];
            int remaining = MAX_TEXT_CHARS * 4;
            int read;
            while (remaining > 0 && (read = input.read(buffer, 0, Math.min(buffer.length, remaining))) >= 0) {
                output.write(buffer, 0, read);
                remaining -= read;
            }
            bytes = output.toByteArray();
        } else {
            return "";
        }
        Charset charset = StandardCharsets.UTF_8;
        try {
            String name = new ContentType(part.getContentType()).getParameter("charset");
            if (name != null && !name.isEmpty()) {
                charset = Charset.forName(name);
            }
        } catch (Exception ex) {
            // Invalid or unknown charset: keep the safe UTF-8 fallback.
        }
        return new String(bytes, charset);
    }

    private static void appendBounded(StringBuilder target, StringBuilder other, String text) {
        int available = MAX_TEXT_CHARS - target.length() - other.length();
        if (available > 0 && text != null) {
            target.append(text, 0, Math.min(available, text.length())).append(' ');
        }
    }

    private static void addTokens(Set<String> target, String text) {
        String normalized = Normalizer.normalize(text, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
        Matcher matcher = TOKEN_PATTERN.matcher(normalized);
        while (matcher.find() && target.size() < MAX_FEATURES) {
            target.add(matcher.group());
        }
    }

    private static int unionSize(Map<String,Long> first, Map<String,Long> second) {
        int size = first.size();
        for (String key : second.keySet()) {
            if (!first.containsKey(key)) {
                size++;
            }
        }
        return size;
    }

    private static String digest(byte[] value) throws Exception {
        return digest(MessageDigest.getInstance("SHA-256"), value);
    }

    private static String digest(MessageDigest messageDigest, byte[] value) {
        byte[] hash = messageDigest.digest(value);
        char[] alphabet = "0123456789abcdef".toCharArray();
        char[] output = new char[hash.length * 2];
        for (int index = 0; index < hash.length; index++) {
            int item = hash[index] & 0xff;
            output[index * 2] = alphabet[item >>> 4];
            output[index * 2 + 1] = alphabet[item & 0x0f];
        }
        return new String(output);
    }
}
