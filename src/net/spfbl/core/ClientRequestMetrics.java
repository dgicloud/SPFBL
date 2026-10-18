/* SpamFox extension to SPFBL; GPL-3.0-or-later. See licence.txt. */
package net.spfbl.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;

/** Cumulative TCP request metrics, independent of reputation and client lookup caches. */
public final class ClientRequestMetrics {
    private static final Path FILE = Paths.get("./data/client-request-metrics.json");
    private static final int MAX_CLIENTS = 10000;
    private static final int MAX_BYTES = 2 * 1024 * 1024;
    private static final Object STORE_LOCK = new Object();
    private static final Map<String,Counts> COUNTS = new HashMap<>();
    private static long since = System.currentTimeMillis();
    private static long revision;
    private static long storedRevision = -1;
    private static boolean loadFailed;
    private static boolean capacityLimited;
    private static volatile boolean persistenceHealthy = true;
    private static ScheduledExecutorService saver;

    private ClientRequestMetrics() { }

    private static synchronized void startSaver() {
        if (saver != null) return;
        saver = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "spamfox-request-metrics");
            thread.setDaemon(true);
            return thread;
        });
        saver.scheduleWithFixedDelay(() -> store(), 60, 60, TimeUnit.SECONDS);
    }

    /** Called once per nonempty request from a registered client on the SPFBL TCP listener. */
    public static synchronized void record(Client client, boolean reputationQuery) {
        if (client == null) return;
        startSaver();
        String cidr = client.getCIDR();
        Counts old = COUNTS.get(cidr);
        if (old == null && COUNTS.size() >= MAX_CLIENTS) {
            if (!capacityLimited) Server.logError("Client request metrics reached the tracked network limit");
            capacityLimited = true;
            return;
        }
        long requests = old == null ? 0 : old.requests;
        long queries = old == null ? 0 : old.queries;
        if (requests == Long.MAX_VALUE) return;
        COUNTS.put(cidr, new Counts(requests + 1,
                reputationQuery ? queries + 1 : queries, System.currentTimeMillis()));
        revision++;
    }

    /** One consistent view; totals equal the rows for currently registered servers. */
    public static synchronized Snapshot snapshot(Iterable<Client> clients) {
        Map<String,Counts> rows = new TreeMap<>();
        long requests = 0, queries = 0;
        for (Client client : clients) {
            String cidr = client.getCIDR();
            Counts counts = COUNTS.get(cidr);
            if (counts == null) counts = new Counts(0, 0, 0);
            if (rows.put(cidr, counts) == null) {
                requests += counts.requests;
                queries += counts.queries;
            }
        }
        return new Snapshot(rows, requests, queries, since, persistenceHealthy && !loadFailed && !capacityLimited);
    }

    public static boolean store() {
        synchronized (STORE_LOCK) {
            final long version;
            final long started;
            final Map<String,Counts> copy;
            synchronized (ClientRequestMetrics.class) {
                if (loadFailed) return false;
                if (revision == storedRevision) return true;
                version = revision;
                started = since;
                copy = new TreeMap<>(COUNTS);
            }
            Path temporary = null;
            try {
                JsonObjectBuilder entries = Json.createObjectBuilder();
                for (Map.Entry<String,Counts> entry : copy.entrySet()) {
                    Counts counts = entry.getValue();
                    entries.add(entry.getKey(), Json.createObjectBuilder().add("requests", counts.requests)
                            .add("queries", counts.queries).add("last", counts.last));
                }
                JsonObject payload = Json.createObjectBuilder().add("format", 1).add("since", started).add("clients", entries).build();
                byte[] bytes = payload.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
                if (bytes.length > MAX_BYTES) throw new IOException("Metrics file size limit exceeded");
                temporary = Files.createTempFile(FILE.toAbsolutePath().getParent(), ".request-metrics-", ".tmp");
                try { Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rw-------")); }
                catch (UnsupportedOperationException ignored) { }
                try (FileChannel output = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                    ByteBuffer buffer = ByteBuffer.wrap(bytes);
                    while (buffer.hasRemaining()) output.write(buffer);
                    output.force(true);
                }
                try { Files.move(temporary, FILE, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
                catch (AtomicMoveNotSupportedException ignored) {
                    Files.move(temporary, FILE, StandardCopyOption.REPLACE_EXISTING);
                }
                synchronized (ClientRequestMetrics.class) { storedRevision = version; }
                persistenceHealthy = true;
                return true;
            } catch (Exception ex) {
                persistenceHealthy = false;
                Server.logError("Client request metrics could not be persisted: " + ex.getClass().getSimpleName());
                return false;
            } finally {
                if (temporary != null) {
                    try { Files.deleteIfExists(temporary); } catch (IOException ignored) { }
                }
            }
        }
    }

    public static void load() {
        synchronized (STORE_LOCK) {
            try {
                Map<String,Counts> loaded = new HashMap<>();
                long started = System.currentTimeMillis();
                boolean exists = Files.exists(FILE);
                if (exists) {
                    if (Files.size(FILE) > MAX_BYTES) throw new IOException("Metrics file too large");
                    JsonObject object;
                    try (JsonReader reader = Json.createReader(new ByteArrayInputStream(Files.readAllBytes(FILE)))) {
                        object = reader.readObject();
                    }
                    if (object.getInt("format") != 1) throw new IOException("Unsupported metrics format");
                    started = object.getJsonNumber("since").longValueExact();
                    if (started <= 0 || started > System.currentTimeMillis()) throw new IOException("Invalid tracking start");
                    JsonObject entries = object.getJsonObject("clients");
                    if (entries.size() > MAX_CLIENTS) throw new IOException("Too many metric records");
                    for (String cidr : entries.keySet()) {
                        if (!Regex.isValidCIDR(cidr)) throw new IOException("Invalid client network");
                        JsonObject entry = entries.getJsonObject(cidr);
                        long requests = entry.getJsonNumber("requests").longValueExact();
                        long queries = entry.getJsonNumber("queries").longValueExact();
                        long last = entry.getJsonNumber("last").longValueExact();
                        if (requests < 0 || queries < 0 || queries > requests || last < 0) throw new IOException("Invalid metrics");
                        loaded.put(cidr, new Counts(requests, queries, last));
                    }
                }
                synchronized (ClientRequestMetrics.class) {
                    COUNTS.clear(); COUNTS.putAll(loaded); since = started;
                    revision = 0; storedRevision = exists ? 0 : -1;
                    loadFailed = false; capacityLimited = false; persistenceHealthy = true;
                }
            } catch (Exception ex) {
                synchronized (ClientRequestMetrics.class) { loadFailed = true; persistenceHealthy = false; }
                Server.logError("Client request metrics were not loaded; existing file preserved: " + ex.getClass().getSimpleName());
            }
        }
        startSaver();
    }

    public static final class Counts {
        public final long requests, queries, last;
        Counts(long requests, long queries, long last) { this.requests = requests; this.queries = queries; this.last = last; }
    }

    public static final class Snapshot {
        public final Map<String,Counts> rows;
        public final long requests, queries, since;
        public final boolean persistenceHealthy;
        Snapshot(Map<String,Counts> rows, long requests, long queries, long since, boolean healthy) {
            this.rows = Collections.unmodifiableMap(rows); this.requests = requests; this.queries = queries;
            this.since = since; this.persistenceHealthy = healthy;
        }
    }
}
