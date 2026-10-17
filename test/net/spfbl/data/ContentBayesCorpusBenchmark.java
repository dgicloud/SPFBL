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
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Offline benchmark against externally labelled EML corpora. */
public final class ContentBayesCorpusBenchmark {

    private ContentBayesCorpusBenchmark() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            throw new IllegalArgumentException(
                    "Usage: ContentBayesCorpusBenchmark <train-spam-dir> <train-ham-dir> <test-spam-dir> <test-ham-dir>");
        }
        ContentBayes.load();
        TrainingResult spam = train(new File(args[0]), true);
        TrainingResult ham = train(new File(args[1]), false);
        System.out.println("TRAIN_SPAM added=" + spam.added + " duplicate=" + spam.duplicate
                + " conflict=" + spam.conflict + " limit=" + spam.limit
                + " invalid=" + spam.invalid + " too_small=" + spam.tooSmall);
        System.out.println("TRAIN_HAM added=" + ham.added + " duplicate=" + ham.duplicate
                + " conflict=" + ham.conflict + " limit=" + ham.limit
                + " invalid=" + ham.invalid + " too_small=" + ham.tooSmall);
        if (!ContentBayes.enable()) {
            throw new IllegalStateException("Training corpus did not meet the minimum for both classes.");
        }
        if (!ContentBayes.store()) {
            throw new IllegalStateException("Could not persist the offline Bayes candidate model.");
        }
        System.out.println("CANDIDATE_MODEL=data/content-bayes.db");
        System.out.print(ContentBayes.stats());
        report("TRAIN_SPAM", asList(emlFiles(new File(args[0]))), true);
        report("TRAIN_HAM", asList(emlFiles(new File(args[1]))), false);

        File spamDirectory = new File(args[2]);
        File[] spamFiles = emlFiles(spamDirectory);
        List<File> cwl = new ArrayList<>();
        List<File> rspamd = new ArrayList<>();
        for (File file : spamFiles) {
            if (file.getName().startsWith("cwl-")) {
                cwl.add(file);
            } else {
                rspamd.add(file);
            }
        }
        report("TEST_CWL_SPAM", cwl, true);
        report("TEST_RSPAMD_SPAM", rspamd, true);
        report("TEST_RSPAMD_HAM", asList(emlFiles(new File(args[3]))), false);
    }

    private static TrainingResult train(File directory, boolean spam) throws Exception {
        TrainingResult result = new TrainingResult();
        for (File file : emlFiles(directory)) {
            if (file.length() <= 0 || file.length() > 5L * 1024L * 1024L) {
                result.invalid++;
                continue;
            }
            ContentBayes.LearnStatus status;
            try {
                status = ContentBayes.learn(Files.readAllBytes(file.toPath()), spam);
            } catch (Exception ex) {
                result.invalid++;
                continue;
            }
            switch (status) {
                case ADDED:
                    result.added++;
                    break;
                case DUPLICATE:
                    result.duplicate++;
                    break;
                case TOO_SMALL:
                    result.tooSmall++;
                    break;
                case LABEL_CONFLICT:
                    result.conflict++;
                    break;
                case LIMIT_REACHED:
                    result.limit++;
                    break;
                default:
                    result.invalid++;
                    break;
            }
        }
        return result;
    }

    private static void report(String name, List<File> files, boolean expectedSpam) throws Exception {
        List<ScoredMessage> scoredMessages = new ArrayList<>();
        int unscorable = 0;
        int invalid = 0;
        for (File file : files) {
            ContentBayes.Prediction prediction;
            try {
                prediction = ContentBayes.scoreFile(file);
            } catch (Exception ex) {
                invalid++;
                continue;
            }
            if (prediction == null) {
                unscorable++;
            } else {
                scoredMessages.add(new ScoredMessage(file.getName(), prediction.getSpamProbability()));
            }
        }
        System.out.println(name + " total=" + files.size() + " scoreable=" + scoredMessages.size()
                + " unscorable=" + unscorable + " invalid=" + invalid);
        double[] thresholds = new double[]{0.999999d, 0.99999d, 0.9999d, 0.999d,
            0.995d, 0.99d, 0.95d, 0.90d, 0.80d, 0.50d};
        for (double threshold : thresholds) {
            int triggered = 0;
            StringBuilder examples = new StringBuilder();
            for (ScoredMessage message : scoredMessages) {
                if (message.spamProbability >= threshold) {
                    triggered++;
                    if (!expectedSpam && examples.length() < 300) {
                        if (examples.length() > 0) {
                            examples.append(",");
                        }
                        examples.append(message.name).append("=")
                                .append(String.format(java.util.Locale.ROOT, "%.8f", message.spamProbability));
                    }
                }
            }
            if (expectedSpam) {
                System.out.println("  threshold=" + threshold + " spam_detected=" + triggered
                        + " spam_missed=" + (files.size() - triggered));
            } else {
                System.out.println("  threshold=" + threshold + " ham_false_positive=" + triggered
                        + " ham_not_flagged=" + (files.size() - triggered)
                        + (examples.length() == 0 ? "" : " false_positive_examples=" + examples));
            }
        }
    }

    private static final class ScoredMessage {
        private final String name;
        private final double spamProbability;

        private ScoredMessage(String name, double spamProbability) {
            this.name = name;
            this.spamProbability = spamProbability;
        }
    }

    private static File[] emlFiles(File directory) {
        File[] files = directory.listFiles((dir, name) -> name.toLowerCase(java.util.Locale.ROOT).endsWith(".eml"));
        if (files == null) {
            throw new IllegalArgumentException("Cannot read EML directory: " + directory);
        }
        java.util.Arrays.sort(files, (left, right) -> left.getName().compareToIgnoreCase(right.getName()));
        return files;
    }

    private static List<File> asList(File[] files) {
        List<File> result = new ArrayList<>();
        Collections.addAll(result, files);
        return result;
    }

    private static final class TrainingResult {
        int added;
        int duplicate;
        int conflict;
        int limit;
        int invalid;
        int tooSmall;
    }
}
