/* SpamFox extension to SPFBL; GPL-3.0-or-later. See licence.txt. */
package net.spfbl.service;

import java.io.ByteArrayOutputStream;
import java.util.Properties;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import javax.activation.DataHandler;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;

/** Verifies that archive inspection refuses an excessive number of ZIP entries. */
public final class ServerSMTPArchiveSmoke {

    private ServerSMTPArchiveSmoke() {
    }

    public static void main(String[] args) throws Exception {
        MimeMessage message = new MimeMessage(Session.getInstance(new Properties()));
        MimeMultipart multipart = new MimeMultipart();
        MimeBodyPart attachment = new MimeBodyPart();
        attachment.setFileName("campaign.zip");
        attachment.setDataHandler(new DataHandler(new ByteArrayDataSource(
                zipWithEntries(129), "application/zip")));
        multipart.addBodyPart(attachment);
        message.setContent(multipart);
        message.saveChanges();

        TreeSet<String> content = ServerSMTP.extractContent(message, false);
        require(content != null && content.contains("MALWARE=SPFBL.Archive.Limit"),
                "ZIP entry limit was not marked during content inspection");
        System.out.println("PASS: ZIP archive entry limit is enforced during content inspection.");
    }

    private static byte[] zipWithEntries(int entries) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(output)) {
            for (int index = 0; index < entries; index++) {
                zip.putNextEntry(new ZipEntry("entry-" + index + ".txt"));
                zip.write('x');
                zip.closeEntry();
            }
        }
        return output.toByteArray();
    }

    private static void require(boolean value, String message) {
        if (!value) {
            throw new IllegalStateException(message);
        }
    }
}
