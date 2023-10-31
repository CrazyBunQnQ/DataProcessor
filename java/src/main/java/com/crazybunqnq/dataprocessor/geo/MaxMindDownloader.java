package com.crazybunqnq.dataprocessor.geo;

import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveInputStream;
import org.apache.commons.compress.archivers.ArchiveStreamFactory;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;

public class MaxMindDownloader {
    private static final String MAXMIND_URL = "https://download.maxmind.com/app/geoip_download?edition_id={EDITION_ID}&license_key={API_KEY}&suffix={SUFFIX}";
    private static final String DAY = new SimpleDateFormat("yyyyMMdd").format(new Date());

    public static void main(String[] args) {
    }

    public static void unzipFile(String source, String outputDirectory) throws Exception {
        try (ArchiveInputStream i = new ArchiveStreamFactory().createArchiveInputStream(ArchiveStreamFactory.ZIP, new BufferedInputStream(new FileInputStream(source)))) {
            ArchiveEntry entry;
            while ((entry = i.getNextEntry()) != null) {
                if (!i.canReadEntryData(entry)) {
                    throw new IOException("Error reading archive entry: " + entry.getName());
                }

                File f = new File(outputDirectory, entry.getName());
                if (entry.isDirectory()) {
                    if (!f.isDirectory() && !f.mkdirs()) {
                        throw new IOException("Failed to create directory: " + f);
                    }
                } else {
                    File parent = f.getParentFile();
                    if (!parent.isDirectory() && !parent.mkdirs()) {
                        throw new IOException("Failed to create directory: " + parent);
                    }

                    try (OutputStream o = new BufferedOutputStream(new FileOutputStream(f))) {
                        IOUtils.copy(i, o);
                    }
                }
            }
        }
    }

    public static void untarGzFile(String source, String outputDirectory) throws Exception {
        try (GzipCompressorInputStream gzipIn = new GzipCompressorInputStream(new BufferedInputStream(new FileInputStream(source)))) {
            try (ArchiveInputStream archiveIn = new ArchiveStreamFactory().createArchiveInputStream(new BufferedInputStream(gzipIn))) {
                ArchiveEntry entry;
                while ((entry = archiveIn.getNextEntry()) != null) {
                    if (!archiveIn.canReadEntryData(entry)) {
                        throw new IOException("Error reading archive entry: " + entry.getName());
                    }

                    File f = new File(outputDirectory, entry.getName());
                    if (entry.isDirectory()) {
                        if (!f.isDirectory() && !f.mkdirs()) {
                            throw new IOException("Failed to create directory: " + f);
                        }
                    } else {
                        File parent = f.getParentFile();
                        if (!parent.isDirectory() && !parent.mkdirs()) {
                            throw new IOException("Failed to create directory: " + parent);
                        }

                        try (OutputStream out = new BufferedOutputStream(new FileOutputStream(f))) {
                            IOUtils.copy(archiveIn, out);
                        }
                    }
                }
            }
        }
    }

    public static void downloadFileWithResume(String apiKey, String editionId, String suffix, File destination) throws IOException {
        String sourceUrl = MAXMIND_URL.replace("{API_KEY}", apiKey).replace("{EDITION_ID}", editionId).replace("{SUFFIX}", suffix);
        if (destination == null) {
            destination = new File(editionId + "_" + DAY + "." + suffix);
        }
        // 断点续传
        long existingFileSize = 0L;
        if (destination.exists() && destination.isFile()) {
            existingFileSize = destination.length();
        }

        HttpURLConnection httpConnection = (HttpURLConnection) new URL(sourceUrl).openConnection();

        // 断点续传
        if (existingFileSize > 0) {
            httpConnection.setRequestProperty("Range", "bytes=" + existingFileSize + "-");
        }
        httpConnection.connect();

        if (httpConnection.getResponseCode() != HttpURLConnection.HTTP_PARTIAL && httpConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Server responded with status: " + httpConnection.getResponseCode());
        }

        try (InputStream inputStream = httpConnection.getInputStream()) {
            try {
                FileUtils.copyInputStreamToFile(inputStream, destination);
            } catch (IOException e) {
                if (e.getMessage().contains("Premature end of Content-Length delimited message body")) {
                    // 如果网络中断，重试下载
                    downloadFileWithResume(sourceUrl, editionId, suffix, destination);
                } else {
                    throw e;
                }
            }
        }
    }
}
