package geo;

import org.junit.Test;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.Date;

import static com.crazybunqnq.dataprocessor.geo.GeoLite2Convert.*;
import static com.crazybunqnq.dataprocessor.geo.MaxMindDownloader.*;

public class GeoLiteTest {
    private static final String API_KEY = "YOUR_MAXMIND_API_KEY";
    /**
     * GeoLite2-ASN tar.gz
     * GeoLite2-ASN-CSV zip
     * GeoLite2-City tar.gz
     * GeoLite2-City-CSV zip
     * GeoLite2-Country tar.gz
     * GeoLite2-Country-CSV zip
     */
    private static final String[] EDITION_ID = new String[]{"GeoLite2-City-CSV", "zip"};
    private static final String DAY = new SimpleDateFormat("yyyyMMdd").format(new Date());
    private static final String UNZIP_DIRECTORY = EDITION_ID[0] + "_" + DAY;
    private static final String DESTINATION_PATH = EDITION_ID[0] + "_" + DAY + "." + EDITION_ID[1];
    private static final String DOWNLOAD_PATH = "F:\\下载\\";

    @Test
    public void downloadAndConvertTest() {
        try {
            downloadFileWithResume(API_KEY, EDITION_ID[0], EDITION_ID[1], new File(DESTINATION_PATH));
            System.out.println("Download completed.");

            // 解压文件
            if (DESTINATION_PATH.endsWith(".zip")) {
                unzipFile(DESTINATION_PATH, DOWNLOAD_PATH + UNZIP_DIRECTORY);
            } else if (DESTINATION_PATH.endsWith(".tar.gz")) {
                untarGzFile(DESTINATION_PATH, DOWNLOAD_PATH + UNZIP_DIRECTORY);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            return;
        }

        String dirPath = DOWNLOAD_PATH + UNZIP_DIRECTORY + File.separator;
        File file = new File (dirPath + "GeoLite2-City-Locations-zh-CN.csv");
        if (!file.exists()) {
            File[] files = new File(DOWNLOAD_PATH + UNZIP_DIRECTORY).listFiles();
            if (files != null && files.length == 1 && files[0].isDirectory()) {String dirName = files[0].getName(); String version = dirName.substring(dirName.lastIndexOf("_") + 1); System.out.println("GeoLite2 Data Version: " + version);
                dirPath = dirPath + files[0].getName() + File.separator;
            }
        }
        readLocations(dirPath + "GeoLite2-City-Locations-zh-CN.csv");
        removeDuplicates(dirPath + "GeoLite2-City-Blocks-IPv4.csv");
        convertToCityInfo(dirPath + "GeoLite2-City-Blocks-IPv4.csv", dirPath + "Geography.json");
        convertToIpInfo(dirPath + "GeoLite2-City-Blocks-IPv4.csv", dirPath + "Geography_Ip.json");
    }
}
