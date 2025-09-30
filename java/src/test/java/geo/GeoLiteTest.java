package geo;

import org.junit.Test;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.crazybunqnq.dataprocessor.geo.GeoLite2Convert.*;
import static com.crazybunqnq.dataprocessor.geo.MaxMindDownloader.*;
import static com.crazybunqnq.dataprocessor.geo.PinyinUtils.*;

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
        readCnData("geo_cn/cn_region.csv");
        readLocations(dirPath + "GeoLite2-City-Locations-zh-CN.csv");
        readEnLocations(dirPath + "GeoLite2-City-Locations-en.csv");
        removeDuplicates(dirPath + "GeoLite2-City-Blocks-IPv4.csv");
        convertToCityInfo(dirPath + "GeoLite2-City-Blocks-IPv4.csv", dirPath + "Geography.json");
        
        // 处理Geography.json文件，为没有enName的条目添加拼音
        processJsonFileForPinyin(dirPath + "Geography.json");
        
        convertToIpInfo(dirPath + "GeoLite2-City-Blocks-IPv4.csv", dirPath + "Geography_Ip.json");
        
        // 等待文件完全生成并验证文件存在性
        String ipJsonPath = dirPath + "Geography_Ip.json";
        if (waitForFileGeneration(ipJsonPath)) {
            // 处理Geography_Ip.json文件，为没有enName的条目添加拼音（带重试机制）
            processJsonFileWithRetry(ipJsonPath);
        } else {
            System.err.println("警告: Geography_Ip.json 文件生成失败或不完整，跳过拼音处理");
        }
    }
    
    /**
     * 等待文件完全生成，包括文件存在性检查和大小稳定性验证
     * 
     * @param filePath 文件路径
     * @return 如果文件成功生成并稳定则返回true，否则返回false
     */
    private static boolean waitForFileGeneration(String filePath) {
        File file = new File(filePath);
        int maxAttempts = 30; // 最多等待30秒
        int attemptInterval = 1000; // 每次检查间隔1秒
        
        for (int i = 0; i < maxAttempts; i++) {
            if (file.exists() && file.length() > 0) {
                // 文件存在且不为空，再等待一秒确保写入完成
                try {
                    Thread.sleep(attemptInterval);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
                
                // 再次检查文件是否仍然存在且大小稳定
                long firstSize = file.length();
                try {
                    Thread.sleep(500); // 等待0.5秒
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return false;
                }
                long secondSize = file.length();
                
                if (firstSize == secondSize && secondSize > 0) {
                    System.out.println("文件生成完成: " + filePath + " (大小: " + secondSize + " 字节)");
                    return true;
                }
            }
            
            try {
                Thread.sleep(attemptInterval);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        
        System.err.println("文件生成超时: " + filePath);
        return false;
    }
    
    /**
     * 带重试机制的JSON文件处理方法
     * 
     * @param jsonFilePath JSON文件路径
     */
    private static void processJsonFileWithRetry(String jsonFilePath) {
        int maxRetries = 3;
        int retryDelay = 2000; // 2秒延迟
        
        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                System.out.println("第 " + attempt + " 次尝试处理文件: " + jsonFilePath);
                processJsonFileForPinyin(jsonFilePath);
                System.out.println("文件处理成功完成");
                return; // 成功则退出
            } catch (Exception e) {
                System.err.println("第 " + attempt + " 次处理失败: " + e.getMessage());
                
                if (attempt < maxRetries) {
                    System.out.println("等待 " + (retryDelay / 1000) + " 秒后重试...");
                    try {
                        Thread.sleep(retryDelay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        System.err.println("重试等待被中断");
                        return;
                    }
                } else {
                    System.err.println("所有重试尝试均失败，放弃处理文件: " + jsonFilePath);
                    e.printStackTrace();
                }
            }
        }
    }
    
    /**
     * 处理JSON文件，为没有enName字段或enName为空的条目添加拼音形式的英文名称
     * 
     * @param jsonFilePath JSON文件路径
     */
    private static void processJsonFileForPinyin(String jsonFilePath) {
        File inputFile = new File(jsonFilePath);
        if (!inputFile.exists()) {
            System.out.println("文件不存在: " + jsonFilePath);
            return;
        }
        
        File tempFile = new File(jsonFilePath + ".tmp");
        
        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile, java.nio.charset.StandardCharsets.UTF_8));
             BufferedWriter writer = new BufferedWriter(new FileWriter(tempFile, java.nio.charset.StandardCharsets.UTF_8))) {
            
            String line;
            int totalCount = 0;
            int emptyEnNameCount = 0;  // 空enName字段计数
            int missingEnNameCount = 0; // 缺失enName字段计数
            int unchangedCount = 0;     // 未修改行计数
            
            System.out.println("开始处理文件: " + jsonFilePath);
            
            while ((line = reader.readLine()) != null) {
                totalCount++;
                String originalLine = line;
                String processedLine = processLineForPinyin(line);
                writer.write(processedLine);
                writer.newLine();
                
                // 统计处理类型
                if (!processedLine.equals(originalLine)) {
                    // 检查是空enName还是缺失enName
                    if (originalLine.contains("\"enName\":\"\"")) {
                        emptyEnNameCount++;
                    } else if (!originalLine.contains("\"enName\"")) {
                        missingEnNameCount++;
                    }
                } else {
                    unchangedCount++;
                }
                
                // 每处理1000行显示进度
                if (totalCount % 1000 == 0) {
                    System.out.println("已处理: " + totalCount + " 行");
                }
            }
            
            System.out.println("=== 处理完成统计 ===");
            System.out.println("文件: " + jsonFilePath);
            System.out.println("总行数: " + totalCount);
            System.out.println("空enName字段处理: " + emptyEnNameCount + " 行");
            System.out.println("缺失enName字段处理: " + missingEnNameCount + " 行");
            System.out.println("未修改行数: " + unchangedCount + " 行");
            System.out.println("总处理行数: " + (emptyEnNameCount + missingEnNameCount) + " 行");
            
        } catch (IOException e) {
            System.err.println("处理文件时出错: " + jsonFilePath);
            e.printStackTrace();
            return;
        }
        
        // 替换原文件
        if (inputFile.delete()) {
            if (tempFile.renameTo(inputFile)) {
                System.out.println("成功更新文件: " + jsonFilePath);
            } else {
                System.err.println("无法重命名临时文件: " + tempFile.getAbsolutePath());
            }
        } else {
            System.err.println("无法删除原文件: " + jsonFilePath);
        }
    }
    
    /**
     * 处理单行JSON数据，为没有enName或enName为空的条目添加拼音
     * 
     * @param jsonLine JSON行数据
     * @return 处理后的JSON行数据
     */
    private static String processLineForPinyin(String jsonLine) {
        if (jsonLine == null || jsonLine.trim().isEmpty()) {
            return jsonLine;
        }
        
        // 检查是否包含enName字段
        Pattern enNamePattern = Pattern.compile("\"enName\"\\s*:\\s*\"([^\"]*)\"");
        Matcher enNameMatcher = enNamePattern.matcher(jsonLine);
        
        if (enNameMatcher.find()) {
            String enNameValue = enNameMatcher.group(1);
            // 如果enName存在但为空，则添加拼音
            if (enNameValue.trim().isEmpty()) {
                return addPinyinToLine(jsonLine, enNameMatcher);
            }
            // enName已存在且不为空，不需要处理
            return jsonLine;
        } else {
            // 没有enName字段，需要添加
            return addEnNameFieldToLine(jsonLine);
        }
    }
    
    /**
     * 为已有enName字段但值为空的JSON行添加拼音
     */
    private static String addPinyinToLine(String jsonLine, Matcher enNameMatcher) {
        // 提取name字段的值
        Pattern namePattern = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]*)\"");
        Matcher nameMatcher = namePattern.matcher(jsonLine);
        
        if (nameMatcher.find()) {
            String nameValue = nameMatcher.group(1);
            String pinyinName = convertLocationToPinyin(nameValue);
            
            // 替换空的enName值
            return jsonLine.replace(enNameMatcher.group(0), "\"enName\":\"" + pinyinName + "\"");
        }
        
        return jsonLine;
    }
    
    /**
     * 为没有enName字段的JSON行添加enName字段
     */
    private static String addEnNameFieldToLine(String jsonLine) {
        // 提取name字段的值
        Pattern namePattern = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]*)\"");
        Matcher nameMatcher = namePattern.matcher(jsonLine);
        
        if (nameMatcher.find()) {
            String nameValue = nameMatcher.group(1);
            String pinyinName = convertLocationToPinyin(nameValue);
            
            // 在name字段后添加enName字段
            String nameField = nameMatcher.group(0);
            String replacement = nameField + ",\"enName\":\"" + pinyinName + "\"";
            return jsonLine.replace(nameField, replacement);
        }
        
        return jsonLine;
    }
}
