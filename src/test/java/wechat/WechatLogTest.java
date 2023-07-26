package wechat;

import com.alibaba.fastjson.JSONObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.junit.Test;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.io.*;
import java.net.URLDecoder;
import java.nio.file.Files;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Pattern;

public class WechatLogTest {
    @Test
    public void processWechatMsgTest() {
        processWechatMsg("H:\\WeChatExport\\CrazyBunQnQ");
    }

    @Test
    public void generateSimpleTrainingDataTest() {
        generateSimpleTrainingData("H:\\WeChatExport\\CrazyBunQnQ");
    }

    public void generateSimpleTrainingData(String inputPath) {
        File dir = new File(inputPath);
        File[] files = dir.listFiles();

        File outdir = new File("CrazyBotV1");
        if (!outdir.exists()) {
            outdir.mkdir();
        }
        String trainFilePath = "CrazyBotV1\\train.json";
        String devFilePath = "CrazyBotV1\\dev.json";
        int n = 0;
        try (BufferedWriter trainWriter = new BufferedWriter(new FileWriter(trainFilePath));
             BufferedWriter devWriter = new BufferedWriter(new FileWriter(devFilePath))) {
            for (File file : files) {
                if (!file.isFile() || !file.getName().endsWith(".json")) {
                    continue;
                }
                List<SimpleQA> qas = getQA(file, "CrazyBunQnQ");
                // 遍历 qas 将每一个对象转换为一行 json 字符串写入 outFilePath 中
                for (SimpleQA qa : qas) {
                    String line = JSONObject.toJSONString(qa);
                    if (n > 10) {
                        devWriter.write(line);
                        devWriter.newLine();
                        n = 0;
                    } else {
                        trainWriter.write(line);
                        trainWriter.newLine();
                        n++;
                    }
                }
                System.out.println("已生成 " + file.getName() + " 的 QA 对话并写入 " + trainFilePath);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 处理微微信聊天记录，批量将 html 转换为 json
     *
     * @param inputPath
     */
    public void processWechatMsg(String inputPath) {
        File dir = new File("H:\\WeChatExport\\CrazyBunQnQ");
        File[] files = dir.listFiles();
        for (File file : files) {
            if (!file.isFile() || !file.getName().endsWith(".html")) {
                continue;
            }
            wechatMsgHtmlToJson(file);
        }
    }

    private static final SimpleDateFormat sdf18 = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    private static final SimpleDateFormat sdf17 = new SimpleDateFormat("yyyyMMdd HH:mm:ss");
    private static final SimpleDateFormat sdf16_1 = new SimpleDateFormat("yyyy-MM-dd HH:mm");
    private static final SimpleDateFormat sdf16_2 = new SimpleDateFormat("yyyy-M-dd ahh:mm");
    private static final SimpleDateFormat sdf15 = new SimpleDateFormat("yyyyMd HH:mm:ss");
    private static final SimpleDateFormat sdf14 = new SimpleDateFormat("yyyyMMdd HH:mm");
    private static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-M-dd ahh:mm:ss");


    public List<SimpleQA> getQA(File input, String answerer) {
        List<SimpleQA> list = new ArrayList<>(100);
        String fileName = input.getName();
        fileName = fileName.substring(0, fileName.lastIndexOf("."));
        System.out.println("开始获取【" + fileName + "】的 QA 对话...");
        WechatMsg preMsg = null;
        // 遍历 input 的每一行
        try (BufferedReader br = new BufferedReader(new FileReader(input))) {
            String line;
            while ((line = br.readLine()) != null) {
                // WechatMsg curMsg = JSONObject.parseObject(line, WechatMsg.class);
                JSONObject jsonObject;
                try {
                    jsonObject = JSONObject.parseObject(line);
                } catch (Exception e) {
                    e.printStackTrace();
                    preMsg = null;
                    continue;
                }
                WechatMsg curMsg = new WechatMsg();
                curMsg.setType(jsonObject.getString("type"));
                curMsg.setContent(jsonObject.getString("content"));
                curMsg.setUserName(jsonObject.getString("userName"));
                curMsg.setDatetime(jsonObject.getString("datetime"));
                curMsg.setRefContent(jsonObject.getString("refContent"));
                curMsg.setUserId(jsonObject.getString("userId"));
                curMsg.setFrom(fileName);
                // 处理低质量对话和敏感信息
                if (dropMsg(curMsg)) {
                    continue;
                }
                // 没有提问或者回答者不是目标用户则跳过
                if (preMsg == null || !answerer.equals(curMsg.getUserName())) {
                    preMsg = curMsg;
                    continue;
                }
                if (StringUtils.isBlank(preMsg.getContent())) {
                    // TODO 可能是非文字
                    preMsg = null;
                    continue;
                }
                if (StringUtils.isBlank(curMsg.getContent())) {
                    // TODO 可能是非文字
                    // preMsg = curMsg;
                    continue;
                }
                // TODO 引用回答
                if (StringUtils.isNotBlank(curMsg.getRefContent())) {
                    // list.add(new SimpleQA(curMsg.getRefContent(), curMsg.getContent()));
                    // preMsg = curMsg;
                    continue;
                }
                // 问答是同一人则跳过
                if (preMsg.getUserName().equals(curMsg.getUserName())) {
                    preMsg = curMsg;
                    continue;
                }
                // curMsg 与 preMsg 时间差超过 5 分钟则跳过
                if (sdf18.parse(curMsg.getDatetime()).getTime() - sdf18.parse(preMsg.getDatetime()).getTime() > 5 * 60 * 1000) {
                    preMsg = curMsg;
                    continue;
                }
                list.add(new SimpleQA(preMsg.content, curMsg.content));
                preMsg = curMsg;
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        } finally {
            return list;
        }
    }

    /**
     * html 聊天记录转换为 JSON 格式
     *
     * @param input
     */
    public void wechatMsgHtmlToJson(File input) {
        // File input = new File("H:\\WeChatExport\\CrazyBunQnQ\\车勇志.html");
        // String jsFolderPath = "H:\\WeChatExport\\CrazyBunQnQ\\车勇志_files\\Data"; // JS 文件的目录
        String fileName = input.getName();
        fileName = fileName.substring(0, fileName.lastIndexOf("."));
        System.out.println("开始解析【" + fileName + "】的聊天记录...");
        String inputPath = input.getParentFile().getAbsolutePath();
        // String jsFolderPath = inputPath.substring(0, inputPath.lastIndexOf(".")) + "_files\\Data"; // JS 文件的目录
        String jsFolderPath = inputPath + File.separator + fileName + "_files\\Data"; // JS 文件的目录
        Document doc;
        try {
            doc = Jsoup.parse(input, "UTF-8");
            Elements chatElements = doc.select("div.msg.chat");
            String outFilePath = inputPath + File.separator + fileName + ".json";
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(outFilePath))) {
                for (Element chatElement : chatElements) {
                    String line = getJsonLine(chatElement);
                    writer.write(line);
                    writer.newLine();
                }
                File folder = new File(jsFolderPath);
                // 判断 folder 是否存在
                if (!folder.exists()) {
                    return;
                }

                File[] listOfFiles = folder.listFiles();

                if (listOfFiles == null) {
                    System.out.println("No files in the specified directory.");
                    return;
                }

                for (File file : listOfFiles) {
                    if (file.isFile() && file.getName().endsWith(".js")) {
                        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
                        try {
                            // 从 File file 中获取第一行包含 "var msgArray" 的字符串
                            String msgArrayStr = Files.lines(file.toPath())
                                    .filter(line -> line.contains("var msgArray"))
                                    .findFirst().get();
                            engine.eval(msgArrayStr);
                            List<String> msgList = new ArrayList<>();
                            Object msgArray = engine.get("msgArray");
                            if (msgArray instanceof jdk.nashorn.api.scripting.ScriptObjectMirror) {
                                jdk.nashorn.api.scripting.ScriptObjectMirror scriptObjectMirror = (jdk.nashorn.api.scripting.ScriptObjectMirror) msgArray;
                                if (scriptObjectMirror.isArray()) {
                                    msgList = Arrays.asList(scriptObjectMirror.values().toArray(new String[0]));
                                }

                                for (String htmlChat : msgList) {
                                    Document doc2 = Jsoup.parse(htmlChat);
                                    Elements chatElements2 = doc2.select("div.msg.chat");
                                    for (Element chatElement : chatElements2) {
                                        String line = getJsonLine(chatElement);
                                        writer.write(line);
                                        writer.newLine();
                                    }
                                }
                            }
                        } catch (ScriptException e) {
                            e.printStackTrace();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
            } catch (IOException e) {
                System.out.println("解析 " + fileName + "聊天记录时出错！");
                e.printStackTrace();
            }
            System.out.println("解析完成: " + outFilePath);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    Set<String> tmp = new HashSet<>(10);

    // {
    // tmp.add(".bmp");
    // tmp.add(".jpg");
    // tmp.add(".pdf");
    // tmp.add(".doc");
    // tmp.add("https://");
    // tmp.add(".mp3");
    // tmp.add(".mp4");
    // }
    private String getJsonLine(Element chatElement) {
        Element ntBox = chatElement.selectFirst("div.nt-box");
        // 时间
        String time = ntBox.text();
        // 人名
        String userName = chatElement.select("span.dspname").text();
        Element contentBox = chatElement.selectFirst("div.content-box");
        String elementStr = contentBox.toString();
        if (!tmp.contains(".bmp") && elementStr.contains(".bmp")) {
            System.out.println(elementStr);
            tmp.add(".bmp");
        }
        if (!tmp.contains(".jpg") && elementStr.contains(".jpg")) {
            System.out.println(elementStr);
            tmp.add(".jpg");
        }
        if (!tmp.contains(".pdf") && elementStr.contains(".pdf")) {
            System.out.println(elementStr);
            tmp.add(".pdf");
        }
        if (!tmp.contains(".doc") && elementStr.contains(".doc")) {
            System.out.println(elementStr);
            tmp.add(".doc");
        }
        if (!tmp.contains("https://") && elementStr.contains("https://")) {
            System.out.println(elementStr);
            tmp.add("https://");
        }
        if (!tmp.contains(".mp3") && elementStr.contains(".mp3")) {
            System.out.println(elementStr);
            tmp.add(".mp3");
        }
        if (!tmp.contains(".mp4") && elementStr.contains(".mp4")) {
            System.out.println(elementStr);
            tmp.add(".mp4");
        }
        if ("妈妈".equals(userName)) {
            System.out.println();
        }
        processMedia(contentBox);
        time = time.replace(userName, "").trim();
        Date date = getDate(time);
        if (userName.contains("\"") || userName.contains("\\")) {
            userName = userName.replace("\\", "\\\\");
            userName = userName.replace("\"", "\\\"");
        }
        // 用户 id
        String userId = ntBox.selectFirst("span.dspname").attr("wxId");
        // 内容
        String content = chatElement.select("span.dont-break-out.msg-text").text();
        if (content.contains("\"") || content.contains("\r") || content.contains("\n") || content.contains("\\")) {
            content = content.replace("\\", "\\\\");
            content = content.replace("\"", "\\\"");
            content = content.replace("\r\n", "\\n");
            content = content.replace("\n\r", "\\n");
            content = content.replace("\r", "\\n");
            content = content.replace("\n", "\\n");
        }
        // 引用内容
        String refContent = chatElement.select("span.dont-break-out.refermsg.msg-text").text();
        if (refContent.contains("\"") || refContent.contains("\r") || refContent.contains("\n") || content.contains("\\")) {
            refContent = refContent.replace("\\", "\\\\");
            refContent = refContent.replace("\"", "\\\"");
            refContent = refContent.replace("\r\n", "\\n");
            refContent = refContent.replace("\n\r", "\\n");
            refContent = refContent.replace("\r", "\\n");
            refContent = refContent.replace("\n", "\\n");
        }
        // 问 or 答
        String questionOrAnswer = chatElement.hasClass("left") ? "Q" : "A";


        // language=JSON
        return "{ " +
                "\"datetime\": \"" + sdf18.format(date) + "\", " +
                "\"type\": \"" + questionOrAnswer + "\", " +
                "\"userId\": \"" + userId + "\", " +
                "\"userName\": \"" + userName + "\", " +
                "\"content\": \"" + content + "\", " +
                "\"refContent\": \"" + refContent + "\" " +
                "}";
    }

    private void processMedia(Element contentBox) {
        Element a = contentBox.selectFirst("a");
        Element img = getImgElement(contentBox);
        if (a != null) {
            String name = a.text();
            String type = name.contains(".") ? name.substring(name.lastIndexOf(".") + 1) : null;
            String path = a.attr("href");
            if (path.startsWith("http") && type == null) {
                type = "link";
            }
            try {
                path = URLDecoder.decode(path, "UTF-8");
            } catch (UnsupportedEncodingException e) {
            }
        }
        if (img != null) {
            System.out.println();
        }
    }


    private static final Pattern PUNCTUATION_REG = Pattern.compile("(\\.{3,})|(。{3,})|(\\?{3,})|(？{3,})|(！{3,})|(!{3,})|(,{3,})|(，{3,})");
    private static final Pattern IMG_REG = Pattern.compile("\\[图片]");
    private static final Pattern PWD1_REG = Pattern.compile("[\\w@\\-=!#$%^&]{8,}.*((密码)|(key))");
    private static final Pattern PWD2_REG = Pattern.compile("((密码)|(key)).*[\\w@\\-=!#$%^&]{8,}");
    private static final Pattern BULLSHIT_REG = Pattern.compile("[.。?？]*[恩嗯呢呐好的滴啊阿哈呃额卧槽牛逼收到= en0.]*[.。?？]*");

    /**
     * 处理低质量对话和敏感信息
     *
     * @param msg
     * @return
     */
    private boolean dropMsg(WechatMsg msg) {
        String content = msg.getContent();
        String noSymbol = content.replaceAll("(\\.{3,})|(。{3,})|(\\?{3,})|(？{3,})|(！{3,})|(!{3,})|(,{3,})|(，{3,})", "");
        if (noSymbol.length() < 10) {
            return true;
        }
        if (IMG_REG.matcher(content).matches() || PWD1_REG.matcher(content).matches() || PWD2_REG.matcher(content).matches() || BULLSHIT_REG.matcher(content).matches()) {
            return true;
        }
        // TODO 可上下文
        if (content.startsWith("「")) {
            return true;
        }
        return false;
    }

    private static Element getImgElement(Element contentBox) {
        Element img = contentBox.selectFirst("img");
        Element appinfo = contentBox.selectFirst("div.appinfo");
        Element appinfoImg = appinfo == null ? null : appinfo.selectFirst("img");
        if (img != null && appinfoImg != null) {
            if (img.equals(appinfoImg)) {
                img = null;
            }
        }
        // wxemoji
        return img;
    }

    private static Date getDate(String time) {
        Date date = null;
        try {
            try {
                date = sdf18.parse(time);
            } catch (Exception ignored1) {
                try {
                    date = sdf16_1.parse(time);
                } catch (Exception ignored2) {
                    try {
                        date = sdf16_2.parse(time);
                    } catch (Exception ignored3) {
                        try {
                            date = sdf14.parse(time);
                        } catch (Exception ignored4) {
                            try {
                                date = sdf.parse(time);
                            } catch (Exception ignored5) {
                                try {
                                    date = sdf17.parse(time);
                                } catch (Exception ignored6) {
                                    date = sdf15.parse(time);
                                }
                            }
                        }
                    }
                }
            }
        } catch (ParseException e) {
            System.out.println("转换时间出错: " + time);
            System.out.println();
        }
        if (date == null) {
            System.out.println("转换时间出错: " + time);
            System.out.println();
        }
        return date;
    }

    @Data
    static class WechatMsg {
        private String datetime;
        private String type;
        private String userId;
        private String userName;
        private String content;
        private String refContent;
        private String from;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    class SimpleQA {
        private String content;
        private String summary;
    }
}
