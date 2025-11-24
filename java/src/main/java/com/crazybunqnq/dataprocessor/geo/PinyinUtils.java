package com.crazybunqnq.dataprocessor.geo;

import net.sourceforge.pinyin4j.PinyinHelper;
import net.sourceforge.pinyin4j.format.HanyuPinyinCaseType;
import net.sourceforge.pinyin4j.format.HanyuPinyinOutputFormat;
import net.sourceforge.pinyin4j.format.HanyuPinyinToneType;
import net.sourceforge.pinyin4j.format.HanyuPinyinVCharType;
import net.sourceforge.pinyin4j.format.exception.BadHanyuPinyinOutputFormatCombination;

/**
 * 拼音转换工具类
 */
public class PinyinUtils {
    
    private static final HanyuPinyinOutputFormat format = new HanyuPinyinOutputFormat();
    
    static {
        // 设置拼音格式：小写，无音调，用v表示ü
        format.setCaseType(HanyuPinyinCaseType.LOWERCASE);
        format.setToneType(HanyuPinyinToneType.WITHOUT_TONE);
        format.setVCharType(HanyuPinyinVCharType.WITH_V);
    }
    
    /**
     * 将中文转换为拼音，每个字的拼音首字母大写，用空格分隔
     * 例如：北京 -> Bei Jing
     * 
     * @param chinese 中文字符串
     * @return 拼音字符串
     */
    public static String toPinyin(String chinese) {
        if (chinese == null || chinese.trim().isEmpty()) {
            return "";
        }
        
        StringBuilder result = new StringBuilder();
        char[] chars = chinese.toCharArray();
        
        for (char ch : chars) {
            if (Character.toString(ch).matches("[\\u4e00-\\u9fa5]")) {
                // 是中文字符
                try {
                    String[] pinyinArray = PinyinHelper.toHanyuPinyinStringArray(ch, format);
                    if (pinyinArray != null && pinyinArray.length > 0) {
                        String pinyin = pinyinArray[0];
                        // 首字母大写
                        pinyin = pinyin.substring(0, 1).toUpperCase() + pinyin.substring(1);
                        result.append(pinyin).append(" ");
                    } else {
                        // 无法转换的中文字符，保持原样
                        result.append(ch).append(" ");
                    }
                } catch (BadHanyuPinyinOutputFormatCombination e) {
                    // 转换失败，保持原字符
                    result.append(ch).append(" ");
                }
            } else if (Character.isLetter(ch) || Character.isDigit(ch)) {
                // 英文字母或数字，直接添加
                result.append(ch);
            } else if (ch == ' ') {
                // 空格，添加一个空格
                if (result.length() > 0 && result.charAt(result.length() - 1) != ' ') {
                    result.append(" ");
                }
            }
            // 其他字符（标点符号等）忽略
        }
        
        return result.toString().trim();
    }
    
    /**
     * 处理地理位置名称，将中文部分转换为拼音
     * 例如：中国 北京市 朝阳区 -> China Beijing Chaoyang
     * 
     * @param locationName 地理位置名称
     * @return 拼音形式的地理位置名称
     */
    public static String convertLocationToPinyin(String locationName) {
        if (locationName == null || locationName.trim().isEmpty()) {
            return "";
        }
        
        // 移除常见的地理位置后缀
        String cleaned = locationName
                .replace("省", "")
                .replace("市", "")
                .replace("区", "")
                .replace("县", "")
                .replace("自治区", "")
                .replace("特别行政区", "")
                .replace("维吾尔", "")
                .replace("回族", "")
                .replace("壮族", "")
                .replace("藏族", "")
                .replace("蒙古", "Mongolia")
                .trim();
        
        // 特殊地名映射
        cleaned = replaceSpecialNames(cleaned);
        
        return toPinyin(cleaned);
    }
    
    /**
     * 替换特殊地名为英文
     */
    private static String replaceSpecialNames(String name) {
        // 国家名称
        name = name.replace("中国", "China");
        name = name.replace("美国", "United States");
        name = name.replace("英国", "United Kingdom");
        name = name.replace("法国", "France");
        name = name.replace("德国", "Germany");
        name = name.replace("日本", "Japan");
        name = name.replace("韩国", "South Korea");
        name = name.replace("俄罗斯", "Russia");
        name = name.replace("印度", "India");
        name = name.replace("巴西", "Brazil");
        name = name.replace("澳大利亚", "Australia");
        name = name.replace("加拿大", "Canada");
        
        // 中国主要城市
        name = name.replace("北京", "Beijing");
        name = name.replace("上海", "Shanghai");
        name = name.replace("广州", "Guangzhou");
        name = name.replace("深圳", "Shenzhen");
        name = name.replace("天津", "Tianjin");
        name = name.replace("重庆", "Chongqing");
        name = name.replace("南京", "Nanjing");
        name = name.replace("杭州", "Hangzhou");
        name = name.replace("成都", "Chengdu");
        name = name.replace("西安", "Xi'an");
        name = name.replace("武汉", "Wuhan");
        name = name.replace("青岛", "Qingdao");
        name = name.replace("大连", "Dalian");
        name = name.replace("宁波", "Ningbo");
        name = name.replace("厦门", "Xiamen");
        name = name.replace("福州", "Fuzhou");
        name = name.replace("沈阳", "Shenyang");
        name = name.replace("长春", "Changchun");
        name = name.replace("哈尔滨", "Harbin");
        name = name.replace("石家庄", "Shijiazhuang");
        name = name.replace("太原", "Taiyuan");
        name = name.replace("呼和浩特", "Hohhot");
        name = name.replace("长沙", "Changsha");
        name = name.replace("郑州", "Zhengzhou");
        name = name.replace("济南", "Jinan");
        name = name.replace("合肥", "Hefei");
        name = name.replace("南昌", "Nanchang");
        name = name.replace("昆明", "Kunming");
        name = name.replace("贵阳", "Guiyang");
        name = name.replace("兰州", "Lanzhou");
        name = name.replace("西宁", "Xining");
        name = name.replace("银川", "Yinchuan");
        name = name.replace("乌鲁木齐", "Urumqi");
        name = name.replace("拉萨", "Lhasa");
        name = name.replace("海口", "Haikou");
        name = name.replace("三亚", "Sanya");
        
        return name;
    }
}