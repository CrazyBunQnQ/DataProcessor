package com.crazybunqnq.dataprocessor.geo;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class GeoLite2Convert {

    /**
     * id 对应的地理位置
     */
    private static Map<String, String[]> idLocationMap = new HashMap<>();
    /**
     * 地理位置对应的 id
     */
    private static Map<String, String> locationIdMap = new HashMap<>();
    /**
     * 国家或省的 id
     */
    private static Map<String, String> parentIdMap = new HashMap<>();
    /**
     * 已存储的 id 集合
     */
    private static Set<String> savedIdSet = new HashSet<>();
    /**
     * 已存储的位置集合
     */
    private static Set<String> savedLocations = new HashSet<>();
    private static Map<String, String> removedIdMap = new HashMap<>();// 忽略的 id 要在其他绑定关系中修改关联 id

    /**
     * 判断重复
     * name + "_" + parent_ip
     */
    private static Map<String, String> pidNameMap = new HashMap<>();
    /**
     * name 与 parent_ip 相同则视为重复
     * key: 原 id
     * value: 改写后的 id
     */
    private static Map<String, String> idRewriteMap = new HashMap<>();

    private static Map<String, Geography> cnRegionMap = new HashMap<>();
    private static Map<String, String> chineseProvincesAndCitiesRewritten = new HashMap<>();
    private static Map<String, String> cnIdPidMap = new HashMap<>();

    public static void main(String[] args) {
    }

    /**
     * 读取中国数据
     *
     * @param csvPath
     */
    public static void readCnData(String csvPath) {
        cnRegionMap.put("1814991", new Geography("1814991", "中国", "0", "34.77", "113.72"));
        try (InputStream is = GeoLite2Convert.class.getClassLoader().getResourceAsStream(csvPath);
             BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {

            String line;
            // 忽略表头
            br.readLine();

            while ((line = br.readLine()) != null) {
                // 处理每一行数据
                String[] tokens = line.split(",");
                if (tokens.length < 5) {
                    continue; // 跳过不完整的行
                }

                String id = tokens[0].trim();
                String name = tokens[1].trim();
                String parentId = tokens[2].trim().isEmpty() || "\"\"".equals(tokens[2].trim()) ? "1814991" : (tokens[2].trim());
                // 长度不足 12 则在前面用 0 补全
                id = id.length() < 12 ? "0".repeat(12 - id.length()) + id : id;
                parentId = !"1814991".equals(parentId) && parentId.length() < 12 ? "0".repeat(12 - parentId.length()) + parentId : parentId;
                String lng = tokens[3].trim();
                String lat = tokens[4].trim();

                Geography geography = new Geography(id, name, parentId, lat, lng);
                cnRegionMap.put(id, geography);
                if (name.endsWith("省")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("省")), name);
                } else if (name.endsWith("市")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("市")), name);
                } else if (name.endsWith("特别行政区")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("特别行政区")), name);
                } else if (name.endsWith("维吾尔自治区")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("维吾尔自治区")), name);
                } else if (name.endsWith("回族自治区")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("回族自治区")), name);
                } else if (name.endsWith("壮族自治区")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("壮族自治区")), name);
                } else if (name.endsWith("自治区")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("自治区")), name);
                } else if (name.endsWith("区")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("区")), name);
                } else if (name.endsWith("自治县")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("自治县")), name);
                } else if (name.endsWith("县")) {
                    chineseProvincesAndCitiesRewritten.put(name.substring(0, name.indexOf("县")), name);
                }
                cnIdPidMap.put(id, parentId);
            }
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        //     遍历 cnRegionMap
        for (Geography geography : cnRegionMap.values()) {
            String id = geography.getId();
            String parentId = geography.getParentId();

            // 重写 id
            if (idRewriteMap.containsKey(id)) {
                id = idRewriteMap.get(id);
            }

            String savedName = getFullNameById(id);
            if (locationIdMap.containsKey(savedName)) {
                // 忽略的 id 要在其他绑定关系中修改关联 id
                removedIdMap.put(id, savedName);
                continue;
            }
            locationIdMap.put(savedName, id);
            String[] split = savedName.split(" ");
            String contryName = split.length > 0 ? split[0] : "";
            String provinceName = split.length > 1 ? split[1] : "";
            String cityName = split.length > 2 ? split[2] : "";
            String simpleName = split[split.length - 1];
            if (cityName == null || cityName.trim().isEmpty()) {
                if (provinceName == null || provinceName.trim().isEmpty()) {
                    parentIdMap.put(contryName, id);
                } else {
                    parentIdMap.put(contryName + " " + provinceName, id);
                }
            } else if (provinceName == null || provinceName.trim().isEmpty()) {
                parentIdMap.put(contryName, id);
            }
            idLocationMap.put(id, new String[]{contryName, provinceName, cityName, simpleName});

        }
    }

    // 根据 id 获取完整的 name 路径，递归获取父级名称
    public static String getFullNameById(String id) {
        // 存储完整的名称路径
        StringBuilder fullName = new StringBuilder();

        // 递归过程：向上查找父级直到没有父级
        Geography geography = cnRegionMap.get(id);
        if (geography != null) {
            fullName.insert(0, geography.getName()); // 将当前的名称加到前面
            String parentId = cnIdPidMap.get(id);
            if (parentId != null && !parentId.isEmpty()) {
                // 如果有父级，递归获取父级的名称
                fullName.insert(0, " ");  // 在父级名称和当前名称之间添加空格
                fullName.insert(0, getFullNameById(parentId)); // 递归调用获取父级名称
            }
        }

        return fullName.toString().trim();
    }

    /**
     * 从指定路径读取地点数据文件，解析并处理各层级（国家、省份、城市）的地点信息，修正特殊地区名称映射，并存储到全局映射表中。
     *
     * @param locationsPath
     */
    public static void readLocations(String locationsPath) {
        try (BufferedReader br = new BufferedReader(new FileReader(locationsPath))) {
            String line;
            br.readLine(); // Skip header
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                String id = values[0];
                String contryName = values[5];
                String provinceName = values[7];
                if (line.contains("台湾") || line.contains("香港") || line.contains("澳门")) {
                    provinceName = contryName;
                    contryName = "中国";
                }
                String cityName = values[10].replace("\"", "");
                // 修改中国省市
                if (chineseProvincesAndCitiesRewritten.containsKey(provinceName)) {
                    provinceName = chineseProvincesAndCitiesRewritten.get(provinceName);
                }
                if (chineseProvincesAndCitiesRewritten.containsKey(cityName)) {
                    cityName = chineseProvincesAndCitiesRewritten.get(cityName);
                }
                if (cityName == null || cityName.trim().isEmpty()) {
                    if (provinceName == null || provinceName.trim().isEmpty()) {
                        parentIdMap.put(contryName, id);
                    } else {
                        parentIdMap.put(contryName + " " + provinceName, id);
                    }
                } else if (provinceName == null || provinceName.trim().isEmpty()) {
                    parentIdMap.put(contryName, id);
                }
                String simpleName = !cityName.isEmpty() ? cityName : (!provinceName.isEmpty() ? provinceName : contryName);
                String savedName = contryName + " " + provinceName + " " + cityName;
                savedName = savedName.trim();
                if (locationIdMap.containsKey(savedName)) {
                    // 忽略的 id 要在其他绑定关系中修改关联 id
                    removedIdMap.put(id, savedName);
                } else {
                    idLocationMap.put(id, new String[]{contryName, provinceName, cityName, simpleName});
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    /**
     * 从指定文件中读取数据，去除重复的地名标识符（geonameId），并根据映射关系更新和存储唯一的地名信息，同时记录被忽略的重复标识符。
     *
     * @param ipv4Path
     */
    public static void removeDuplicates(String ipv4Path) {
        Set<String> tmpId = new HashSet<>();
        try (BufferedReader br = new BufferedReader(new FileReader(ipv4Path))) {
            String line;
            br.readLine(); // Skip header
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                String geonameId = values[1];
                if (tmpId.contains(geonameId)) {
                    continue;
                }

                if (idLocationMap.containsKey(geonameId)) {
                    String[] locationInfo = idLocationMap.get(geonameId);
                    String cityName = locationInfo[2];
                    String provinceName = locationInfo[1];
                    String parentName = locationInfo[0];
                    String savedName = parentName + " " + provinceName + " " + cityName;
                    savedName = savedName.trim();
                    if (locationIdMap.containsKey(savedName)) {
                        // 忽略的 id 要在其他绑定关系中修改关联 id
                        removedIdMap.put(geonameId, savedName);
                        continue;
                    }
                    locationIdMap.put(savedName, geonameId);
                    tmpId.add(geonameId);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 将指定的 IPv4 文件解析为城市信息 JSON 数据，并写入目标文件。
     * 方法会跳过文件头，逐行读取、解析并转换为城市信息，同时处理相关数据映射和去重逻辑。
     * 输出格式包括城市的纬度、经度、名称、ID、排序值以及父级 ID。
     */
    public static void convertToCityInfo(String ipv4Path, String locationsOutputPath) {
        try (BufferedReader br = new BufferedReader(new FileReader(ipv4Path)); FileWriter fw = new FileWriter(locationsOutputPath)) {
            String line;
            br.readLine(); // Skip header
            fw.write("[");
            boolean firstEntry = true;
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                String geonameId = values[1];
                String latitude = "0";
                String longitude = "0";
                try {
                    latitude = String.format("%.2f", Double.parseDouble(values[7]));
                    longitude = String.format("%.2f", Double.parseDouble(values[8]));
                } catch (Exception ignored) {
                }

                if (idLocationMap.containsKey(geonameId)) {
                    String[] locationInfo = idLocationMap.get(geonameId);
                    String cityName = locationInfo[2];
                    String provinceName = locationInfo[1];
                    String parentName = locationInfo[0];
                    if (savedIdSet.contains(geonameId)) {
                        continue;
                    }
                    String savedName = parentName + " " + provinceName + " " + cityName;
                    savedName = savedName.trim();
                    String parentId = "";
                    if (!cityName.isEmpty() && !provinceName.isEmpty()) {
                        parentName = parentName + " " + provinceName;
                    }
                    if (parentIdMap.containsKey(parentName)) {
                        parentId = parentIdMap.get(parentName);
                    }
                    if (removedIdMap.containsKey(parentId)) {
                        parentId = locationIdMap.get(parentName);
                    }
                    if (removedIdMap.containsKey(geonameId)) {
                        geonameId = locationIdMap.get(savedName);
                    }
                    if (savedLocations.contains(savedName)) {
                        continue;
                    }
                    String simpleName = locationInfo[3];
                    if (simpleName == null || simpleName.trim().isEmpty()) {
                        continue;
                    }

                    String key = simpleName + "_" + parentId;
                    if (pidNameMap.containsKey(key)) {
                        idRewriteMap.put(geonameId, pidNameMap.get(key));
                        System.out.println(simpleName + " id: " + geonameId + " 改写为 " + pidNameMap.get(key));
                        continue;
                    }
                    if (!firstEntry) {
                        fw.write(",\n");
                    } else {
                        fw.write("\n");
                        firstEntry = false;
                    }
                    String entry;
                    if (parentId == null || "".equals(parentId.trim()) || geonameId.equals(parentId)) {
                        entry = String.format("{\"latitude\": %s, \"name\": \"%s\", \"id\": \"%s\", \"orderValue\": %s, \"parentId\": null, \"longitude\": %s}", latitude, simpleName, geonameId, geonameId, longitude);
                    } else {
                        entry = String.format("{\"latitude\": %s, \"name\": \"%s\", \"id\": \"%s\", \"orderValue\": %s, \"parentId\": \"%s\", \"longitude\": %s}", latitude, simpleName, geonameId, geonameId, parentId, longitude);
                        pidNameMap.put(key, geonameId);
                    }
                    fw.write(entry);
                    savedIdSet.add(geonameId);
                    savedLocations.add(savedName);
                }
            }

            // 读取 resources/geo_cn 下的 cn_region.csv 文件
            String csvPath = "geo_cn/cn_region.csv";
            convertCnRegionToCityInfo(csvPath, fw);

            fw.write("\n]");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void convertCnRegionToCityInfo(String csvPath, FileWriter fw) {
        try (InputStream is = GeoLite2Convert.class.getClassLoader().getResourceAsStream(csvPath);
             BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {

            String line;
            // 忽略表头
            br.readLine();

            while ((line = br.readLine()) != null) {
                // 处理每一行数据
                String[] tokens = line.split(",");
                if (tokens.length < 5) {
                    continue; // 跳过不完整的行
                }

                String id = tokens[0].trim();
                // 长度不足 12 则在前面用 0 补全
                id = id.length() < 12 ? "0".repeat(12 - id.length()) + id : id;
                String name = tokens[1].trim();
                // name = renameLocation(name);
                String parentId = tokens[2].trim().isEmpty() || "\"\"".equals(tokens[2].trim()) ? "1814991" : (tokens[2].trim());
                // 长度不足 12 则在前面用 0 补全
                parentId = !"1814991".equals(parentId) && parentId.length() < 12 ? "0".repeat(12 - parentId.length()) + parentId : parentId;
                String lng = tokens[3].trim();
                String lat = tokens[4].trim();

                String entry = String.format(
                        "{\"latitude\": %s, \"name\": \"%s\", \"id\": \"%s\", \"orderValue\": %s, \"parentId\": \"%s\", \"longitude\": %s}",
                        lat, name, id, id, parentId, lng);

                fw.write(",\n");
                fw.write(entry);
            }
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 该方法将 IPv4 地址段文件转换为包含地理信息的 JSON 数据文件。
     * 读取输入文件中的每个地址段，结合地理信息映射生成 JSON 格式的地址信息并写入输出文件。
     * 若地址段或地理信息无效则跳过，输出中包含 IP 范围和对应地理位置。
     */
    public static void convertToIpInfo(String ipv4Path, String ipOutputPath) {
        long id = 1;
        try (BufferedReader br = new BufferedReader(new FileReader(ipv4Path)); FileWriter fw = new FileWriter(ipOutputPath)) {
            String line;
            br.readLine(); // Skip header
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                String network = values[0];
                String geonameId = values[1]; // 地理位置 id
                if ("".equals(geonameId)) {
                    geonameId = values[2]; // 注册国家 id
                }
                if ("".equals(geonameId)) {
                    geonameId = values[3]; // 代表国家 id
                }
                if (removedIdMap.containsKey(geonameId)) {
                    geonameId = locationIdMap.get(removedIdMap.get(geonameId));
                }
                if (idRewriteMap.containsKey(geonameId)) {
                    geonameId = idRewriteMap.get(geonameId);
                }
                String[] ips = convertNetworkToIps(network);
                if (ips == null) {
                    continue;
                }
                String[] location = idLocationMap.get(geonameId);

                if (location != null) {
                    String cityInfo = location[0] + " " + location[1] + " " + location[2];
                    cityInfo = cityInfo.trim();
                    // 可能只有大洲，没有国家
                    if (cityInfo == null || cityInfo.isEmpty()) {
                        continue;
                    }
                    String result = "{\"city\":\"" + cityInfo + "\",\"start_ip\":" + ips[0] + ",\"id\":\"" + id + "\",\"end_ip\":" + ips[1] + "}";
                    fw.write(result + "\n");
                    id++;
                } else {
                    System.out.println("未识别地理位置信息: " + line);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 将 CIDR 网络段（如 "192.168.0.0/24"）转换为对应的起始和结束 IP 地址的整数表示。
     * 通过解析网络前缀计算掩码，并返回包含起始和结束 IP 的字符串数组。
     * 如果解析失败，则返回 null。
     */
    private static String[] convertNetworkToIps(String network) {
        String[] parts = network.split("/");
        String ip = parts[0];
        int prefixLength = Integer.parseInt(parts[1]);

        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            byte[] address = inetAddress.getAddress();

            int mask = 0xffffffff << (32 - prefixLength);
            byte[] maskBytes = new byte[]{
                    (byte) (mask >>> 24),
                    (byte) (mask >> 16 & 0xff),
                    (byte) (mask >> 8 & 0xff),
                    (byte) (mask & 0xff)
            };

            byte[] startAddress = new byte[4];
            for (int i = 0; i < 4; i++) {
                startAddress[i] = (byte) (address[i] & maskBytes[i]);
            }

            byte[] endAddress = new byte[4];
            for (int i = 0; i < 4; i++) {
                endAddress[i] = (byte) (startAddress[i] | ~maskBytes[i]);
            }

            InetAddress startInetAddress = InetAddress.getByAddress(startAddress);
            InetAddress endInetAddress = InetAddress.getByAddress(endAddress);
            long startIp = ipToLong(startInetAddress.getHostAddress());
            long endIp = ipToLong(endInetAddress.getHostAddress());

            return new String[]{Long.toString(startIp), Long.toString(endIp)};

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static long ipToLong(String ipString) {
        String[] octets = ipString.split("\\.");
        long ip = 0;
        for (int i = 0; i < 4; i++) {
            ip += Long.parseLong(octets[i]) << (24 - (8 * i));
        }
        return ip;
    }

    /**
     * 地理位置统一省市明明规则
     *
     * @param location
     * @return
     */
    private static String renameLocation(String location) {
        if (sheng.isEmpty()) {
            initCnData();
        }
        if (sheng.containsKey(location)) {
            return sheng.get(location);
        }
        return location;
    }

    private static Map<String, String> sheng = new HashMap<>();

    private static void initCnData() {
        sheng.put("北京", "北京市");
        sheng.put("天津", "天津市");
        sheng.put("河北", "河北省");
        sheng.put("山西", "山西省");
        sheng.put("内蒙古", "内蒙古自治区");
        sheng.put("辽宁", "辽宁省");
        sheng.put("吉林", "吉林省");
        sheng.put("黑龙江", "黑龙江省");
        sheng.put("上海", "上海市");
        sheng.put("江苏", "江苏省");
        sheng.put("浙江", "浙江省");
        sheng.put("安徽", "安徽省");
        sheng.put("福建", "福建省");
        sheng.put("江西", "江西省");
        sheng.put("山东", "山东省");
        sheng.put("河南", "河南省");
        sheng.put("湖北", "湖北省");
        sheng.put("湖南", "湖南省");
        sheng.put("广东", "广东省");
        sheng.put("广西", "广西壮族自治区");
        sheng.put("海南", "海南省");
        sheng.put("重庆", "重庆市");
        sheng.put("四川", "四川省");
        sheng.put("贵州", "贵州省");
        sheng.put("云南", "云南省");
    }

}
