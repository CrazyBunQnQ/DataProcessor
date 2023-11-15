package com.crazybunqnq.dataprocessor.geo;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
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
    private static Map<String, String[]> locationMap = new HashMap<>();
    /**
     * 国家或省的 id
     */
    private static Map<String, String> parentIdMap = new HashMap<>();
    private static Set<String> idSet = new HashSet<>();
    private static Set<String> savedLocations = new HashSet<>();
    private static Map<String, String> savedLocationMap = new HashMap<>();
    private static Map<String, String> removedIdMap = new HashMap<>();

    public static void main(String[] args) {
    }

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
                String cityName = values[10];
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
                locationMap.put(id, new String[]{contryName, provinceName, cityName, simpleName});
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

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

                if (locationMap.containsKey(geonameId)) {
                    String[] locationInfo = locationMap.get(geonameId);
                    String cityName = locationInfo[2];
                    String provinceName = locationInfo[1];
                    String parentName = locationInfo[0];
                    String savedName = parentName + " " + provinceName + " " + cityName;
                    savedName = savedName.trim();
                    if (savedLocationMap.containsKey(savedName)) {
                        // 忽略的 id 要在其他绑定关系中修改关联 id
                        removedIdMap.put(geonameId, savedName);
                        continue;
                    }
                    savedLocationMap.put(savedName, geonameId);
                    tmpId.add(geonameId);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

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

                if (locationMap.containsKey(geonameId)) {
                    String[] locationInfo = locationMap.get(geonameId);
                    String cityName = locationInfo[2];
                    String provinceName = locationInfo[1];
                    String parentName = locationInfo[0];
                    if (idSet.contains(geonameId)) {
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
                        parentId = savedLocationMap.get(parentName);
                    }
                    if (removedIdMap.containsKey(geonameId)) {
                        geonameId = savedLocationMap.get(savedName);
                    }
                    if (savedLocations.contains(savedName)) {
                        continue;
                    }
                    String simpleName = locationInfo[3];
                    if (simpleName == null || simpleName.trim().isEmpty()) {
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
                    }
                    fw.write(entry);
                    idSet.add(geonameId);
                    savedLocations.add(savedName);
                }
            }
            fw.write("\n]");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

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
                    geonameId = savedLocationMap.get(removedIdMap.get(geonameId));
                }
                String[] ips = convertNetworkToIps(network);
                if (ips == null) {
                    continue;
                }
                String[] location = locationMap.get(geonameId);

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
}
