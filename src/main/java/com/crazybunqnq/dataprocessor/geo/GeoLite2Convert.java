package com.crazybunqnq.dataprocessor.geo;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

public class GeoLite2Convert {
    private static final String LOCATIONS_PATH = "F:\\下载\\GeoLite2-City-CSV_20231006\\GeoLite2-City-Locations-zh-CN.csv";
    private static final String IPV4_PATH = "F:\\下载\\GeoLite2-City-CSV_20231006\\GeoLite2-City-Blocks-IPv4.csv";
    private static final String OUTPUT_PATH = "F:\\下载\\GeoLite2-City-CSV_20231006\\Geography_Ip.json";

    public static void main(String[] args) {
        Map<String, String[]> locationMap = new HashMap<>();

        try (BufferedReader br = new BufferedReader(new FileReader(LOCATIONS_PATH))) {
            String line;
            br.readLine(); // Skip header
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                locationMap.put(values[0], new String[]{values[5], values[7], values[10]});
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (BufferedReader br = new BufferedReader(new FileReader(IPV4_PATH));
             FileWriter fw = new FileWriter(OUTPUT_PATH)) {
            String line;
            br.readLine(); // Skip header
            fw.write("[\n");
            boolean firstEntry = true;
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                String network = values[0];
                String geonameId = values[1];
                String[] ips = convertNetworkToIps(network);
                if (ips == null) {
                    continue;
                }
                String[] location = locationMap.get(geonameId);

                if (location != null) {
                    if (!firstEntry) {
                        fw.write(",");
                    } else {
                        firstEntry = false;
                    }
                    String cityInfo = location[0] + " " + location[1] + " " + location[2];
                    String result = "{\"city\":\"" + cityInfo + "\",\"start_ip\":" + ips[0] + ",\"id\":\"" + geonameId + "\",\"end_ip\":" + ips[1] + "}\n";
                    fw.write(result);
                }
            }
            fw.write("]");
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
            byte[] maskBytes = new byte[] {
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
