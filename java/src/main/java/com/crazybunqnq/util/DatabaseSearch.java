package com.crazybunqnq.util;

import java.sql.*;
import java.util.HashSet;
import java.util.Set;

public class DatabaseSearch {

    private static Set<String> cache = new HashSet<>();

    // 方法用于在指定数据库中查找指定值的位置
    public static void findValueInDatabase(String jdbcUrl, String username, String password, String dbName, String value) {
        // 使用 Java 8 的 try-with-resources 自动关闭资源
        try (
                // 加载 MySQL JDBC 驱动程序
                // Class.forName("com.mysql.cj.jdbc.Driver");
                Connection conn = DriverManager.getConnection(jdbcUrl, username, password);
                Statement stmt = conn.createStatement();
        ) {
            // 获取数据库中所有表名
            DatabaseMetaData metaData = conn.getMetaData();
            ResultSet tables = metaData.getTables(dbName, null, null, new String[]{"TABLE"});

            while (tables.next()) {
                String tableName = tables.getString("TABLE_NAME");
                // 查询表中的所有列名
                ResultSet columns = metaData.getColumns(dbName, null, tableName, null);

                while (columns.next()) {
                    String columnName = columns.getString("COLUMN_NAME");
                    // 构造查询语句，检查是否存在指定值
                    String query = "SELECT " + columnName + " FROM " + tableName + " WHERE " + columnName + " = ?";

                    try (PreparedStatement pstmt = conn.prepareStatement(query)) {
                        pstmt.setString(1, value);
                        ResultSet resultSet = pstmt.executeQuery();

                        if (resultSet.next()) {
                            String v = resultSet.getString(1);
                            if (value.equals(v)) {
                                if (cache.contains(tableName)) {
                                    break;
                                } else {
                                    System.out.println("Value found in table: " + tableName + ", column: " + columnName);
                                    cache.add(tableName);
                                }
                            }
                        }
                    } catch (Exception e) {
                        System.out.println(e.getMessage());
                    }
                }
            }

        } catch (SQLException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
