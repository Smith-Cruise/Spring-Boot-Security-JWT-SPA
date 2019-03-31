package org.inlighting.spa.datasource;

import java.util.HashMap;
import java.util.Map;

public class Database {
    private static Map<String, Map<String, String>> data = new HashMap<>();

    static {
        Map<String, String> data1 = new HashMap<>();
        data1.put("password", "smith123");
        data1.put("role", "ROLE_USER");

        Map<String, String> data2 = new HashMap<>();
        data2.put("password", "danny123");
        data2.put("role", "ROLE_ADMIN");

        data.put("smith", data1);
        data.put("danny", data2);
    }

    public static Map<String, Map<String, String>> getData() {
        return data;
    }
}
