package com.example.gatewayzuul.util;

import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

public class CorsHelper {

    public static HttpServletResponse addResponseHeaders(ServletResponse res) {

        HttpServletResponse httpResponse = (HttpServletResponse) res;

        httpResponse.setHeader("Access-Control-Allow-Origin", "*");
        httpResponse.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE");
        httpResponse.setHeader("Access-Control-Max-Age", "3600");
        httpResponse.setHeader("Access-Control-Allow-Credentials", "true");
        httpResponse.setHeader("Access-Control-Allow-Headers", "content-type,Authorization");

        return httpResponse;

    }

}
