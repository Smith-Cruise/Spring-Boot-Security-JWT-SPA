# Spring Boot 2 + Spring Security 5 + JWT 的单页应用 Restful 解决方案
# 預計新增為..
![](https://i.imgur.com/uK1g78i.png)

## 特性
* 使用 JWT 進行鑑權，支持 token 過期
* 使用 Ehcache 進行緩存，減少每次鑑權對數據庫的壓力
* 盡可能貼合 Spring Security 的設計
* 實現註解權限控制

## 預計新增
* 攔截header為範例
* 預計Ehcache 改為 redis 單機 進行緩存
* 預計Ehcache 改為 redis cluster 進行緩存
* 預計loadblance 採用 nginx 進行 負載平衡

## 呼叫方式
```java
    private static void sendRequest() throws Exception{
    	  HttpPost post = new HttpPost("http://192.168.0.146:8080/login");

          // add request parameter, form parameters
          List<NameValuePair> urlParameters = new ArrayList<>();
          urlParameters.add(new BasicNameValuePair("username", "jack"));
          urlParameters.add(new BasicNameValuePair("password", "jack123"));
          //urlParameters.add(new BasicNameValuePair("custom", "secret"));

          post.setEntity(new UrlEncodedFormEntity(urlParameters));

          try (CloseableHttpClient httpClient = HttpClients.createDefault();
               CloseableHttpResponse response = httpClient.execute(post)) {

              System.out.println(EntityUtils.toString(response.getEntity()));
          }
    }
    
    private static  void sendGet() throws ClientProtocolException, IOException  {

    	  HttpGet request = new HttpGet("http://192.168.0.146:8080/user");

          // add request headers
          request.addHeader("Authorization", "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1Nzc0MjI0NDYsInVzZXJuYW1lIjoiamFjayJ9.iOLivJ6D2L9Ot7IznfSlp-TRgDSAvE53UIUo3c0PBQo");
        //  request.addHeader(HttpHeaders.USER_AGENT, "Googlebot");

          try (CloseableHttpResponse response = httpClient.execute(request)) {

              // Get HttpResponse Status
              System.out.println(response.getStatusLine().toString());

              HttpEntity entity = response.getEntity();
              Header headers = entity.getContentType();
              System.out.println(headers);

              if (entity != null) {
                  // return it as a String
                  String result = EntityUtils.toString(entity);
               
                  System.out.println(result);
                  
              }

          }
    }
```

# Postman
login/post
>http://localhost:8080/login
>
![](https://i.imgur.com/Ao5W3my.png)

user/get
>http://localhost:8080/user
>
![](https://i.imgur.com/0wB5IiK.png)

# redis
![](https://i.imgur.com/KZv2T3i.png)
![](https://i.imgur.com/zP5MrLW.png)



# 原始項目
https://github.com/Smith-Cruise/Spring-Boot-Security-JWT-SPA
