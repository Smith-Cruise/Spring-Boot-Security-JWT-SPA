# Spring Boot 2 + Spring Security 5 + JWT 的单页应用 Restful 解决方案

此前我已经写过一篇类似的教程，但那时候使用了投机的方法，没有尊重 Spring Security 的官方设计，自己并不感到满意。这段时间比较空，故重新研究了一遍。

项目 GitHub：[https://github.com/Smith-Cruise/Spring-Boot-Security-JWT-SPA](https://github.com/Smith-Cruise/Spring-Boot-Security-JWT-SPA)

老版本：[https://github.com/Smith-Cruise/Spring-Boot-Security-JWT-SPA/blob/master/README_OLD.md](https://github.com/Smith-Cruise/Spring-Boot-Security-JWT-SPA/blob/master/README_OLD.md)

## 特性

* 使用 JWT 进行鉴权，支持 token 过期
* 使用 Ehcache 进行缓存，减少每次鉴权对数据库的压力
* 尽可能贴合 Spring Security 的设计
* 实现注解权限控制

## 准备

开始本教程的时候希望对下面知识点进行粗略的了解。

*  知道 JWT 的基本概念
* 了解过 Spring Security

我之前写过两篇关于安全框架的问题，大家可以大致看一看，打下基础。

 [Shiro+JWT+Spring Boot Restful简易教程](https://github.com/Smith-Cruise/Spring-Boot-Shiro "Shiro+JWT+Spring Boot Restful简易教程")

 [Spring Boot+Spring Security+Thymeleaf 简单教程](https://github.com/Smith-Cruise/Spring-Boot-Security-Thymeleaf-Demo "Spring Boot+Spring Security+Thymeleaf 简单教程")

本项目中 `JWT` 密钥是使用用户自己的登入密码，这样每一个 `token` 的密钥都不同，相对比较安全。

### 大体思路：

**登入：**

1. POST 用户名密码到 \login
2. 请求到达 `JwtAuthenticationFilter` 中的 `attemptAuthentication()` 方法，获取 request 中的 POST 参数，包装成一个 `UsernamePasswordAuthenticationToken` 交付给 `AuthenticationManager` 的 `authenticate()` 方法进行鉴权。
3. `AuthenticationManager` 会从 `CachingUserDetailsService` 中查找用户信息，并且判断账号密码是否正确。
4. 如果账号密码正确跳转到 `JwtAuthenticationFilter` 中的 `successfulAuthentication()` 方法，我们进行签名，生成 token 返回给用户。
5. 账号密码错误则跳转到 `JwtAuthenticationFilter` 中的 `unsuccessfulAuthentication()` 方法，我们返回错误信息让用户重新登入。

**请求鉴权：**

请求鉴权的主要思路是我们会从请求中的 Authorization 字段拿取 token，如果不存在此字段的用户，Spring Security 会默认会用 `AnonymousAuthenticationToken()` 包装它，即代表匿名用户。

1. 任意请求发起
2. 到达 `JwtAuthorizationFilter` 中的 `doFilterInternal()` 方法，进行鉴权。
3. 如果鉴权成功我们把生成的 `Authentication` 用 `SecurityContextHolder.getContext().setAuthentication()` 放入 Security，即代表鉴权完成。此处如何鉴权由我们自己代码编写，后序会详细说明。


## 准备 pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.1.7.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>org.inlighting</groupId>
    <artifactId>spring-boot-security-jwt</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>spring-boot-security-jwt</name>
    <description>Demo project for Spring Boot</description>

    <properties>
        <java.version>1.8</java.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <!-- JWT 支持 -->
        <dependency>
            <groupId>com.auth0</groupId>
            <artifactId>java-jwt</artifactId>
            <version>3.8.2</version>
        </dependency>

        <!-- cache 支持 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-cache</artifactId>
        </dependency>

        <!-- cache 支持 -->
        <dependency>
            <groupId>org.ehcache</groupId>
            <artifactId>ehcache</artifactId>
        </dependency>

        <!-- cache 支持 -->
        <dependency>
            <groupId>javax.cache</groupId>
            <artifactId>cache-api</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!-- ehcache 读取 xml 配置文件使用 -->
        <dependency>
            <groupId>javax.xml.bind</groupId>
            <artifactId>jaxb-api</artifactId>
            <version>2.3.0</version>
        </dependency>

        <!-- ehcache 读取 xml 配置文件使用 -->
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-impl</artifactId>
            <version>2.3.0</version>
        </dependency>

        <!-- ehcache 读取 xml 配置文件使用 -->
        <dependency>
            <groupId>com.sun.xml.bind</groupId>
            <artifactId>jaxb-core</artifactId>
            <version>2.3.0</version>
        </dependency>

        <!-- ehcache 读取 xml 配置文件使用 -->
        <dependency>
            <groupId>javax.activation</groupId>
            <artifactId>activation</artifactId>
            <version>1.1.1</version>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>

```

pom.xml 配置文件这块没有什么好说的，主要说明下面的几个依赖：

```xml
<!-- ehcache 读取 xml 配置文件使用 -->
<dependency>
  <groupId>javax.xml.bind</groupId>
  <artifactId>jaxb-api</artifactId>
  <version>2.3.0</version>
</dependency>

<!-- ehcache 读取 xml 配置文件使用 -->
<dependency>
  <groupId>com.sun.xml.bind</groupId>
  <artifactId>jaxb-impl</artifactId>
  <version>2.3.0</version>
</dependency>

<!-- ehcache 读取 xml 配置文件使用 -->
<dependency>
  <groupId>com.sun.xml.bind</groupId>
  <artifactId>jaxb-core</artifactId>
  <version>2.3.0</version>
</dependency>

<!-- ehcache 读取 xml 配置文件使用 -->
<dependency>
  <groupId>javax.activation</groupId>
  <artifactId>activation</artifactId>
  <version>1.1.1</version>
</dependency>
```

因为 ehcache 读取 xml 配置文件时使用了这几个依赖，而这几个依赖从 JDK 9 开始时是选配模块，所以高版本的用户需要添加这几个依赖才能正常使用。

## 基础工作准备

接下来准备下几个基础工作，就是新建个实体、模拟个数据库，写个 JWT 工具类这种基础操作。

### UserEntity.java

关于 role 为什么使用 GrantedAuthority 说明下：其实是为了简化代码，直接用了 Security 现成的 role 类，实际项目中我们肯定要自己进行处理，将其转换为 Security 的 role 类。

```java
public class UserEntity {

    public UserEntity(String username, String password, Collection<? extends GrantedAuthority> role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    private String username;

    private String password;

    private Collection<? extends GrantedAuthority> role;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Collection<? extends GrantedAuthority> getRole() {
        return role;
    }

    public void setRole(Collection<? extends GrantedAuthority> role) {
        this.role = role;
    }
}
```

### ResponseEntity.java

前后端分离为了方便前端我们要统一 json 的返回格式，所以自定义一个 ResponseEntity.java。

```java
public class ResponseEntity {

    public ResponseEntity() {
    }

    public ResponseEntity(int status, String msg, Object data) {
        this.status = status;
        this.msg = msg;
        this.data = data;
    }

    private int status;

    private String msg;

    private Object data;

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public Object getData() {
        return data;
    }

    public void setData(Object data) {
        this.data = data;
    }
}
```

### Database.java

这里我们使用一个 HashMap 模拟了一个数据库，密码我已经预先用 `Bcrypt` 加密过了，这也是 Spring Security 官方推荐的加密算法（MD5 加密已经在 Spring Security 5 中被移除了，不安全）。

| 用户名 | 密码                      | 权限        |
| ------ | ------------------------- | ----------- |
| jack   | jack123 存 Bcrypt 加密后  | ROLE_USER   |
| danny  | danny123 存 Bcrypt 加密后 | ROLE_EDITOR |
| smith  | smith123 存 Bcrypt 加密后 | ROLE_ADMIN  |

```java
@Component
public class Database {
    private Map<String, UserEntity> data = null;
    
    public Map<String, UserEntity> getDatabase() {
        if (data == null) {
            data = new HashMap<>();

            UserEntity jack = new UserEntity(
                    "jack",
                    "$2a$10$AQol1A.LkxoJ5dEzS5o5E.QG9jD.hncoeCGdVaMQZaiYZ98V/JyRq",
                    getGrants("ROLE_USER"));
            UserEntity danny = new UserEntity(
                    "danny",
                    "$2a$10$8nMJR6r7lvh9H2INtM2vtuA156dHTcQUyU.2Q2OK/7LwMd/I.HM12",
                    getGrants("ROLE_EDITOR"));
            UserEntity smith = new UserEntity(
                    "smith",
                    "$2a$10$E86mKigOx1NeIr7D6CJM3OQnWdaPXOjWe4OoRqDqFgNgowvJW9nAi",
                    getGrants("ROLE_ADMIN"));
            data.put("jack", jack);
            data.put("danny", danny);
            data.put("smith", smith);
        }
        return data;
    }
    
    private Collection<GrantedAuthority> getGrants(String role) {
        return AuthorityUtils.commaSeparatedStringToAuthorityList(role);
    }
}
```

### UserService.java

这里再模拟一个 service，主要就是模仿数据库的操作。

```java
@Service
public class UserService {

    @Autowired
    private Database database;

    public UserEntity getUserByUsername(String username) {
        return database.getDatabase().get(username);
    }
}
```

### JwtUtil.java

自己编写的一个工具类，主要负责 JWT 的签名和鉴权。

```java
public class JwtUtil {

    // 过期时间5分钟
    private final static long EXPIRE_TIME = 5 * 60 * 1000;

    /**
     * 生成签名,5min后过期
     * @param username 用户名
     * @param secret 用户的密码
     * @return 加密的token
     */
    public static String sign(String username, String secret) {
        Date expireDate = new Date(System.currentTimeMillis() + EXPIRE_TIME);
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            return JWT.create()
                    .withClaim("username", username)
                    .withExpiresAt(expireDate)
                    .sign(algorithm);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 校验token是否正确
     * @param token 密钥
     * @param secret 用户的密码
     * @return 是否正确
     */
    public static boolean verify(String token, String username, String secret) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withClaim("username", username)
                    .build();
            DecodedJWT jwt = verifier.verify(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 获得token中的信息无需secret解密也能获得
     * @return token中包含的用户名
     */
    public static String getUsername(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("username").asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }
}
```

## Spring Security 改造

登入这块，我们使用自定义的 `JwtAuthenticationFilter` 来进行登入。

请求鉴权，我们使用自定义的 `JwtAuthorizationFilter` 来处理。

> 也许大家觉得两个单词长的有点像，😜。

### UserDetailsServiceImpl.java

我们首先实现官方的 `UserDetailsService` 接口，这里主要负责一个从数据库拿数据的操作。

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserService userService;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userService.getUserByUsername(username);
        if (userEntity == null) {
            throw new UsernameNotFoundException("This username didn't exist.");
        }
        return new User(userEntity.getUsername(), userEntity.getPassword(), userEntity.getRole());
    }
}
```

后序我们还需要对其进行缓存改造，不然每次请求都要从数据库拿一次数据鉴权，对数据库压力太大了。

### JwtAuthenticationFilter.java

这个过滤器主要处理登入操作，我们继承了 `UsernamePasswordAuthenticationFilter`，这样能大大简化我们的工作量。

```java
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    /*
    过滤器一定要设置 AuthenticationManager，所以此处我们这么编写，这里的 AuthenticationManager
    我会从 Security 配置的时候传入
    */
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        /*
        运行父类 UsernamePasswordAuthenticationFilter 的构造方法，能够设置此滤器指定
        方法为 POST [\login]
        */
        super();
        setAuthenticationManager(authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 从请求的 POST 中拿取 username 和 password 两个字段进行登入
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
        // 设置一些客户 IP 啥信息，后面想用的话可以用，虽然没啥用
        setDetails(request, token);
        // 交给 AuthenticationManager 进行鉴权
        return getAuthenticationManager().authenticate(token);
    }

    /*
    鉴权成功进行的操作，我们这里设置返回加密后的 token
    */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        handleResponse(request, response, authResult, null);
    }

    /*
    鉴权失败进行的操作，我们这里就返回 用户名或密码错误 的信息
    */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        handleResponse(request, response, null, failed);
    }

    private void handleResponse(HttpServletRequest request, HttpServletResponse response, Authentication authResult, AuthenticationException failed) throws IOException, ServletException {
        ObjectMapper mapper = new ObjectMapper();
        ResponseEntity responseEntity = new ResponseEntity();
        response.setHeader("Content-Type", "application/json;charset=UTF-8");
        if (authResult != null) {
            // 处理登入成功请求
            User user = (User) authResult.getPrincipal();
            String token = JwtUtil.sign(user.getUsername(), user.getPassword());
            responseEntity.setStatus(HttpStatus.OK.value());
            responseEntity.setMsg("登入成功");
            responseEntity.setData("Bearer " + token);
            response.setStatus(HttpStatus.OK.value());
            response.getWriter().write(mapper.writeValueAsString(responseEntity));
        } else {
            // 处理登入失败请求
            responseEntity.setStatus(HttpStatus.BAD_REQUEST.value());
            responseEntity.setMsg("用户名或密码错误");
            responseEntity.setData(null);
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            response.getWriter().write(mapper.writeValueAsString(responseEntity));
        }
    }
}
```

> `private void handleResponse()` 此处处理的方法不是很好，我的想法是跳转到控制器中进行处理，但是这样鉴权成功的 token 带不过去，所以先这么写了，有点复杂。

### JwtAuthorizationFilter.java

这个过滤器处理每个请求鉴权，我们选择继承 `BasicAuthenticationFilter` ，考虑到 Basic 认证和 JWT 比较像，就选择了它。

```java
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserDetailsService userDetailsService;

    // 会从 Spring Security 配置文件那里传过来
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserDetailsService userDetailsService) {
        super(authenticationManager);
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 判断是否有 token，并且进行认证
        Authentication token = getAuthentication(request);
        if (token == null) {
            chain.doFilter(request, response);
            return;
        }
        // 认证成功
        SecurityContextHolder.getContext().setAuthentication(token);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || ! header.startsWith("Bearer ")) {
            return null;
        }

        String token = header.split(" ")[1];
        String username = JwtUtil.getUsername(token);
        UserDetails userDetails = null;
        try {
            userDetails = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            return null;
        }
        if (! JwtUtil.verify(token, username, userDetails.getPassword())) {
            return null;
        }
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }
}
```

### SecurityConfiguration.java

此处我们进行 Security 的配置，并且实现缓存功能。缓存这块我们使用官方现成的 `CachingUserDetailsService` ，唯独的缺点就是它没有 public 方法，我们不能正常实例化，需要曲线救国，下面代码也有详细说明。

```java
// 开启 Security
@EnableWebSecurity
// 开启注解配置支持
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    // Spring Boot 的 CacheManager，这里我们使用 JCache
    @Autowired
    private CacheManager cacheManager;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 开启跨域
        http.cors()
                .and()
                // security 默认 csrf 是开启的，我们使用了 token ，这个也没有什么必要了
                .csrf().disable()
                .authorizeRequests()
                // 默认所有请求通过，但是我们要在需要权限的方法加上安全注解，这样比写死配置灵活很多
                .anyRequest().permitAll()
                .and()
                // 添加自己编写的两个过滤器
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), cachingUserDetailsService(userDetailsServiceImpl)))
                // 前后端分离是 STATELESS，故 session 使用该策略
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    // 此处配置 AuthenticationManager，并且实现缓存
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 对自己编写的 UserDetailsServiceImpl 进一步包装，实现缓存
        CachingUserDetailsService cachingUserDetailsService = cachingUserDetailsService(userDetailsServiceImpl);
        // jwt-cache 我们在 ehcache.xml 配置文件中有声明
        UserCache userCache = new SpringCacheBasedUserCache(cacheManager.getCache("jwt-cache"));
        cachingUserDetailsService.setUserCache(userCache);
        /*
        security 默认鉴权完成后会把密码抹除，但是这里我们使用用户的密码来作为 JWT 的生成密钥，
        如果被抹除了，在对 JWT 进行签名的时候就拿不到用户密码了，故此处关闭了自动抹除密码。
         */
        auth.eraseCredentials(false);
        auth.userDetailsService(cachingUserDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
    此处我们实现缓存的时候，我们使用了官方现成的 CachingUserDetailsService ，但是这个类的构造方法不是 public 的，
    我们不能够正常实例化，所以在这里进行曲线救国。
     */
    private CachingUserDetailsService cachingUserDetailsService(UserDetailsServiceImpl delegate) {

        Constructor<CachingUserDetailsService> ctor = null;
        try {
            ctor = CachingUserDetailsService.class.getDeclaredConstructor(UserDetailsService.class);
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
        Assert.notNull(ctor, "CachingUserDetailsService constructor is null");
        ctor.setAccessible(true);
        return BeanUtils.instantiateClass(ctor, delegate);
    }
}
```

### Ehcache 配置

Ehcache 3 开始，统一使用了 JCache，就是  JSR107 标准，网上很多教程都是基于 Ehcache 2 的，所以大家可能在参照网上的教程会遇到很多坑。

> JSR107：emm，其实 JSR107 是一种缓存标准，各个框架只要遵守这个标准，就是现实大一统。差不多就是我不需要更改系统代码，也能随意更换底层的缓存系统。

在 resources 目录下创建 `ehcache.xml` 文件：

```xml
<ehcache:config
        xmlns:ehcache="http://www.ehcache.org/v3"
        xmlns:jcache="http://www.ehcache.org/v3/jsr107">

    <ehcache:cache alias="jwt-cache">
        <!-- 我们使用用户名作为缓存的 key，故使用 String -->
        <ehcache:key-type>java.lang.String</ehcache:key-type>
        <ehcache:value-type>org.springframework.security.core.userdetails.User</ehcache:value-type>
        <ehcache:expiry>
            <ehcache:ttl unit="days">1</ehcache:ttl>
        </ehcache:expiry>
        <!-- 缓存实体的数量 -->
        <ehcache:heap unit="entries">2000</ehcache:heap>
    </ehcache:cache>

</ehcache:config>
```

在 `application.properties` 中开启缓存支持：

```properties
spring.cache.type=jcache
spring.cache.jcache.config=classpath:ehcache.xml
```

### 统一全局异常

我们要把异常的返回形式也统一了，这样才能方便前端的调用。

我们平常会使用 `@RestControllerAdvice` 来统一异常，但是它只能管理 Controller 层面抛出的异常。Security 中抛出的异常不会抵达 Controller，无法被 `@RestControllerAdvice` 捕获，故我们还要改造 `ErrorController` 。

```java
@RestController
public class CustomErrorController implements ErrorController {

    @Override
    public String getErrorPath() {
        return "/error";
    }

    @RequestMapping("/error")
    public ResponseEntity handleError(HttpServletRequest request, HttpServletResponse response) {
        return new ResponseEntity(response.getStatus(), (String) request.getAttribute("javax.servlet.error.message"), null);
    }
}
```

## 测试

写个控制器试试，大家也可以参考我控制器里面获取用户信息的方式，推荐使用 `@AuthenticationPrincipal` 这个注解！！！

```java
@RestController
public class MainController {

    // 任何人都可以访问，在方法中判断用户是否合法
    @GetMapping("everyone")
    public ResponseEntity everyone() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (! (authentication instanceof AnonymousAuthenticationToken)) {
            // 登入用户
            return new ResponseEntity(HttpStatus.OK.value(), "You are already login", authentication.getPrincipal());
        } else {
            return new ResponseEntity(HttpStatus.OK.value(), "You are anonymous", null);
        }
    }

    @GetMapping("user")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity user(@AuthenticationPrincipal UsernamePasswordAuthenticationToken token) {
        return new ResponseEntity(HttpStatus.OK.value(), "You are user", token);
    }

    @GetMapping("admin")
    @IsAdmin
    public ResponseEntity admin(@AuthenticationPrincipal UsernamePasswordAuthenticationToken token) {
        return new ResponseEntity(HttpStatus.OK.value(), "You are admin", token);
    }
}
```

我这里还使用了 `@IsAdmin` 注解，`@IsAdmin` 注解如下：

```java
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@PreAuthorize("hasAnyRole('ROLE_ADMIN')")
public @interface IsAdmin {
}
```

这样能省去每次编写一长串的 `@PreAuthorize()` ，而且更加直观。

## FAQ

### 如何解决JWT过期问题？

我们可以在 `JwtAuthorizationFilter` 中加点料，如果用户快过期了，返回个特别的状态码，前端收到此状态码去访问 `GET /re_authentication` 携带老的 token 重新拿一个新的 token 即可。

### 如何作废已颁发未过期的 token？

我个人的想法是把每次生成的 token 放入缓存中，每次请求都从缓存里拿，如果没有则代表此缓存报废。
