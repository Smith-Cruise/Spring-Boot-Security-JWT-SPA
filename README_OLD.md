# Spring Boot 2 + Spring Security 5 + JWT 的单页应用Restful解决方案-过时

## 准备

项目GitHub：[https://github.com/Smith-Cruise/Spring-Boot-Security-JWT-SPA](https://github.com/Smith-Cruise/Spring-Boot-Security-JWT-SPA)

 我之前写过两篇关于安全框架的问题，大家可以大致看一看，打下基础。

 [Shiro+JWT+Spring Boot Restful简易教程](https://github.com/Smith-Cruise/Spring-Boot-Shiro "Shiro+JWT+Spring Boot Restful简易教程")

 [Spring Boot+Spring Security+Thymeleaf 简单教程](https://github.com/Smith-Cruise/Spring-Boot-Security-Thymeleaf-Demo "Spring Boot+Spring Security+Thymeleaf 简单教程")

在开始前你至少需要了解 `Spring Security` 的基本配置和 `JWT` 机制。

一些关于 `Maven` 的配置和 `Controller` 的编写这里就不说了，自己看下源码即可。

本项目中 `JWT` 密钥是使用用户自己的登入密码，这样每一个 `token` 的密钥都不同，相对比较安全。

## 改造思路

平常我们使用 `Spring Security` 会用到 `UsernamePasswordAuthenticationFilter` 和 `UsernamePasswordAuthenticationToken` 这两个类，但这两个类初衷是为了解决表单登入，对 `JWT` 这类 `Token` 鉴权的方式并不是很友好。所以我们要开发属于自己的 `Filter` 和 `AuthenticationToken` 来替换掉  `Spring Security` 自带的类。

同时默认的 `Spring Security` 鉴定用户是使用了 `ProviderManager` 这个类进行判断，同时 `ProviderManager` 会调用 `AuthenticationUserDetailsService` 这个接口中的 `UserDetails loadUserDetails(T token) throws UsernameNotFoundException` 来从数据库中获取用户信息（这个方法需要用户自己继承实现）。因为考虑到自带的实现方式并不能很好的支持JWT，例如 `UsernamePasswordAuthenticationToken`  中有 `username` 和 `password` 字段进行赋值，但是 `JWT` 是附带在请求的 `header` 中，只有一个 token ，何来 `username` 和 `password` 这种说法。

所以我对其进行了大换血，例如获取用户的方法并没有在 `AuthenticationUserDetailsService`  中实现，但这样就可能不能完美的遵守 `Spring Security` 的官方设计，如果有更好的方法请指正。

## 改造

### 改造 `Authentication`

`Authentication` 是 `Security` 官方提供的一个接口，是保存在 `SecurityContextHolder` 供调用鉴权使用的核心。

这里主要说下三个方法

`getCredentials()` 原本是用于获取密码，现我们打算用其存放前端传递过来的 `token`

`getPrincipal()` 原本用于存放用户信息，现在我们继续保留。比如存储一些用户的 `username`，`id` 等关键信息供 `Controller` 中使用

`getDetails()` 原本返回一些客户端 `IP` 等杂项，但是考虑到这里基本都是  `restful` 这类无状态请求，这个就显的无关紧要 ，所以就被阉割了:happy:

**默认提供的Authentication接口**

```java
public interface Authentication extends Principal, Serializable {

	Collection<? extends GrantedAuthority> getAuthorities();

	Object getCredentials();

	Object getDetails();

	Object getPrincipal();

	boolean isAuthenticated();

	void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
}
```

**JWTAuthenticationToken**

我们编写属于自己的 `Authentication` ，注意**两个构造方法的不同**。 `AbstractAuthenticationToken` 是官方实现 `Authentication` 的一个类。

```java
public class JWTAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private final Object principal;
    private final Object credentials;

    /**
     * 鉴定token前使用的方法，因为还没有鉴定token是否合法，所以要setAuthenticated(false)
     * @param token JWT密钥
     */
    public JWTAuthenticationToken(String token) {
        super(null);
        this.principal = null;
        this.credentials = token;
        setAuthenticated(false);
    }

    /**
     * 鉴定成功后调用的方法，返回的JWTAuthenticationToken供Controller里面调用。
     * 因为已经鉴定成功，所以要setAuthenticated(true)
     * @param token JWT密钥
     * @param userInfo 一些用户的信息，比如username, id等
     * @param authorities 所拥有的权限
     */
    public JWTAuthenticationToken(String token, Object userInfo, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = userInfo;
        this.credentials = token;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
```

### 改造 AuthenticationManager

用于判断用户 `token` 是否合法

**JWTAuthenticationManager**

```java
@Component
public class JWTAuthenticationManager implements AuthenticationManager {

    @Autowired
    private UserService userService;

    /**
     * 进行token鉴定
     * @param authentication 待鉴定的JWTAuthenticationToken
     * @return 鉴定完成的JWTAuthenticationToken，供Controller使用
     * @throws AuthenticationException 如果鉴定失败，抛出
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = authentication.getCredentials().toString();
        String username = JWTUtil.getUsername(token);

        UserEntity userEntity = userService.getUser(username);
        if (userEntity == null) {
            throw new UsernameNotFoundException("该用户不存在");
        }

        /*
         * 官方推荐在本方法中必须要处理三种异常，
         * DisabledException、LockedException、BadCredentialsException
         * 这里为了方便就只处理了BadCredentialsException，大家可以根据自己业务的需要进行定制
         * 详情看AuthenticationManager的JavaDoc
         */
        boolean isAuthenticatedSuccess = JWTUtil.verify(token, username, userEntity.getPassword());
        if (! isAuthenticatedSuccess) {
            throw new BadCredentialsException("用户名或密码错误");
        }

        JWTAuthenticationToken authenticatedAuth = new JWTAuthenticationToken(
                token, userEntity, AuthorityUtils.commaSeparatedStringToAuthorityList(userEntity.getRole())
        );
        return authenticatedAuth;
    }
}
```

### 开发属于自己的 Filter

接下来我们要使用属于自己的过滤器，考虑到 `token` 是附加在 `header` 中，这和 `BasicAuthentication` 认证很像，所以我们继承 `BasicAuthenticationFilter`  进行重写核心方法改造。

**JWTAuthenticationFilter**

```java
public class JWTAuthenticationFilter extends BasicAuthenticationFilter {

    /**
     * 使用我们自己开发的JWTAuthenticationManager
     * @param authenticationManager 我们自己开发的JWTAuthenticationManager
     */
    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader("Authorization");
        if (header == null || !header.toLowerCase().startsWith("bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String token = header.split(" ")[1];
            JWTAuthenticationToken JWToken = new JWTAuthenticationToken(token);
            // 鉴定权限，如果鉴定失败，AuthenticationManager会抛出异常被我们捕获
            Authentication authResult = getAuthenticationManager().authenticate(JWToken);
            // 将鉴定成功后的Authentication写入SecurityContextHolder中供后序使用
            SecurityContextHolder.getContext().setAuthentication(authResult);
        } catch (AuthenticationException failed) {
            SecurityContextHolder.clearContext();
            // 返回鉴权失败
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, failed.getMessage());
            return;
        }
        chain.doFilter(request, response);
    }
}
```

### 配置

**SecurityConfig**

```java
// 开启方法注解功能
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JWTAuthenticationManager jwtAuthenticationManager;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // restful具有先天的防范csrf攻击，所以关闭这功能
        http.csrf().disable()
                // 默认允许所有的请求通过，后序我们通过方法注解的方式来粒度化控制权限
                .authorizeRequests().anyRequest().permitAll()
                .and()
                // 添加属于我们自己的过滤器，注意因为我们没有开启formLogin()，所以UsernamePasswordAuthenticationFilter根本不会被调用
                .addFilterAt(new JWTAuthenticationFilter(jwtAuthenticationManager), UsernamePasswordAuthenticationFilter.class)
                // 前后端分离本身就是无状态的，所以我们不需要cookie和session这类东西。所有的信息都保存在一个token之中。
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

}
```

关于**方法注解鉴权** 这块有很多奇淫巧技，可以看看 [Spring Boot+Spring Security+Thymeleaf 简单教程](https://github.com/Smith-Cruise/Spring-Boot-Security-Thymeleaf-Demo#spring-security-%E9%85%8D%E7%BD%AE "Spring Boot+Spring Security+Thymeleaf 简单教程") 这篇文章

## 统一全局异常

一个 `restful` 最后的异常抛出肯定是要格式统一的，这样才方便前端的调用。

我们平常会使用 `RestControllerAdvice` 来统一异常，但是他只能管理我们自己抛出的异常，而管不住框架本身的异常，比如404啥的，所以我们还要改造 `ErrorController`

**ExceptionController**

```java
@RestControllerAdvice
public class ExceptionController {

    // 捕捉控制器里面自己抛出的所有异常
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseBean> globalException(Exception ex) {
        return new ResponseEntity<>(
                new ResponseBean(
                        HttpStatus.INTERNAL_SERVER_ERROR.value(), ex.getMessage(), null), HttpStatus.INTERNAL_SERVER_ERROR
        );
    }
}
```

**CustomErrorController**

如果直接去实现 `ErrorController` 这个接口，有很多现成方法都没有，不好用，所以我们选择 `AbstractErrorController`

```java
@RestController
public class CustomErrorController extends AbstractErrorController {

    // 异常路径网址
    private final String PATH = "/error";

    public CustomErrorController(ErrorAttributes errorAttributes) {
        super(errorAttributes);
    }

    @RequestMapping("/error")
    public ResponseEntity<ResponseBean> error(HttpServletRequest request) {
        // 获取request中的异常信息，里面有好多，比如时间、路径啥的，大家可以自行遍历map查看
        Map<String, Object> attributes = getErrorAttributes(request, true);
        // 这里只选择返回message字段
        return new ResponseEntity<>(
                new ResponseBean(
                       getStatus(request).value() , (String) attributes.get("message"), null), getStatus(request)
        );
    }

    @Override
    public String getErrorPath() {
        return PATH;
    }
}
```

## 测试

写个控制器试试，大家也可以参考我控制器里面获取用户信息的方式，推荐使用 `@AuthenticationPrincipal` 这个方法！！！

```java
@RestController
public class MainController {

    @Autowired
    private UserService userService;

    // 登入，获取token
    @PostMapping("login")
    public ResponseEntity<ResponseBean> login(@RequestParam String username, @RequestParam String password) {
        UserEntity userEntity = userService.getUser(username);
        if (userEntity==null || !userEntity.getPassword().equals(password)) {
            return new ResponseEntity<>(new ResponseBean(HttpStatus.BAD_REQUEST.value(), "login fail", null), HttpStatus.BAD_REQUEST);
        }

        // JWT签名
        String token = JWTUtil.sign(username, password);
        return new ResponseEntity<>(new ResponseBean(HttpStatus.OK.value(), "login success", token), HttpStatus.OK);
    }

    // 任何人都可以访问，在方法中判断用户是否合法
    @GetMapping("everyone")
    public ResponseEntity<ResponseBean> everyone() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication.isAuthenticated()) {
            // 登入用户
            return new ResponseEntity<>(new ResponseBean(HttpStatus.OK.value(), "You are already login", authentication.getPrincipal()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(new ResponseBean(HttpStatus.OK.value(), "You are anonymous", null), HttpStatus.OK);
        }
    }
    
    @GetMapping("user")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ResponseEntity<ResponseBean> user(@AuthenticationPrincipal UserEntity userEntity) {
        return new ResponseEntity<>(new ResponseBean(HttpStatus.OK.value(), "You are user", userEntity), HttpStatus.OK);
    }

    @GetMapping("admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<ResponseBean> admin(@AuthenticationPrincipal UserEntity userEntity) {
        return new ResponseEntity<>(new ResponseBean(HttpStatus.OK.value(), "You are admin", userEntity), HttpStatus.OK);
    }

}
```



## 其他

这里简单解答下一些常见问题。
### 鉴定Token是否合法是每次请求数据库过于耗费资源

我们不可能每一次鉴定都去数据库拿一次数据来判断 `token` 是否合法，这样非常浪费资源还影响效率。

我们可以在 `JWTAuthenticationManager` 使用缓存。

当用户第一次访问，我们查询数据库判断 `token` 是否合法，如果合法将其放入缓存（缓存过期时间和token过期时间一致），此后每个请求先去缓存中寻找，如果存在则跳过请求数据库环节，直接当做该 `token` 合法。

### 如何解决JWT过期问题

在 `JWTAuthenticationManager` 中编写方法，当 `token` 即将过期时抛出一个特定的异常，例如 `ReAuthenticateException`，然后我们在 `JWTAuthenticationFilter` 中单独捕获这个异常，返回一个特定的 `http` 状态码，然后前端去单独另外访问 `GET /re_authentication` 获取一个新的token来替代掉原本的，同时从缓存中删除老的 `token`。