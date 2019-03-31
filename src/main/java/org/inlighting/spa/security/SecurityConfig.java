package org.inlighting.spa.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
