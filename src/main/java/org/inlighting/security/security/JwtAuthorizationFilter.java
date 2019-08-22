package org.inlighting.security.security;

import org.inlighting.security.util.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
