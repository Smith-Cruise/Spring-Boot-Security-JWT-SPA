package org.inlighting.spa.controller;

import org.inlighting.spa.JWTUtil;
import org.inlighting.spa.ResponseBean;
import org.inlighting.spa.datasource.UserEntity;
import org.inlighting.spa.datasource.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

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
