package org.inlighting.security.controller;

import org.inlighting.security.entity.ResponseEntity;
import org.inlighting.security.security.IsAdmin;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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
