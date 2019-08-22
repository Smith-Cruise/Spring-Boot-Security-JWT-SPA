package org.inlighting.security.controller;

import org.inlighting.security.entity.ResponseEntity;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
