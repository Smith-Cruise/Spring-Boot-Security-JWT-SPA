package org.inlighting.spa.controller;

import org.inlighting.spa.ResponseBean;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
public class CustomErrorController extends AbstractErrorController {

    private final String PATH = "/error";


    public CustomErrorController(ErrorAttributes errorAttributes) {
        super(errorAttributes);
    }

    @RequestMapping("/error")
    public ResponseEntity<ResponseBean> error(HttpServletRequest request) {
        Map<String, Object> attributes = getErrorAttributes(request, true);
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
