package org.inlighting.spa.controller;

import org.inlighting.spa.ResponseBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;


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
