package org.inlighting.spa.controller;

import org.inlighting.spa.ResponseBean;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

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
