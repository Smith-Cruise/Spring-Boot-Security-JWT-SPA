package org.inlighting.spa.security;

import org.inlighting.spa.JWTUtil;
import org.inlighting.spa.datasource.UserEntity;
import org.inlighting.spa.datasource.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

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
