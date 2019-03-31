package org.inlighting.spa.datasource;

import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UserService {
    public UserEntity getUser(String username) {
        // 没有此用户直接返回null
        if (! Database.getData().containsKey(username))
            return null;

        UserEntity user = new UserEntity();
        Map<String, String> detail = Database.getData().get(username);

        user.setUsername(username);
        user.setPassword(detail.get("password"));
        user.setRole(detail.get("role"));
        return user;
    }
}
