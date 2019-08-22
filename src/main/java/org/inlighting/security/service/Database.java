package org.inlighting.security.service;

import org.inlighting.security.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

@Component
public class Database {
    private Map<String, UserEntity> data = null;

    public Map<String, UserEntity> getDatabase() {
        if (data == null) {
            data = new HashMap<>();

            UserEntity jack = new UserEntity(
                    "jack",
                    "$2a$10$AQol1A.LkxoJ5dEzS5o5E.QG9jD.hncoeCGdVaMQZaiYZ98V/JyRq",
                    getGrants("ROLE_USER"));
            UserEntity danny = new UserEntity(
                    "danny",
                    "$2a$10$8nMJR6r7lvh9H2INtM2vtuA156dHTcQUyU.2Q2OK/7LwMd/I.HM12",
                    getGrants("ROLE_EDITOR"));
            UserEntity smith = new UserEntity(
                    "smith",
                    "$2a$10$E86mKigOx1NeIr7D6CJM3OQnWdaPXOjWe4OoRqDqFgNgowvJW9nAi",
                    getGrants("ROLE_ADMIN"));
            data.put("jack", jack);
            data.put("danny", danny);
            data.put("smith", smith);
        }
        return data;
    }

    private Collection<GrantedAuthority> getGrants(String role) {
        return AuthorityUtils.commaSeparatedStringToAuthorityList(role);
    }
}
