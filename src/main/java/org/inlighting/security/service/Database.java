package org.inlighting.security.service;

import org.inlighting.security.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

public class Database {
    private Map<String, UserEntity> data;

    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public Database() {
        data = new HashMap<>();

        UserEntity jack = new UserEntity("jack", getPassword("jack123"), getGrants("ROLE_USER"));
        UserEntity danny = new UserEntity("danny", getPassword("danny123"), getGrants("ROLE_EDITOR"));
        UserEntity alice = new UserEntity("alice", getPassword("alice123"), getGrants("ROLE_REVIEWER"));
        UserEntity smith = new UserEntity("smith", getPassword("smith123"), getGrants("ROLE_ADMIN"));
        data.put("jack", jack);
        data.put("danny", danny);
        data.put("alice", alice);
        data.put("smith", smith);
    }

    public Map<String, UserEntity> getDatabase() {
        return data;
    }

    private String getPassword(String raw) {
        return passwordEncoder.encode(raw);
    }

    private Collection<GrantedAuthority> getGrants(String role) {
        return AuthorityUtils.commaSeparatedStringToAuthorityList(role);
    }
}
