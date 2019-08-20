package org.inlighting.security.entity;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UserEntity {

    public UserEntity(String username, String password, Collection<? extends GrantedAuthority> role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    private String username;

    private String password;

    private Collection<? extends GrantedAuthority> role;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Collection<? extends GrantedAuthority> getRole() {
        return role;
    }

    public void setRole(Collection<? extends GrantedAuthority> role) {
        this.role = role;
    }
}
