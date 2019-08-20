package org.inlighting.security.service;

import org.inlighting.security.entity.UserEntity;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private Database database = new Database();

    public UserEntity getUserByUsername(String username) {
        return database.getDatabase().get(username);
    }
}
