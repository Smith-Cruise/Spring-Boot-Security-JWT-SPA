package org.inlighting.security.service;

import org.inlighting.security.entity.UserEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private Database database;

    public UserEntity getUserByUsername(String username) {
        return database.getDatabase().get(username);
    }
}
