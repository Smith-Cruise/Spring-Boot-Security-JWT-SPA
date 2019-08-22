package org.inlighting.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class Main {


    public static void main(String[] args) {

        try {
            BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
            System.out.println(encoder.encode("smith123"));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
