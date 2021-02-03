package com.security.oauth.authserver;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;


@RestController
public class TestResource {
    
    @GetMapping("/user/me")
    public Principal user(Principal principal) {
        return principal;
    }
    
}