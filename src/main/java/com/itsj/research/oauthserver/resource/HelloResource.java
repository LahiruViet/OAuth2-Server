package com.itsj.research.oauthserver.resource;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HelloResource {

    @GetMapping("/user/me")
    public Principal user(Principal principal) {
        return principal;
    }

}
