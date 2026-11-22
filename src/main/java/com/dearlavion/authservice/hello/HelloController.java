package com.dearlavion.authservice.hello;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Smoke-test endpoint. The homelab deploy calls it right after the container is healthy, to prove
 * a request reaches the freshly deployed service. Public and static on purpose: no tenant header,
 * no token, no database access (that is what {@code /actuator/health} is for).
 */
@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello World";
    }
}
