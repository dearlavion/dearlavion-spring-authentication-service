package com.dearlavion.authservice;

import com.dearlavion.authservice.security.JwtTokenService;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/** Who may read or change an account through /auth/user/{username}, against an embedded mongod (no Docker needed). */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.autoconfigure.exclude=",
                "spring.data.mongodb.uri=mongodb://localhost:27017/user-route-test",
                "de.flapdoodle.mongodb.embedded.version=7.0.14",
                "app.customers=acme,other,security",
                "app.security-tenant=security",
                "app.kafka-enabled=false",
                "app.google-enabled=false",
                "app.provision-secret=test-provision-secret",
                "app.service-key=test-service-key",
                "app.jwt-secret-base64=NUI2RjdEM0UyQTlDNEI4RTBBMUY2RDlCM0U3QTJDOUQ0RjhFNUI2QzNBN0IxRDZGNEM5QTNFOEQyQjVGN0Ex",
                "app.jwt-expires-in-seconds=60",
                "app.jwt-reset-expires-in-seconds=30",
        })
class UserRouteAccessTest {

    @Autowired private TestRestTemplate rest;
    @Autowired private JwtTokenService jwt;

    @BeforeEach
    void plainHttpClient() {
        rest.getRestTemplate().setRequestFactory(
                new HttpComponentsClientHttpRequestFactory(HttpClients.custom().disableCookieManagement().build()));
    }

    private static HttpHeaders headers(String customer, String... pair) {
        HttpHeaders h = new HttpHeaders();
        h.set("X-Customer", customer);
        if (pair.length == 2) h.set(pair[0], pair[1]);
        return h;
    }

    private static HttpHeaders bearer(String customer, String token) {
        return headers(customer, HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }

    private String register(String customer) {
        String name = "u" + UUID.randomUUID().toString().substring(0, 8);
        assertThat(rest.exchange("/auth/register", HttpMethod.POST, new HttpEntity<>(
                Map.of("username", name, "email", name + "@x.test", "password", "pass-word-1"), headers(customer)), Map.class)
                .getStatusCode()).isEqualTo(HttpStatus.OK);
        return name;
    }

    private String login(String customer, String name) {
        return (String) rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", name, "password", "pass-word-1"), headers(customer)), Map.class)
                .getBody().get("token");
    }

    private ResponseEntity<Map> get(String name, HttpHeaders h) {
        return rest.exchange("/auth/user/" + name, HttpMethod.GET, new HttpEntity<>(h), Map.class);
    }

    private HttpStatus patch(String name, HttpHeaders h, Map<String, String> body) {
        return (HttpStatus) rest.exchange("/auth/user/" + name, HttpMethod.PATCH, new HttpEntity<>(body, h), Map.class).getStatusCode();
    }

    private String emailOf(String name) {
        return (String) get(name, headers("acme", "X-Service-Key", "test-service-key")).getBody().get("email");
    }

    @Test
    void callsWithoutAValidCredentialAreRefusedAndChangeNothing() {
        String name = register("acme");
        for (HttpHeaders h : new HttpHeaders[]{
                headers("acme"),
                headers("acme", "X-Service-Key", "wrong"),
                headers("acme", "X-Provision-Secret", "wrong"),
                bearer("acme", "garbage"),
                bearer("acme", jwt.generatePasswordResetToken(name, "acme"))}) {
            assertThat(get(name, h).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(patch(name, h, Map.of("email", "attacker@evil.test"))).isEqualTo(HttpStatus.UNAUTHORIZED);
        }
        assertThat(emailOf(name)).isEqualTo(name + "@x.test");
    }

    @Test
    void anotherUsersOrAnotherTenantsTokenIsForbidden() {
        String victim = register("acme");
        String intruder = register("acme");
        String token = login("acme", intruder);
        assertThat(get(victim, bearer("acme", token)).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(patch(victim, bearer("acme", token), Map.of("email", "attacker@evil.test"))).isEqualTo(HttpStatus.FORBIDDEN);
        // Same token, pointed at another tenant.
        assertThat(get(intruder, bearer("other", token)).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(emailOf(victim)).isEqualTo(victim + "@x.test");
    }

    @Test
    void theUserThemselvesAndBothSecretsAreAllowed() {
        String name = register("acme");
        String token = login("acme", name);
        assertThat(get(name, bearer("acme", token)).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(patch(name, bearer("acme", token), Map.of("email", "mine@x.test"))).isEqualTo(HttpStatus.OK);
        // A v1/v2-style token, without uid.
        assertThat(get(name, bearer("acme", jwt.generateToken(name, "acme"))).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(patch(name, headers("acme", "X-Service-Key", "test-service-key"), Map.of("email", "svc@x.test"))).isEqualTo(HttpStatus.OK);
        assertThat(patch(name, headers("acme", "X-Provision-Secret", "test-provision-secret"), Map.of("email", "ops@x.test"))).isEqualTo(HttpStatus.OK);
        assertThat(emailOf(name)).isEqualTo("ops@x.test");
    }

    @Test
    void neitherOwnLoginNorTheServiceKeyCanPromoteAUser() {
        String name = register("acme");
        patch(name, bearer("acme", login("acme", name)), Map.of("activeProfile", "ADMIN"));
        patch(name, headers("acme", "X-Service-Key", "test-service-key"), Map.of("activeProfile", "ADMIN"));
        assertThat(get(name, headers("acme", "X-Service-Key", "test-service-key")).getBody()).containsEntry("activeProfile", "USER");
    }

    @Test
    void aSuperadminCanOnlyBeChangedWithTheProvisionSecret() {
        String name = register("security");
        String token = login("security", name);
        assertThat(patch(name, bearer("security", token), Map.of("email", "a@evil.test"))).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(patch(name, headers("security", "X-Service-Key", "test-service-key"), Map.of("email", "a@evil.test")))
                .isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(patch(name, headers("security", "X-Provision-Secret", "test-provision-secret"), Map.of("email", "ok@x.test")))
                .isEqualTo(HttpStatus.OK);
    }
}
