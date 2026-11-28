package com.dearlavion.authservice;

import org.junit.jupiter.api.BeforeAll;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end verification of the Spring Boot port against a real MongoDB (Testcontainers): SIMPLE
 * register/login/verify, multi-tenant isolation via X-Customer, the provision-secret role gate,
 * and the AdminAuthFilter's 401 (no/bad token) vs 403 (wrong role) distinction. Kafka is disabled
 * for the test run (app.kafka-enabled=false) so it doesn't need a real broker.
 */
@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthServiceIntegrationTest {

    @Container
    static final MongoDBContainer MONGO = new MongoDBContainer("mongo:7");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("spring.data.mongodb.uri", MONGO::getReplicaSetUrl);
        registry.add("app.customers", () -> "acme,other");
        registry.add("app.kafka-enabled", () -> "false");
        registry.add("app.google-enabled", () -> "false");
        registry.add("app.provision-secret", () -> "test-provision-secret");
        registry.add("app.jwt-secret-base64", () -> "NUI2RjdEM0UyQTlDNEI4RTBBMUY2RDlCM0U3QTJDOUQ0RjhFNUI2QzNBN0IxRDZGNEM5QTNFOEQyQjVGN0Ex");
        registry.add("app.jwt-expires-in-seconds", () -> "60");
        registry.add("app.jwt-reset-expires-in-seconds", () -> "30");
    }

    @Autowired
    private TestRestTemplate rest;

    @BeforeAll
    static void noop() {
    }

    private HttpHeaders customerHeaders(String customer) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Customer", customer);
        return headers;
    }

    private void useHttpComponents() {
        rest.getRestTemplate().setRequestFactory(new HttpComponentsClientHttpRequestFactory());
    }

    @Test
    void registerLoginAndVerifyRoundTrip() {
        useHttpComponents();
        Map<String, Object> body = Map.of("username", "alice", "email", "alice@acme.dev", "password", "s3cret!");
        ResponseEntity<Map> registered = rest.exchange("/auth/register", HttpMethod.POST,
                new HttpEntity<>(body, customerHeaders("acme")), Map.class);
        assertThat(registered.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(registered.getBody()).containsEntry("user", "alice");

        ResponseEntity<Map> login = rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "alice", "password", "s3cret!"), customerHeaders("acme")), Map.class);
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = (String) login.getBody().get("token");
        assertThat(token).isNotBlank();
        Map<String, Object> loginUser = (Map<String, Object>) login.getBody().get("user");
        assertThat(loginUser).containsEntry("username", "alice").containsEntry("customer", "acme");

        ResponseEntity<Map> wrongPassword = rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "alice", "password", "wrong"), customerHeaders("acme")), Map.class);
        assertThat(wrongPassword.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<Map> verify = rest.postForEntity("/auth/verify", Map.of("token", token), Map.class);
        assertThat(verify.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(verify.getBody()).containsEntry("valid", true).containsEntry("username", "alice").containsEntry("customer", "acme");

        ResponseEntity<Map> verifyGarbage = rest.postForEntity("/auth/verify", Map.of("token", "not-a-jwt"), Map.class);
        assertThat(verifyGarbage.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(verifyGarbage.getBody()).containsEntry("valid", false);
    }

    @Test
    void multiTenantIsolationSameUsernameDifferentCustomers() {
        useHttpComponents();
        Map<String, Object> acmeBody = Map.of("username", "bob", "email", "bob@acme.dev", "password", "pw-acme");
        Map<String, Object> otherBody = Map.of("username", "bob", "email", "bob@other.dev", "password", "pw-other");

        ResponseEntity<Map> r1 = rest.exchange("/auth/register", HttpMethod.POST, new HttpEntity<>(acmeBody, customerHeaders("acme")), Map.class);
        ResponseEntity<Map> r2 = rest.exchange("/auth/register", HttpMethod.POST, new HttpEntity<>(otherBody, customerHeaders("other")), Map.class);
        assertThat(r1.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(r2.getStatusCode()).isEqualTo(HttpStatus.OK);

        // "bob" logging into "acme" with "other"'s password must fail — separate databases.
        ResponseEntity<Map> crossLogin = rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "bob", "password", "pw-other"), customerHeaders("acme")), Map.class);
        assertThat(crossLogin.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<Map> ownLogin = rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "bob", "password", "pw-acme"), customerHeaders("acme")), Map.class);
        assertThat(ownLogin.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void unknownCustomerIsRejected() {
        useHttpComponents();
        ResponseEntity<Map> res = rest.exchange("/auth/register", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "x", "email", "x@x.dev", "password", "pw"), customerHeaders("not-a-real-tenant")), Map.class);
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void provisionSecretGatesPrivilegedRoleAssignment() {
        useHttpComponents();
        HttpHeaders headersNoSecret = customerHeaders("acme");
        Map<String, Object> body = Map.of("username", "wannabe-admin", "email", "wannabe@acme.dev", "password", "pw", "activeProfile", "ADMIN");
        ResponseEntity<Map> withoutSecret = rest.exchange("/auth/register", HttpMethod.POST, new HttpEntity<>(body, headersNoSecret), Map.class);
        assertThat(withoutSecret.getStatusCode()).isEqualTo(HttpStatus.OK);

        HttpHeaders operator = customerHeaders("acme");
        operator.set("X-Provision-Secret", "test-provision-secret");
        ResponseEntity<Map> got = rest.exchange("/auth/user/wannabe-admin", HttpMethod.GET, new HttpEntity<>(operator), Map.class);
        assertThat(got.getBody()).containsEntry("activeProfile", "USER"); // silently downgraded

        HttpHeaders headersWithSecret = customerHeaders("acme");
        headersWithSecret.set("X-Provision-Secret", "test-provision-secret");
        Map<String, Object> adminBody = Map.of("username", "real-admin", "email", "real-admin@acme.dev", "password", "pw", "activeProfile", "ADMIN");
        rest.exchange("/auth/register", HttpMethod.POST, new HttpEntity<>(adminBody, headersWithSecret), Map.class);
        ResponseEntity<Map> gotAdmin = rest.exchange("/auth/user/real-admin", HttpMethod.GET, new HttpEntity<>(headersWithSecret), Map.class);
        assertThat(gotAdmin.getBody()).containsEntry("activeProfile", "ADMIN");
    }

    @Test
    void adminGuardEnforcesAuthenticationAndRole() {
        useHttpComponents();
        // No token at all -> 401.
        ResponseEntity<Map> noToken = rest.exchange("/admin/users", HttpMethod.GET, HttpEntity.EMPTY, Map.class);
        assertThat(noToken.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // Garbage token -> 401.
        HttpHeaders badAuth = new HttpHeaders();
        badAuth.set("Authorization", "Bearer garbage");
        ResponseEntity<Map> badToken = rest.exchange("/admin/users", HttpMethod.GET, new HttpEntity<>(badAuth), Map.class);
        assertThat(badToken.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        // A real but non-admin (USER) token -> 403.
        HttpHeaders headersWithSecret = customerHeaders("acme");
        headersWithSecret.set("X-Provision-Secret", "test-provision-secret");
        rest.exchange("/auth/register", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "plain-user", "email", "plain@acme.dev", "password", "pw"), headersWithSecret), Map.class);
        ResponseEntity<Map> loginPlain = rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "plain-user", "password", "pw"), customerHeaders("acme")), Map.class);
        String plainToken = (String) loginPlain.getBody().get("token");
        HttpHeaders plainAuth = new HttpHeaders();
        plainAuth.set("Authorization", "Bearer " + plainToken);
        ResponseEntity<Map> forbidden = rest.exchange("/admin/users", HttpMethod.GET, new HttpEntity<>(plainAuth), Map.class);
        assertThat(forbidden.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        // A real ADMIN token -> 200, and the list is scoped to their own tenant.
        rest.exchange("/auth/register", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "guard-admin", "email", "guard-admin@acme.dev", "password", "pw", "activeProfile", "ADMIN"), headersWithSecret), Map.class);
        ResponseEntity<Map> loginAdmin = rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "guard-admin", "password", "pw"), customerHeaders("acme")), Map.class);
        String adminToken = (String) loginAdmin.getBody().get("token");
        HttpHeaders adminAuth = new HttpHeaders();
        adminAuth.set("Authorization", "Bearer " + adminToken);
        ResponseEntity<List> list = rest.exchange("/admin/users", HttpMethod.GET, new HttpEntity<>(adminAuth), List.class);
        assertThat(list.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(list.getBody()).isNotEmpty();
    }

    @Test
    void softDeleteBlocksLogin() {
        useHttpComponents();
        HttpHeaders headersWithSecret = customerHeaders("acme");
        headersWithSecret.set("X-Provision-Secret", "test-provision-secret");
        rest.exchange("/auth/register", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "deactivate-me", "email", "deactivate@acme.dev", "password", "pw", "activeProfile", "ADMIN"), headersWithSecret), Map.class);
        ResponseEntity<Map> adminLogin = rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "deactivate-me", "password", "pw"), customerHeaders("acme")), Map.class);
        String token = (String) adminLogin.getBody().get("token");
        HttpHeaders adminAuth = new HttpHeaders();
        adminAuth.set("Authorization", "Bearer " + token);

        rest.exchange("/admin/users/deactivate-me/active", HttpMethod.PATCH,
                new HttpEntity<>(Map.of("active", false), adminAuth), Map.class);

        ResponseEntity<Map> loginAfterDeactivate = rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", "deactivate-me", "password", "pw"), customerHeaders("acme")), Map.class);
        assertThat(loginAfterDeactivate.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void forgotPasswordIsSilentOnUnknownEmail() {
        useHttpComponents();
        ResponseEntity<Map> res = rest.exchange("/auth/forgot-password?email=nobody@acme.dev", HttpMethod.POST,
                new HttpEntity<>(customerHeaders("acme")), Map.class);
        assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
