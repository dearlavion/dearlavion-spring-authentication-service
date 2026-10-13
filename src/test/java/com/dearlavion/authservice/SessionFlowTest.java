package com.dearlavion.authservice;

import com.dearlavion.authservice.security.JwtTokenService;
import com.dearlavion.authservice.user.UserService;
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

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cookie sessions, the caller's own profile and the id lookup, against an embedded mongod (no Docker needed).
 * Each test registers its own uniquely named users, so tests don't depend on each other.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.autoconfigure.exclude=",
                "spring.data.mongodb.uri=mongodb://localhost:27017/session-flow-test",
                "de.flapdoodle.mongodb.embedded.version=7.0.14",
                "app.customers=acme,other",
                "app.kafka-enabled=false",
                "app.google-enabled=false",
                "app.provision-secret=test-provision-secret",
                "app.jwt-secret-base64=NUI2RjdEM0UyQTlDNEI4RTBBMUY2RDlCM0U3QTJDOUQ0RjhFNUI2QzNBN0IxRDZGNEM5QTNFOEQyQjVGN0Ex",
                "app.jwt-expires-in-seconds=60",
                "app.jwt-reset-expires-in-seconds=30",
                "app.session-cookie-path=/api/v1/auth",
        })
class SessionFlowTest {

    private static final String COOKIE = "dl_refresh";

    @Autowired private TestRestTemplate rest;
    @Autowired private JwtTokenService jwt;
    @Autowired private UserService users;

    @BeforeEach
    void plainHttpClient() {
        // PATCH needs the Apache client; cookie management is off so the tests control the Cookie header.
        rest.getRestTemplate().setRequestFactory(
                new HttpComponentsClientHttpRequestFactory(HttpClients.custom().disableCookieManagement().build()));
    }

    private static String unique(String prefix) {
        return prefix + UUID.randomUUID().toString().substring(0, 8);
    }

    private HttpHeaders headers(String customer, String bearer, String cookie) {
        HttpHeaders h = new HttpHeaders();
        if (customer != null) h.set("X-Customer", customer);
        if (bearer != null) h.setBearerAuth(bearer);
        if (cookie != null) h.set(HttpHeaders.COOKIE, COOKIE + "=" + cookie);
        return h;
    }

    /**
     * Registers a user, then sets the display name through the profile endpoint: POST /auth/register has
     * never stored firstname/lastname (UserMapper.toEntity skips them), and that is left as is for existing clients.
     */
    private void register(String customer, String username, String firstname) {
        Map<String, Object> body = Map.of("username", username, "email", username + "@" + customer + ".dev", "password", "s3cret!pw");
        ResponseEntity<Map> r = rest.exchange("/auth/register", HttpMethod.POST, new HttpEntity<>(body, headers(customer, null, null)), Map.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = (String) sessionLogin(customer, username, "s3cret!pw").getBody().get("token");
        ResponseEntity<Map> named = rest.exchange("/auth/me/profile", HttpMethod.PATCH,
                new HttpEntity<>(Map.of("firstname", firstname), headers(null, token, null)), Map.class);
        assertThat(named.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private ResponseEntity<Map> sessionLogin(String customer, String username, String password) {
        return rest.exchange("/auth/session/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", username, "password", password), headers(customer, null, null)), Map.class);
    }

    private static String cookieValue(ResponseEntity<?> r) {
        List<String> all = r.getHeaders().get(HttpHeaders.SET_COOKIE);
        assertThat(all).isNotNull();
        String line = all.stream().filter(c -> c.startsWith(COOKIE + "=")).findFirst().orElseThrow();
        return line.substring((COOKIE + "=").length(), line.indexOf(';') < 0 ? line.length() : line.indexOf(';'));
    }

    private ResponseEntity<Map> refresh(String customer, String cookie) {
        return rest.exchange("/auth/session/refresh", HttpMethod.POST, new HttpEntity<>(headers(customer, null, cookie)), Map.class);
    }

    private ResponseEntity<Map> me(String bearer) {
        return rest.exchange("/auth/me", HttpMethod.GET, new HttpEntity<>(headers(null, bearer, null)), Map.class);
    }

    @Test
    void loginSetsAHardenedCookieAndMeReturnsTheProfile() {
        String name = unique("alice");
        register("acme", name, "Alice A.");

        ResponseEntity<Map> login = sessionLogin("acme", name, "s3cret!pw");
        assertThat(login.getStatusCode()).isEqualTo(HttpStatus.OK);
        String cookieLine = login.getHeaders().get(HttpHeaders.SET_COOKIE).get(0);
        assertThat(cookieLine).contains("HttpOnly").contains("SameSite=Strict").contains("Path=/api/v1/auth");
        assertThat(((Number) login.getBody().get("expiresIn")).longValue()).isEqualTo(900L);

        String token = (String) login.getBody().get("token");
        ResponseEntity<Map> me = me(token);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody()).containsEntry("username", name).containsEntry("firstname", "Alice A.").containsEntry("customer", "acme");
        assertThat((String) me.getBody().get("id")).isNotBlank();
        assertThat(me.getBody()).doesNotContainKey("password");
    }

    @Test
    void wrongPasswordUnknownCustomerAndMissingTokenAreRejected() {
        String name = unique("bob");
        register("acme", name, "Bob");
        assertThat(sessionLogin("acme", name, "wrong").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(sessionLogin("nope", name, "s3cret!pw").getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(me(null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(me("not-a-jwt").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void refreshRotatesTheCookieAndAnOldOneIsRefused() {
        String name = unique("carol");
        register("acme", name, "Carol");
        ResponseEntity<Map> login = sessionLogin("acme", name, "s3cret!pw");
        String first = cookieValue(login);

        ResponseEntity<Map> refreshed = refresh("acme", first);
        assertThat(refreshed.getStatusCode()).isEqualTo(HttpStatus.OK);
        String second = cookieValue(refreshed);
        assertThat(second).isNotEqualTo(first);
        assertThat(me((String) refreshed.getBody().get("token")).getStatusCode()).isEqualTo(HttpStatus.OK);

        assertThat(refresh("acme", first).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED); // rotated away
        assertThat(refresh("acme", null).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);   // no cookie
        assertThat(refresh("other", second).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED); // another tenant

        ResponseEntity<Void> out = rest.exchange("/auth/session/logout", HttpMethod.POST, new HttpEntity<>(headers("acme", null, second)), Void.class);
        assertThat(out.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(out.getHeaders().get(HttpHeaders.SET_COOKIE).get(0)).contains("Max-Age=0");
        assertThat(refresh("acme", second).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED); // revoked
    }

    @Test
    void profileUpdateChangesOnlyWhatWasSentAndValidatesLength() {
        String name = unique("dana");
        register("acme", name, "Dana");
        String token = (String) sessionLogin("acme", name, "s3cret!pw").getBody().get("token");

        ResponseEntity<Map> updated = rest.exchange("/auth/me/profile", HttpMethod.PATCH,
                new HttpEntity<>(Map.of("bio", "Content strategist"), headers(null, token, null)), Map.class);
        assertThat(updated.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(updated.getBody()).containsEntry("bio", "Content strategist").containsEntry("firstname", "Dana");

        ResponseEntity<Map> renamed = rest.exchange("/auth/me/profile", HttpMethod.PATCH,
                new HttpEntity<>(Map.of("firstname", "Dana D.", "bio", ""), headers(null, token, null)), Map.class);
        assertThat(renamed.getBody()).containsEntry("firstname", "Dana D.");
        assertThat(renamed.getBody().get("bio")).isNull();

        ResponseEntity<Map> tooLong = rest.exchange("/auth/me/profile", HttpMethod.PATCH,
                new HttpEntity<>(Map.of("bio", "x".repeat(2001)), headers(null, token, null)), Map.class);
        assertThat(tooLong.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void verifyPasswordAnswersForTheCaller() {
        String name = unique("erin");
        register("acme", name, "Erin");
        String token = (String) sessionLogin("acme", name, "s3cret!pw").getBody().get("token");
        ResponseEntity<Map> good = rest.exchange("/auth/me/verify-password", HttpMethod.POST,
                new HttpEntity<>(Map.of("password", "s3cret!pw"), headers(null, token, null)), Map.class);
        ResponseEntity<Map> bad = rest.exchange("/auth/me/verify-password", HttpMethod.POST,
                new HttpEntity<>(Map.of("password", "nope"), headers(null, token, null)), Map.class);
        assertThat(good.getBody()).containsEntry("valid", true);
        assertThat(bad.getBody()).containsEntry("valid", false);
    }

    @Test
    void lookupReturnsNamesOnlyAndNeverCrossesTenants() {
        String a = unique("fay");
        String b = unique("gus");
        register("acme", a, "Fay");
        register("acme", b, "Gus");
        register("other", a, "Other Fay"); // same username in another tenant
        String tokenA = (String) sessionLogin("acme", a, "s3cret!pw").getBody().get("token");
        String tokenOther = (String) sessionLogin("other", a, "s3cret!pw").getBody().get("token");
        String idA = (String) me(tokenA).getBody().get("id");
        String idB = (String) me((String) sessionLogin("acme", b, "s3cret!pw").getBody().get("token")).getBody().get("id");

        ResponseEntity<List> found = rest.exchange("/auth/users/lookup", HttpMethod.POST,
                new HttpEntity<>(Map.of("ids", List.of(idA, idB, "not-an-id")), headers(null, tokenA, null)), List.class);
        assertThat(found.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(found.getBody()).hasSize(2);
        @SuppressWarnings("unchecked")
        Map<String, Object> first = (Map<String, Object>) found.getBody().get(0);
        assertThat(first.keySet()).containsExactlyInAnyOrder("id", "username", "firstname", "lastname");

        ResponseEntity<List> crossTenant = rest.exchange("/auth/users/lookup", HttpMethod.POST,
                new HttpEntity<>(Map.of("ids", List.of(idA, idB)), headers(null, tokenOther, null)), List.class);
        assertThat(crossTenant.getBody()).isEmpty();
    }

    @Test
    void aPasswordResetTokenCannotActAsALogin() {
        String name = unique("hana");
        register("acme", name, "Hana");
        String reset = jwt.generatePasswordResetToken(name, "acme");
        assertThat(me(reset).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void theClassicLoginTokenStillWorksAndNowCarriesTheUserId() {
        String name = unique("ivan");
        register("acme", name, "Ivan");
        ResponseEntity<Map> login = rest.exchange("/auth/login", HttpMethod.POST,
                new HttpEntity<>(Map.of("username", name, "password", "s3cret!pw"), headers("acme", null, null)), Map.class);
        String token = (String) login.getBody().get("token");
        ResponseEntity<Map> verified = rest.exchange("/auth/verify", HttpMethod.POST,
                new HttpEntity<>(Map.of("token", token)), Map.class);
        assertThat(verified.getBody()).containsEntry("valid", true).containsEntry("username", name);
        assertThat(me(token).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void aDeactivatedUserLosesTheSessionImmediately() {
        String name = unique("jade");
        register("acme", name, "Jade");
        ResponseEntity<Map> login = sessionLogin("acme", name, "s3cret!pw");
        String token = (String) login.getBody().get("token");
        String cookie = cookieValue(login);

        users.setActive("acme", name, false);
        assertThat(me(token).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(refresh("acme", cookie).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(sessionLogin("acme", name, "s3cret!pw").getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
}
