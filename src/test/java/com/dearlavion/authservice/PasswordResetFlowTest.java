package com.dearlavion.authservice;

import com.dearlavion.authservice.security.JwtTokenService;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

/** Superadmin password reset by email, against an embedded mongod (no Docker needed) and a mocked mail server. */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.autoconfigure.exclude=",
                "spring.data.mongodb.uri=mongodb://localhost:27017/password-reset-test",
                "de.flapdoodle.mongodb.embedded.version=7.0.14",
                "app.customers=acme,security",
                "app.security-tenant=security",
                "app.kafka-enabled=false",
                "app.google-enabled=false",
                "app.provision-secret=test-provision-secret",
                "app.jwt-secret-base64=NUI2RjdEM0UyQTlDNEI4RTBBMUY2RDlCM0U3QTJDOUQ0RjhFNUI2QzNBN0IxRDZGNEM5QTNFOEQyQjVGN0Ex",
                "app.jwt-expires-in-seconds=60",
                "app.jwt-reset-expires-in-seconds=600",
                "app.security-reset-url=http://ui.test/reset-password",
                "app.mail-from=no-reply@ui.test",
                "spring.mail.host=smtp.ui.test",
        })
class PasswordResetFlowTest {

    private static final String OLD = "old-password-1";
    private static final String NEW = "new-password-2";

    @Autowired private TestRestTemplate rest;
    @Autowired private JwtTokenService jwt;
    @MockBean private JavaMailSender mail;

    @BeforeEach
    void plainHttpClient() {
        rest.getRestTemplate().setRequestFactory(
                new HttpComponentsClientHttpRequestFactory(HttpClients.custom().disableCookieManagement().build()));
    }

    private ResponseEntity<Map> call(String path, HttpMethod method, Object body, HttpHeaders headers) {
        return rest.exchange(path, method, new HttpEntity<>(body, headers), Map.class);
    }

    private static HttpHeaders tenant(String customer) {
        HttpHeaders h = new HttpHeaders();
        h.set("X-Customer", customer);
        return h;
    }

    private String superadmin() {
        String name = "root" + UUID.randomUUID().toString().substring(0, 8);
        HttpHeaders h = tenant("security");
        h.set("X-Provision-Secret", "test-provision-secret");
        assertThat(call("/auth/register", HttpMethod.POST,
                Map.of("username", name, "email", name + "@ui.test", "password", OLD, "activeProfile", "SUPERADMIN"), h)
                .getStatusCode()).isEqualTo(HttpStatus.OK);
        return name;
    }

    private ResponseEntity<Map> login(String username, String password) {
        return call("/auth/session/login", HttpMethod.POST, Map.of("username", username, "password", password), tenant("security"));
    }

    private ResponseEntity<Map> forgot(String email) {
        return call("/auth/forgot-password", HttpMethod.POST, Map.of("email", email), tenant("security"));
    }

    private ResponseEntity<Map> reset(String token, String password) {
        return call("/auth/reset-password", HttpMethod.POST, Map.of("token", token, "newPassword", password), new HttpHeaders());
    }

    private String emailedToken(String email) {
        ArgumentCaptor<SimpleMailMessage> sent = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mail, timeout(3000).atLeastOnce()).send(sent.capture());
        SimpleMailMessage message = sent.getValue();
        assertThat(message.getTo()).containsExactly(email);
        assertThat(message.getFrom()).isEqualTo("no-reply@ui.test");
        String text = message.getText();
        String marker = "http://ui.test/reset-password#token=";
        assertThat(text).contains(marker);
        return text.substring(text.indexOf(marker) + marker.length()).split("\\s")[0];
    }

    @Test
    void theEmailedLinkSetsANewPasswordOnceAndEndsSessions() {
        String name = superadmin();
        String cookie = login(name, OLD).getHeaders().getFirst(HttpHeaders.SET_COOKIE).split(";")[0];

        // Typed with different case and stray spaces.
        assertThat(forgot("  " + name.toUpperCase() + "@UI.test ").getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = emailedToken(name + "@ui.test");

        ResponseEntity<Map> tooShort = reset(token, "short");
        assertThat(tooShort.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(tooShort.getBody().get("message")).isEqualTo("Password must be at least 8 characters");

        assertThat(reset(token, NEW).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(login(name, OLD).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(login(name, NEW).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(reset(token, "third-password-3").getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        HttpHeaders old = tenant("security");
        old.set(HttpHeaders.COOKIE, cookie);
        assertThat(call("/auth/session/refresh", HttpMethod.POST, null, old).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void unknownEmailsLookTheSameAndSendNothing() {
        ResponseEntity<Map> unknown = forgot("nobody@ui.test");
        assertThat(unknown.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(unknown.getBody().get("message")).isEqualTo("If an account exists, a reset link was sent.");
        verify(mail, after(500).never()).send(any(SimpleMailMessage.class));
    }

    @Test
    void asksAreLimitedToOneEmailPerMinute() {
        String name = superadmin();
        forgot(name + "@ui.test");
        forgot(name + "@ui.test");
        verify(mail, after(1000).times(1)).send(any(SimpleMailMessage.class));
    }

    @Test
    void aSuperadminLinkMustBeTiedToTheCurrentPassword() {
        String name = superadmin();
        assertThat(reset(jwt.generatePasswordResetToken(name, "security"), NEW).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void aResetTokenIsNotALogin() {
        String name = superadmin();
        String token = jwt.generatePasswordResetToken(name, "security");
        assertThat(jwt.verifyToken(token)).isNull();
        assertThat(call("/auth/verify", HttpMethod.POST, Map.of("token", token), new HttpHeaders()).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aSuperadminsEmailCannotBeChangedWithoutTheProvisionSecret() {
        String name = superadmin();
        assertThat(call("/auth/user/" + name, HttpMethod.PATCH, Map.of("email", "attacker@evil.test"), tenant("security"))
                .getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        forgot("attacker@evil.test");
        verify(mail, after(500).never()).send(any(SimpleMailMessage.class));
    }
}
