package com.dearlavion.authservice;

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
 * Admin approval and permissions, against an embedded mongod (no Docker needed): a requested admin can't sign in until a
 * superadmin approves it, READ/MODIFY/BOTH are enforced on /admin, project admins can't hand out roles, and only a
 * SUPERADMIN of the security tenant reaches /superadmin.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.autoconfigure.exclude=",
                "spring.data.mongodb.uri=mongodb://localhost:27017/superadmin-flow-test",
                "de.flapdoodle.mongodb.embedded.version=7.0.14",
                "app.customers=acme,other,security",
                "app.security-tenant=security",
                "app.kafka-enabled=false",
                "app.google-enabled=false",
                "app.provision-secret=test-provision-secret",
                "app.jwt-secret-base64=NUI2RjdEM0UyQTlDNEI4RTBBMUY2RDlCM0U3QTJDOUQ0RjhFNUI2QzNBN0IxRDZGNEM5QTNFOEQyQjVGN0Ex",
                "app.jwt-expires-in-seconds=60",
                "app.jwt-reset-expires-in-seconds=30",
        })
class SuperAdminFlowTest {

    private static final String PASSWORD = "s3cret!pw";

    @Autowired private TestRestTemplate rest;

    @BeforeEach
    void plainHttpClient() {
        rest.getRestTemplate().setRequestFactory(
                new HttpComponentsClientHttpRequestFactory(HttpClients.custom().disableCookieManagement().build()));
    }

    private static String unique(String prefix) {
        return prefix + UUID.randomUUID().toString().substring(0, 8);
    }

    private HttpHeaders headers(String customer, String bearer, boolean provision) {
        HttpHeaders h = new HttpHeaders();
        if (customer != null) h.set("X-Customer", customer);
        if (bearer != null) h.setBearerAuth(bearer);
        if (provision) h.set("X-Provision-Secret", "test-provision-secret");
        return h;
    }

    private ResponseEntity<Map> call(HttpMethod method, String path, String customer, String bearer, Object body) {
        return rest.exchange(path, method, new HttpEntity<>(body, headers(customer, bearer, false)), Map.class);
    }

    /** Status only, for responses whose body may be a list or an error object. */
    private HttpStatus status(HttpMethod method, String path, String customer, String bearer, Object body) {
        return HttpStatus.valueOf(rest.exchange(path, method, new HttpEntity<>(body, headers(customer, bearer, false)), String.class).getStatusCode().value());
    }

    private ResponseEntity<List> callList(String path, String bearer) {
        return rest.exchange(path, HttpMethod.GET, new HttpEntity<>(headers(null, bearer, false)), List.class);
    }

    private void register(String customer, String username, String role, boolean provision) {
        Map<String, Object> body = Map.of("username", username, "email", username + "@" + customer + ".dev",
                "password", PASSWORD, "activeProfile", role);
        ResponseEntity<Map> r = rest.exchange("/auth/register", HttpMethod.POST, new HttpEntity<>(body, headers(customer, null, provision)), Map.class);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private ResponseEntity<Map> login(String customer, String username) {
        return call(HttpMethod.POST, "/auth/login", customer, null, Map.of("username", username, "password", PASSWORD));
    }

    private String token(String customer, String username) {
        ResponseEntity<Map> r = login(customer, username);
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        return (String) r.getBody().get("token");
    }

    private String superadminToken() {
        String name = unique("root");
        register("security", name, "SUPERADMIN", true);
        return token("security", name);
    }

    private void requestAdmin(String customer, String username) {
        ResponseEntity<Map> r = call(HttpMethod.POST, "/auth/admin-request", customer, null,
                Map.of("username", username, "email", username + "@" + customer + ".dev", "password", PASSWORD));
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private ResponseEntity<Map> approve(String superToken, String customer, String username, String status, String permission) {
        Map<String, Object> body = permission == null ? Map.of("status", status) : Map.of("status", status, "permission", permission);
        return call(HttpMethod.PATCH, "/superadmin/projects/" + customer + "/users/" + username + "/approval", null, superToken, body);
    }

    @Test
    void requestedAdminCannotSignInUntilApprovedAndPermissionIsEnforced() {
        String root = superadminToken();
        String admin = unique("ada");
        requestAdmin("acme", admin);

        ResponseEntity<Map> pending = login("acme", admin);
        assertThat(pending.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(pending.getBody().get("message").toString()).contains("pending approval");

        assertThat(approve(root, "acme", admin, "APPROVED", null).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        ResponseEntity<Map> approved = approve(root, "acme", admin, "APPROVED", "READ");
        assertThat(approved.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(approved.getBody()).containsEntry("status", "APPROVED").containsEntry("permission", "READ");

        String token = token("acme", admin);
        assertThat(status(HttpMethod.GET, "/admin/users", null, token, null)).isEqualTo(HttpStatus.OK);
        assertThat(call(HttpMethod.POST, "/admin/users", null, token, Map.of("username", unique("u"), "email", unique("e") + "@x.dev", "password", PASSWORD))
                .getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        ResponseEntity<Map> verify = rest.postForEntity("/auth/verify", Map.of("token", token), Map.class);
        assertThat(verify.getBody()).containsEntry("permission", "READ").containsEntry("activeProfile", "ADMIN");

        approve(root, "acme", admin, "APPROVED", "BOTH");
        String bothToken = token("acme", admin);
        String created = unique("member");
        ResponseEntity<Map> make = call(HttpMethod.POST, "/admin/users", null, bothToken,
                Map.of("username", created, "email", created + "@acme.dev", "password", PASSWORD, "activeProfile", "ADMIN"));
        assertThat(make.getStatusCode()).isEqualTo(HttpStatus.OK);
        // The role in the body is ignored: a project admin can't mint admins.
        assertThat(make.getBody()).containsEntry("activeProfile", "USER");

        approve(root, "acme", admin, "REJECTED", null);
        assertThat(login("acme", admin).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(status(HttpMethod.GET, "/admin/users", null, bothToken, null)).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void modifyOnlyAdminCanWriteButNotRead() {
        String root = superadminToken();
        String admin = unique("max");
        requestAdmin("acme", admin);
        approve(root, "acme", admin, "APPROVED", "MODIFY");
        String token = token("acme", admin);
        assertThat(status(HttpMethod.GET, "/admin/users", null, token, null)).isEqualTo(HttpStatus.FORBIDDEN);
        String member = unique("member");
        assertThat(call(HttpMethod.POST, "/admin/users", null, token,
                Map.of("username", member, "email", member + "@acme.dev", "password", PASSWORD)).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void superadminRoutesAreForSuperadminsOfTheSecurityTenantOnly() {
        assertThat(status(HttpMethod.GET, "/superadmin/projects", null, null, null)).isEqualTo(HttpStatus.UNAUTHORIZED);

        // ADMIN registered with the provision secret in a project: valid token, wrong role and tenant.
        String projectAdmin = unique("pa");
        register("acme", projectAdmin, "ADMIN", true);
        assertThat(status(HttpMethod.GET, "/superadmin/projects", null, token("acme", projectAdmin), null)).isEqualTo(HttpStatus.FORBIDDEN);

        // SUPERADMIN is only grantable in the security tenant; elsewhere the role falls back to USER.
        String fake = unique("fake");
        register("acme", fake, "SUPERADMIN", true);
        ResponseEntity<Map> fakeLogin = login("acme", fake);
        assertThat((Map<String, Object>) fakeLogin.getBody().get("user")).containsEntry("activeProfile", "USER");
        assertThat(status(HttpMethod.GET, "/superadmin/projects", null, token("acme", fake), null)).isEqualTo(HttpStatus.FORBIDDEN);

        // An ADMIN of the security tenant is not a SUPERADMIN either.
        String securityAdmin = unique("sa");
        register("security", securityAdmin, "ADMIN", true);
        assertThat(status(HttpMethod.GET, "/superadmin/projects", null, token("security", securityAdmin), null)).isEqualTo(HttpStatus.FORBIDDEN);

        String root = superadminToken();
        ResponseEntity<List> projects = callList("/superadmin/projects", root);
        assertThat(projects.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(projects.getBody()).extracting(p -> ((Map) p).get("customer")).containsExactlyInAnyOrder("acme", "other");
    }

    @Test
    void listingFiltersByRoleStatusAndSearchAndApprovalsListPending() {
        String root = superadminToken();
        String pendingAdmin = unique("pend");
        requestAdmin("other", pendingAdmin);
        String member = unique("plain");
        register("other", member, "USER", false);

        ResponseEntity<Map> admins = call(HttpMethod.GET, "/superadmin/projects/other/users?role=ADMIN&status=PENDING&q=" + pendingAdmin.substring(0, 6), null, root, null);
        assertThat(admins.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(((Number) admins.getBody().get("total")).intValue()).isEqualTo(1);

        // Users written without a status count as approved.
        ResponseEntity<Map> approvedUsers = call(HttpMethod.GET, "/superadmin/projects/other/users?role=USER&status=APPROVED&q=" + member, null, root, null);
        assertThat(((Number) approvedUsers.getBody().get("total")).intValue()).isEqualTo(1);

        ResponseEntity<List> approvals = callList("/superadmin/approvals", root);
        assertThat(approvals.getBody()).anySatisfy(p -> assertThat(((Map) ((Map) p).get("user")).get("username")).isEqualTo(pendingAdmin));

        assertThat(status(HttpMethod.GET, "/superadmin/projects/nope/users", null, root, null)).isEqualTo(HttpStatus.BAD_REQUEST);
        // Users don't take part in approvals.
        assertThat(approve(root, "other", member, "APPROVED", "READ").getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        ResponseEntity<List> audit = callList("/superadmin/audit", root);
        assertThat(audit.getStatusCode()).isEqualTo(HttpStatus.OK);
    }
}
