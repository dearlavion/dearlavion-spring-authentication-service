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
    void adminWithNoPermissionKeepsTheAccountButCannotReadOrWrite() {
        String root = superadminToken();
        String admin = unique("nia");
        requestAdmin("acme", admin);
        approve(root, "acme", admin, "APPROVED", "BOTH");
        String token = token("acme", admin);
        assertThat(status(HttpMethod.GET, "/admin/users", null, token, null)).isEqualTo(HttpStatus.OK);

        assertThat(approve(root, "acme", admin, "APPROVED", "NONE").getBody()).containsEntry("permission", "NONE");
        assertThat(status(HttpMethod.GET, "/admin/users", null, token, null)).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(status(HttpMethod.POST, "/admin/users", null, token, Map.of("username", unique("u"), "email", unique("e") + "@x.dev", "password", PASSWORD)))
                .isEqualTo(HttpStatus.FORBIDDEN);
        // Still approved and active, so the account itself keeps working.
        assertThat(login("acme", admin).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void superadminCreatesAnApprovedAdminOrAPlainUser() {
        String root = superadminToken();
        String adminName = unique("cora");
        Map<String, Object> adminBody = Map.of("username", adminName.toUpperCase(), "email", adminName + "@acme.dev", "password", PASSWORD,
                "firstname", "Cora", "role", "ADMIN", "permission", "READ");
        ResponseEntity<Map> admin = call(HttpMethod.POST, "/superadmin/projects/acme/users", null, root, adminBody);
        assertThat(admin.getStatusCode()).isEqualTo(HttpStatus.OK);
        // Usernames are stored lower-case, like the other apps do.
        assertThat(admin.getBody()).containsEntry("username", adminName).containsEntry("activeProfile", "ADMIN")
                .containsEntry("status", "APPROVED").containsEntry("permission", "READ");

        // Approved already, so it signs in and gets exactly the permission it was given.
        String token = token("acme", adminName);
        assertThat(status(HttpMethod.GET, "/admin/users", null, token, null)).isEqualTo(HttpStatus.OK);
        assertThat(status(HttpMethod.POST, "/admin/users", null, token,
                Map.of("username", unique("u"), "email", unique("e") + "@x.dev", "password", PASSWORD))).isEqualTo(HttpStatus.FORBIDDEN);

        String userName = unique("pat");
        ResponseEntity<Map> user = call(HttpMethod.POST, "/superadmin/projects/acme/users", null, root,
                Map.of("username", userName, "email", userName + "@acme.dev", "password", PASSWORD, "role", "USER"));
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(user.getBody()).containsEntry("activeProfile", "USER");
        assertThat(login("acme", userName).getStatusCode()).isEqualTo(HttpStatus.OK);

        assertThat(call(HttpMethod.POST, "/superadmin/projects/acme/users", null, root, adminBody).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void usersListPagesAcrossProjectsInProjectThenUsernameOrder() {
        String root = superadminToken();
        String tag = unique("zz");
        for (int i = 1; i <= 3; i++) register("acme", tag + "a" + i, "USER", false);
        for (int i = 1; i <= 2; i++) register("other", tag + "b" + i, "USER", false);
        String base = "/superadmin/users?q=" + tag + "&size=2";

        ResponseEntity<Map> first = call(HttpMethod.GET, base + "&page=0", null, root, null);
        assertThat(((Number) first.getBody().get("total")).intValue()).isEqualTo(5);
        assertThat(names((List) first.getBody().get("items"))).containsExactly("acme/" + tag + "a1", "acme/" + tag + "a2");
        // The second page straddles the two projects.
        assertThat(names((List) call(HttpMethod.GET, base + "&page=1", null, root, null).getBody().get("items")))
                .containsExactly("acme/" + tag + "a3", "other/" + tag + "b1");
        assertThat(names((List) call(HttpMethod.GET, base + "&page=2", null, root, null).getBody().get("items")))
                .containsExactly("other/" + tag + "b2");

        ResponseEntity<Map> one = call(HttpMethod.GET, "/superadmin/users?q=" + tag + "&customer=other", null, root, null);
        assertThat(((Number) one.getBody().get("total")).intValue()).isEqualTo(2);
        assertThat(status(HttpMethod.GET, "/superadmin/users?customer=security", null, root, null)).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void rolesAreCreatedSearchedAndDeletedPerProject() {
        String root = superadminToken();
        String tag = unique("Role");
        Map<String, Object> editor = Map.of("name", tag + "A", "description", "Edits content", "permission", "BOTH");

        ResponseEntity<Map> created = call(HttpMethod.POST, "/superadmin/projects/acme/roles", null, root, editor);
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(created.getBody()).containsEntry("name", tag + "A").containsEntry("permission", "BOTH");
        String id = (String) created.getBody().get("id");

        // Names are unique per project, ignoring case, but another project can reuse one.
        assertThat(call(HttpMethod.POST, "/superadmin/projects/acme/roles", null, root,
                Map.of("name", (tag + "a").toLowerCase(), "permission", "READ")).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(call(HttpMethod.POST, "/superadmin/projects/other/roles", null, root,
                Map.of("name", tag + "A", "permission", "READ")).getStatusCode()).isEqualTo(HttpStatus.OK);
        call(HttpMethod.POST, "/superadmin/projects/other/roles", null, root, Map.of("name", tag + "B", "permission", "MODIFY"));

        // Across projects: ordered by project, then name; the second page straddles them.
        String base = "/superadmin/roles?q=" + tag + "&size=2";
        ResponseEntity<Map> first = call(HttpMethod.GET, base + "&page=0", null, root, null);
        assertThat(((Number) first.getBody().get("total")).intValue()).isEqualTo(3);
        assertThat(roleNames((List) first.getBody().get("items"))).containsExactly("acme/" + tag + "A", "other/" + tag + "A");
        assertThat(roleNames((List) call(HttpMethod.GET, base + "&page=1", null, root, null).getBody().get("items"))).containsExactly("other/" + tag + "B");
        assertThat(((Number) call(HttpMethod.GET, "/superadmin/roles?q=" + tag + "&customer=other", null, root, null).getBody().get("total")).intValue()).isEqualTo(2);

        assertThat(status(HttpMethod.DELETE, "/superadmin/projects/acme/roles/" + id, null, root, null)).isEqualTo(HttpStatus.OK);
        assertThat(status(HttpMethod.DELETE, "/superadmin/projects/acme/roles/" + id, null, root, null)).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void roleCreateRejectsBadInputAndNonSuperadmins() {
        String root = superadminToken();
        String path = "/superadmin/projects/acme/roles";
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("name", "x", "permission", "READ"))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("name", unique("ok"), "permission", "NONE"))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("name", unique("ok")))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, "/superadmin/projects/security/roles", null, root, Map.of("name", unique("ok"), "permission", "READ"))).isEqualTo(HttpStatus.BAD_REQUEST);
        String projectAdmin = unique("pa");
        register("acme", projectAdmin, "ADMIN", true);
        assertThat(status(HttpMethod.POST, path, null, token("acme", projectAdmin), Map.of("name", unique("ok"), "permission", "READ"))).isEqualTo(HttpStatus.FORBIDDEN);
    }

    private static List<String> roleNames(List<?> items) {
        return items.stream().map(i -> ((Map) i).get("customer") + "/" + ((Map) ((Map) i).get("role")).get("name")).map(String::valueOf).toList();
    }

    private static List<String> names(List<?> items) {
        return items.stream().map(i -> ((Map) i).get("customer") + "/" + ((Map) ((Map) i).get("user")).get("username")).map(String::valueOf).toList();
    }

    @Test
    void superadminCreateRejectsBadInput() {
        String root = superadminToken();
        String name = unique("bad");
        Map<String, Object> ok = Map.of("username", name, "email", name + "@acme.dev", "password", PASSWORD, "role", "USER");
        String path = "/superadmin/projects/acme/users";
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("username", name, "email", name + "@acme.dev", "password", PASSWORD, "role", "SUPERADMIN")))
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("username", name, "email", name + "@acme.dev", "password", PASSWORD, "role", "ADMIN")))
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("username", name, "email", name + "@acme.dev", "password", "short", "role", "USER")))
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, "/superadmin/projects/security/users", null, root, ok)).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, "/superadmin/projects/nope/users", null, root, ok)).isEqualTo(HttpStatus.BAD_REQUEST);
        // A project admin's own token can't reach it.
        String projectAdmin = unique("pa");
        register("acme", projectAdmin, "ADMIN", true);
        assertThat(status(HttpMethod.POST, path, null, token("acme", projectAdmin), ok)).isEqualTo(HttpStatus.FORBIDDEN);
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
