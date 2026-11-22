package com.dearlavion.authservice;

import com.dearlavion.authservice.access.AccessMigration;
import com.dearlavion.authservice.access.PermissionDef;
import com.dearlavion.authservice.superadmin.PermissionRole;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.model.Role;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.springframework.data.mongodb.core.MongoTemplate;
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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Roles, permissions and approvals, against an embedded mongod (no Docker needed): a requested admin can't sign in until a
 * superadmin gives them a role, the role's read/modify permissions are enforced on /admin and follow edits live, default roles
 * are shared by every project, and only a SUPERADMIN of the security tenant reaches /superadmin.
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

    /** {@code customer} null means a default role/permission. */
    private String rolesPath(String customer) {
        return customer == null ? "/superadmin/defaults/roles" : "/superadmin/projects/" + customer + "/roles";
    }

    private String permissionsPath(String customer) {
        return customer == null ? "/superadmin/defaults/permissions" : "/superadmin/projects/" + customer + "/permissions";
    }

    private String createRole(String root, String customer, String name, String type, List<String> keys) {
        ResponseEntity<Map> r = call(HttpMethod.POST, rolesPath(customer), null, root,
                Map.of("name", name, "permissionKeys", keys));
        assertThat(r.getStatusCode()).isEqualTo(HttpStatus.OK);
        return (String) r.getBody().get("id");
    }

    private ResponseEntity<Map> updateRole(String root, String customer, String id, Map<String, Object> body) {
        return call(HttpMethod.PATCH, rolesPath(customer) + "/" + id, null, root, body);
    }

    private ResponseEntity<Map> approve(String superToken, String customer, String username, String status, String roleId) {
        Map<String, Object> body = roleId == null ? Map.of("status", status) : Map.of("status", status, "roleId", roleId);
        return call(HttpMethod.PATCH, "/superadmin/projects/" + customer + "/users/" + username + "/approval", null, superToken, body);
    }

    private ResponseEntity<Map> assign(String superToken, String customer, String username, String roleId) {
        return call(HttpMethod.PATCH, "/superadmin/projects/" + customer + "/users/" + username + "/role", null, superToken, Map.of("roleId", roleId));
    }

    private ResponseEntity<Map> createUser(String root, String customer, String username, String roleId) {
        return call(HttpMethod.POST, "/superadmin/projects/" + customer + "/users", null, root,
                Map.of("username", username, "email", username + "@" + customer + ".dev", "password", PASSWORD, "roleId", roleId));
    }

    private HttpStatus writeStatus(String token) {
        return status(HttpMethod.POST, "/admin/users", null, token,
                Map.of("username", unique("w"), "email", unique("e") + "@x.dev", "password", PASSWORD));
    }

    private HttpStatus readStatus(String token) {
        return status(HttpMethod.GET, "/admin/users", null, token, null);
    }

    @Test
    void requestedAdminCannotSignInUntilGivenARoleAndTheRoleDrivesAccess() {
        String root = superadminToken();
        String admin = unique("ada");
        requestAdmin("acme", admin);

        ResponseEntity<Map> pending = login("acme", admin);
        assertThat(pending.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(pending.getBody().get("message").toString()).contains("pending approval");

        // Approving needs a role; an unknown one is refused too.
        assertThat(approve(root, "acme", admin, "APPROVED", null).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(approve(root, "acme", admin, "APPROVED", "nope").getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        String reader = createRole(root, "acme", unique("Reader"), "ADMIN", List.of("read"));
        ResponseEntity<Map> approved = approve(root, "acme", admin, "APPROVED", reader);
        assertThat(approved.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(approved.getBody()).containsEntry("status", "APPROVED").containsEntry("roleId", reader).containsEntry("activeProfile", "ADMIN");
        assertThat((List) approved.getBody().get("permissions")).containsExactly("read");

        String token = token("acme", admin);
        assertThat(readStatus(token)).isEqualTo(HttpStatus.OK);
        assertThat(writeStatus(token)).isEqualTo(HttpStatus.FORBIDDEN);
        ResponseEntity<Map> verify = rest.postForEntity("/auth/verify", Map.of("token", token), Map.class);
        assertThat(verify.getBody()).containsEntry("permission", "READ").containsEntry("activeProfile", "ADMIN").containsEntry("roleId", reader);
        assertThat((List) verify.getBody().get("permissions")).containsExactly("read");

        // Editing the role applies to the same token straight away.
        assertThat(updateRole(root, "acme", reader, Map.of("permissionKeys", List.of("read", "create"))).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(writeStatus(token)).isEqualTo(HttpStatus.OK);

        approve(root, "acme", admin, "REJECTED", null);
        assertThat(login("acme", admin).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(readStatus(token)).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void aRoleWithOnlyCreateCanCreateButNotReadAndOneWithNothingCanDoNeither() {
        String root = superadminToken();
        String writerRole = createRole(root, "acme", unique("Writer"), "ADMIN", List.of("create"));
        String emptyRole = createRole(root, "acme", unique("Nobody"), "ADMIN", List.of());
        String writer = unique("max");
        String nobody = unique("nia");
        assertThat(createUser(root, "acme", writer, writerRole).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(createUser(root, "acme", nobody, emptyRole).getStatusCode()).isEqualTo(HttpStatus.OK);

        String writerToken = token("acme", writer);
        assertThat(readStatus(writerToken)).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(writeStatus(writerToken)).isEqualTo(HttpStatus.OK);

        String nobodyToken = token("acme", nobody);
        assertThat(readStatus(nobodyToken)).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(writeStatus(nobodyToken)).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(rest.postForEntity("/auth/verify", Map.of("token", nobodyToken), Map.class).getBody()).containsEntry("permission", "NONE");
    }

    @Test
    void theAdminAreaChecksThePermissionThatMatchesTheRequestType() {
        String root = superadminToken();
        String updater = unique("upe");
        String deleter = unique("dee");
        String reader = unique("rea");
        assertThat(createUser(root, "acme", updater, createRole(root, "acme", unique("Updater"), "ADMIN", List.of("update"))).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(createUser(root, "acme", deleter, createRole(root, "acme", unique("Deleter"), "ADMIN", List.of("delete"))).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(createUser(root, "acme", reader, createRole(root, "acme", unique("Reader"), "ADMIN", List.of("read"))).getStatusCode()).isEqualTo(HttpStatus.OK);
        String target = unique("tgt");
        register("acme", target, "USER", false);

        // update: PATCH works, but not read, create or delete.
        String updaterToken = token("acme", updater);
        assertThat(status(HttpMethod.PATCH, "/admin/users/" + target, null, updaterToken, Map.of("firstname", "X"))).isEqualTo(HttpStatus.OK);
        assertThat(readStatus(updaterToken)).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(writeStatus(updaterToken)).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(status(HttpMethod.DELETE, "/admin/users/" + target, null, updaterToken, null)).isEqualTo(HttpStatus.FORBIDDEN);

        // read: GET works, but PATCH, POST and DELETE don't.
        String readerToken = token("acme", reader);
        assertThat(readStatus(readerToken)).isEqualTo(HttpStatus.OK);
        assertThat(status(HttpMethod.PATCH, "/admin/users/" + target, null, readerToken, Map.of("firstname", "X"))).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(status(HttpMethod.DELETE, "/admin/users/" + target, null, readerToken, null)).isEqualTo(HttpStatus.FORBIDDEN);

        // delete: the request gets past the permission check (this service has no DELETE route, so it is a 404/405, not a 403).
        String deleterToken = token("acme", deleter);
        assertThat(status(HttpMethod.DELETE, "/admin/users/" + target, null, deleterToken, null)).isNotEqualTo(HttpStatus.FORBIDDEN).isNotEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(status(HttpMethod.PATCH, "/admin/users/" + target, null, deleterToken, Map.of("firstname", "X"))).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Autowired private AccessMigration migration;
    @Autowired private TenantService tenants;

    @Test
    void theOldModifyPermissionIsReplacedByCreateUpdateAndDeleteEverywhere() {
        String root = superadminToken();
        // Data as the previous version left it: a default and a project role linking modify, and modify in the catalog.
        MongoTemplate defaults = tenants.defaultsDb();
        defaults.insert(new PermissionDef(null, "modify", "Old", true, "system", Instant.now()));
        String tag = unique("Mig");
        defaults.insert(new PermissionRole(null, tag + "D", null, Role.ADMIN, new ArrayList<>(List.of("read", "modify")), false, "t", Instant.now()));
        tenants.rawDb("acme").insert(new PermissionRole(null, tag + "A", null, Role.ADMIN, new ArrayList<>(List.of("modify")), false, "t", Instant.now()));

        migration.migrate();
        migration.migrate(); // idempotent

        ResponseEntity<Map> roles = call(HttpMethod.GET, "/superadmin/roles?customer=acme&q=" + tag, null, root, null);
        for (Map item : (List<Map>) roles.getBody().get("items")) {
            List keys = (List) ((Map) item.get("role")).get("permissionKeys");
            assertThat(keys).doesNotContain("modify").contains("create", "update", "delete");
        }
        assertThat(((Number) roles.getBody().get("total")).intValue()).isEqualTo(2);
        List<String> catalog = ((List<Map>) call(HttpMethod.GET, "/superadmin/permissions?customer=*&size=100", null, root, null).getBody().get("items"))
                .stream().map(i -> (String) ((Map) i.get("permission")).get("key")).toList();
        assertThat(catalog).doesNotContain("modify").contains("read", "create", "update", "delete");
    }

    @Test
    void anAdminWithoutARoleKeepsTheirLegacyAccess() {
        String legacy = unique("old");
        register("acme", legacy, "ADMIN", true);
        String token = token("acme", legacy);
        assertThat(readStatus(token)).isEqualTo(HttpStatus.OK);
        assertThat(writeStatus(token)).isEqualTo(HttpStatus.OK);
        ResponseEntity<Map> verify = rest.postForEntity("/auth/verify", Map.of("token", token), Map.class);
        assertThat(verify.getBody()).containsEntry("permission", "BOTH").containsEntry("activeProfile", "ADMIN");
        assertThat((List) verify.getBody().get("permissions")).containsExactlyInAnyOrder("create", "delete", "read", "update");
        assertThat(verify.getBody().get("roleId")).isNull();
    }

    @Test
    void aDefaultRoleIsSharedByEveryProjectAndEditsReachAllHolders() {
        String root = superadminToken();
        String tag = unique("Aud");
        assertThat(call(HttpMethod.POST, permissionsPath(null), null, root, Map.of("key", tag.toLowerCase() + ".view")).getStatusCode())
                .isEqualTo(HttpStatus.OK);
        String auditor = createRole(root, null, tag, "ADMIN", List.of("read", tag.toLowerCase() + ".view"));

        // Both projects can use it without defining anything.
        String inAcme = unique("ann");
        String inOther = unique("oli");
        assertThat(createUser(root, "acme", inAcme, auditor).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(createUser(root, "other", inOther, auditor).getStatusCode()).isEqualTo(HttpStatus.OK);
        String acmeToken = token("acme", inAcme);
        String otherToken = token("other", inOther);
        assertThat(readStatus(acmeToken)).isEqualTo(HttpStatus.OK);
        assertThat(readStatus(otherToken)).isEqualTo(HttpStatus.OK);

        // A project sees it in its role list, flagged as a default, with the holders from every project counted.
        ResponseEntity<Map> list = call(HttpMethod.GET, "/superadmin/roles?customer=acme&q=" + tag, null, root, null);
        assertThat(((Number) list.getBody().get("total")).intValue()).isEqualTo(1);
        Map item = (Map) ((List) list.getBody().get("items")).get(0);
        assertThat(item.get("customer")).isNull();
        assertThat((Map) item.get("role")).containsEntry("isDefault", true).containsEntry("userCount", 2);

        // Names can't clash between a default and a project's own role, and a default role can't use a project's permission.
        assertThat(call(HttpMethod.POST, rolesPath("acme"), null, root, Map.of("name", tag.toLowerCase(), "permissionKeys", List.of())).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);
        String own = unique("own") + ".do";
        assertThat(call(HttpMethod.POST, permissionsPath("acme"), null, root, Map.of("key", own)).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(call(HttpMethod.POST, rolesPath(null), null, root, Map.of("name", unique("Bad"), "permissionKeys", List.of(own))).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        // A project's own role can link both a default permission and its own.
        assertThat(call(HttpMethod.POST, rolesPath("acme"), null, root, Map.of("name", unique("Mix"), "permissionKeys", List.of("read", own))).getStatusCode())
                .isEqualTo(HttpStatus.OK);

        // Editing the default role reaches every holder in every project at once.
        assertThat(updateRole(root, null, auditor, Map.of("permissionKeys", List.of(tag.toLowerCase() + ".view"))).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(readStatus(acmeToken)).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(readStatus(otherToken)).isEqualTo(HttpStatus.FORBIDDEN);

        // Held roles can't be deleted; a default permission can't be deleted while a role links it.
        assertThat(status(HttpMethod.DELETE, rolesPath(null) + "/" + auditor, null, root, null)).isEqualTo(HttpStatus.CONFLICT);
        ResponseEntity<Map> perms = call(HttpMethod.GET, "/superadmin/permissions?customer=*&q=" + tag.toLowerCase(), null, root, null);
        String permissionId = (String) ((Map) ((Map) ((List) perms.getBody().get("items")).get(0)).get("permission")).get("id");
        assertThat(status(HttpMethod.DELETE, permissionsPath(null) + "/" + permissionId, null, root, null)).isEqualTo(HttpStatus.CONFLICT);
    }

    private String builtInRoleId(String root, String name) {
        ResponseEntity<Map> found = call(HttpMethod.GET, "/superadmin/roles?customer=*&q=" + name, null, root, null);
        return ((List<Map>) found.getBody().get("items")).stream().map(i -> (Map) i.get("role"))
                .filter(r -> name.equals(r.get("name"))).map(r -> (String) r.get("id")).findFirst().orElseThrow();
    }

    @Test
    void adminAndUserAreBuiltInDefaultRolesThatCanBeEditedButNotRemovedOrRenamed() {
        String root = superadminToken();
        ResponseEntity<Map> found = call(HttpMethod.GET, "/superadmin/roles?customer=acme&size=100", null, root, null);
        List<Map> roles = ((List<Map>) found.getBody().get("items")).stream().map(i -> (Map) i.get("role")).toList();
        Map admin = roles.stream().filter(r -> "Admin".equals(r.get("name"))).findFirst().orElseThrow();
        Map user = roles.stream().filter(r -> "User".equals(r.get("name"))).findFirst().orElseThrow();
        assertThat(admin).containsEntry("builtIn", true).containsEntry("isDefault", true).containsEntry("accountType", "ADMIN");
        assertThat((List) admin.get("permissionKeys")).containsExactlyInAnyOrder("read", "create", "update", "delete");
        assertThat(user).containsEntry("builtIn", true).containsEntry("accountType", "USER");
        assertThat((List) user.get("permissionKeys")).isEmpty();
        String adminId = (String) admin.get("id");

        assertThat(status(HttpMethod.DELETE, rolesPath(null) + "/" + adminId, null, root, null)).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(updateRole(root, null, adminId, Map.of("name", "Boss")).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        // The same name and a new description are fine; a project can't reuse the name.
        assertThat(updateRole(root, null, adminId, Map.of("name", "Admin", "description", "Edited")).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(call(HttpMethod.POST, rolesPath("acme"), null, root, Map.of("name", "admin", "permissionKeys", List.of())).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);

        // Any project can use the built-in Admin role as it is, and editing what it grants applies live.
        String holder = unique("hal");
        assertThat(createUser(root, "acme", holder, adminId).getStatusCode()).isEqualTo(HttpStatus.OK);
        String token = token("acme", holder);
        assertThat(readStatus(token)).isEqualTo(HttpStatus.OK);
        assertThat(writeStatus(token)).isEqualTo(HttpStatus.OK);
        try {
            assertThat(updateRole(root, null, adminId, Map.of("permissionKeys", List.of("read"))).getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(writeStatus(token)).isEqualTo(HttpStatus.FORBIDDEN);
        } finally {
            updateRole(root, null, adminId, Map.of("permissionKeys", List.of("read", "create", "update", "delete"), "description", "Full access to a project's admin area"));
        }
        assertThat(writeStatus(token)).isEqualTo(HttpStatus.OK);
    }

    @Test
    void aRolesAccountTypeFollowsItsPermissionsAndMovesItsHolders() {
        String root = superadminToken();
        String tag = unique("Auto");
        // Linking an admin-area permission makes it an admin role; one with only your own permissions is a user role.
        String ownKey = tag.toLowerCase() + ".thing";
        assertThat(call(HttpMethod.POST, permissionsPath("acme"), null, root, Map.of("key", ownKey)).getStatusCode()).isEqualTo(HttpStatus.OK);
        ResponseEntity<Map> plain = call(HttpMethod.POST, rolesPath("acme"), null, root, Map.of("name", tag + "P", "permissionKeys", List.of(ownKey), "accountType", "ADMIN"));
        assertThat(plain.getBody()).containsEntry("accountType", "USER");  // a sent accountType is ignored

        String roleId = createRole(root, "acme", tag + "R", "ADMIN", List.of("read"));
        String member = unique("sam");
        assertThat(createUser(root, "acme", member, roleId).getBody()).containsEntry("activeProfile", "ADMIN");
        String token = token("acme", member);
        assertThat(readStatus(token)).isEqualTo(HttpStatus.OK);

        // Take the admin-area permission away: the role, and so its holders, become plain users.
        ResponseEntity<Map> edited = updateRole(root, "acme", roleId, Map.of("permissionKeys", List.of(ownKey)));
        assertThat(edited.getBody()).containsEntry("accountType", "USER");
        assertThat(readStatus(token)).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(rest.postForEntity("/auth/verify", Map.of("token", token), Map.class).getBody()).containsEntry("activeProfile", "USER");
        // And back.
        assertThat(updateRole(root, "acme", roleId, Map.of("permissionKeys", List.of(ownKey, "read"))).getBody()).containsEntry("accountType", "ADMIN");
        assertThat(readStatus(token)).isEqualTo(HttpStatus.OK);

        // The built-in User role keeps its type whatever it is given.
        String userRoleId = builtInRoleId(root, "User");
        assertThat(updateRole(root, null, userRoleId, Map.of("permissionKeys", List.of("read"))).getBody()).containsEntry("accountType", "USER");
        updateRole(root, null, userRoleId, Map.of("permissionKeys", List.of()));

        // Delete works once nobody holds it.
        assertThat(status(HttpMethod.DELETE, rolesPath("acme") + "/" + roleId, null, root, null)).isEqualTo(HttpStatus.CONFLICT);
        String other = createRole(root, "acme", unique("Other"), "USER", List.of());
        assertThat(assign(root, "acme", member, other).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(status(HttpMethod.DELETE, rolesPath("acme") + "/" + roleId, null, root, null)).isEqualTo(HttpStatus.OK);
        assertThat(status(HttpMethod.DELETE, rolesPath("acme") + "/" + roleId, null, root, null)).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void thePermissionCatalogHasBuiltInsAndGuardsDuplicatesAndLinkedDeletes() {
        String root = superadminToken();
        ResponseEntity<Map> builtIns = call(HttpMethod.GET, "/superadmin/permissions?customer=*&size=100", null, root, null);
        List<String> keys = ((List<Map>) builtIns.getBody().get("items")).stream().map(i -> (String) ((Map) i.get("permission")).get("key")).toList();
        assertThat(keys).contains("read", "create", "update", "delete").doesNotContain("modify");
        Map readItem = ((List<Map>) builtIns.getBody().get("items")).stream().filter(i -> "read".equals(((Map) i.get("permission")).get("key"))).findFirst().orElseThrow();
        assertThat(status(HttpMethod.DELETE, permissionsPath(null) + "/" + ((Map) readItem.get("permission")).get("id"), null, root, null)).isEqualTo(HttpStatus.BAD_REQUEST);

        String key = unique("pk").toLowerCase() + ".manage";
        ResponseEntity<Map> created = call(HttpMethod.POST, permissionsPath("acme"), null, root, Map.of("key", key.toUpperCase(), "description", "Manage things"));
        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(created.getBody()).containsEntry("key", key).containsEntry("builtIn", false);
        assertThat(call(HttpMethod.POST, permissionsPath("acme"), null, root, Map.of("key", key)).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        // The defaults can't take a key a project already defined, nor a project one the defaults have.
        assertThat(call(HttpMethod.POST, permissionsPath(null), null, root, Map.of("key", key)).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(call(HttpMethod.POST, permissionsPath("other"), null, root, Map.of("key", "read")).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(call(HttpMethod.POST, permissionsPath("acme"), null, root, Map.of("key", "Not A Key!")).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        String roleId = createRole(root, "acme", unique("Linker"), "ADMIN", List.of(key));
        String permissionId = (String) created.getBody().get("id");
        assertThat(((Number) created.getBody().get("roleCount")).intValue()).isEqualTo(0);
        assertThat(status(HttpMethod.DELETE, permissionsPath("acme") + "/" + permissionId, null, root, null)).isEqualTo(HttpStatus.CONFLICT);
        assertThat(updateRole(root, "acme", roleId, Map.of("permissionKeys", List.of())).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(status(HttpMethod.DELETE, permissionsPath("acme") + "/" + permissionId, null, root, null)).isEqualTo(HttpStatus.OK);
        // A role can't link a permission nobody defined.
        assertThat(call(HttpMethod.POST, rolesPath("acme"), null, root, Map.of("name", unique("Ghost"), "permissionKeys", List.of("ghost.key"))).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void aPermissionCanBeRenamedAndRolesThatLinkItFollow() {
        String root = superadminToken();
        String tag = unique("rn").toLowerCase();
        String oldKey = tag + ".view";
        String newKey = tag + ".see";
        ResponseEntity<Map> created = call(HttpMethod.POST, permissionsPath(null), null, root, Map.of("key", oldKey, "description", "Old"));
        String id = (String) created.getBody().get("id");
        String roleId = createRole(root, null, tag + "Role", "ADMIN", List.of("read", oldKey));
        String projectRole = createRole(root, "acme", tag + "Mine", "USER", List.of(oldKey));

        // Description only.
        ResponseEntity<Map> described = call(HttpMethod.PATCH, permissionsPath(null) + "/" + id, null, root, Map.of("description", "Now described"));
        assertThat(described.getBody()).containsEntry("description", "Now described").containsEntry("key", oldKey);

        // Rename: the roles that link it, in every project, follow.
        ResponseEntity<Map> renamed = call(HttpMethod.PATCH, permissionsPath(null) + "/" + id, null, root, Map.of("key", newKey.toUpperCase()));
        assertThat(renamed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(renamed.getBody()).containsEntry("key", newKey).containsEntry("description", "Now described");
        assertThat(((Number) renamed.getBody().get("roleCount")).intValue()).isEqualTo(2);
        ResponseEntity<Map> roles = call(HttpMethod.GET, "/superadmin/roles?customer=acme&q=" + tag, null, root, null);
        for (Map item : (List<Map>) roles.getBody().get("items")) {
            List keys = (List) ((Map) item.get("role")).get("permissionKeys");
            assertThat(keys).contains(newKey).doesNotContain(oldKey);
        }

        // A holder's access follows the renamed permission too.
        String holder = unique("rho");
        assertThat(createUser(root, "acme", holder, roleId).getStatusCode()).isEqualTo(HttpStatus.OK);
        ResponseEntity<Map> verify = rest.postForEntity("/auth/verify", Map.of("token", token("acme", holder)), Map.class);
        assertThat((List) verify.getBody().get("permissions")).containsExactlyInAnyOrder("read", newKey);

        // Guards: taken names, bad names, built-ins, unknown ids, and non-superadmins.
        assertThat(status(HttpMethod.PATCH, permissionsPath(null) + "/" + id, null, root, Map.of("key", "read"))).isEqualTo(HttpStatus.CONFLICT);
        assertThat(status(HttpMethod.PATCH, permissionsPath(null) + "/" + id, null, root, Map.of("key", "Not A Name!"))).isEqualTo(HttpStatus.BAD_REQUEST);
        String readId = (String) ((Map) ((Map) ((List) call(HttpMethod.GET, "/superadmin/permissions?customer=*&q=read", null, root, null).getBody().get("items")).get(0)).get("permission")).get("id");
        assertThat(status(HttpMethod.PATCH, permissionsPath(null) + "/" + readId, null, root, Map.of("key", tag + ".readish"))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.PATCH, permissionsPath(null) + "/missing", null, root, Map.of("description", "x"))).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(status(HttpMethod.PATCH, permissionsPath(null) + "/" + id, null, token("acme", registerAdmin()), Map.of("description", "x"))).isEqualTo(HttpStatus.FORBIDDEN);
    }

    private String registerAdmin() {
        String name = unique("pa");
        register("acme", name, "ADMIN", true);
        return name;
    }

    @Test
    void superadminCreatesUsersWithARole() {
        String root = superadminToken();
        String adminRole = createRole(root, "acme", unique("Boss"), "ADMIN", List.of("read"));
        String userRole = createRole(root, "acme", unique("Plain"), "USER", List.of());
        String adminName = unique("cora");
        ResponseEntity<Map> admin = call(HttpMethod.POST, "/superadmin/projects/acme/users", null, root,
                Map.of("username", adminName.toUpperCase(), "email", adminName + "@acme.dev", "password", PASSWORD, "firstname", "Cora", "roleId", adminRole));
        assertThat(admin.getStatusCode()).isEqualTo(HttpStatus.OK);
        // Usernames are stored lower-case, like the other apps do; an admin-type role is approved on the spot.
        assertThat(admin.getBody()).containsEntry("username", adminName).containsEntry("activeProfile", "ADMIN").containsEntry("status", "APPROVED");
        assertThat(readStatus(token("acme", adminName))).isEqualTo(HttpStatus.OK);

        String userName = unique("pat");
        ResponseEntity<Map> user = createUser(root, "acme", userName, userRole);
        assertThat(user.getBody()).containsEntry("activeProfile", "USER");
        assertThat(login("acme", userName).getStatusCode()).isEqualTo(HttpStatus.OK);

        assertThat(createUser(root, "acme", userName, userRole).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void superadminCreateRejectsBadInput() {
        String root = superadminToken();
        String roleId = createRole(root, "acme", unique("Any"), "USER", List.of());
        String name = unique("bad");
        String path = "/superadmin/projects/acme/users";
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("username", name, "email", name + "@acme.dev", "password", PASSWORD))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("username", name, "email", name + "@acme.dev", "password", PASSWORD, "roleId", "nope"))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("username", name, "email", name + "@acme.dev", "password", "short", "roleId", roleId))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, "/superadmin/projects/security/users", null, root, Map.of("username", name, "email", name + "@acme.dev", "password", PASSWORD, "roleId", roleId))).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.POST, "/superadmin/projects/nope/users", null, root, Map.of("username", name, "email", name + "@acme.dev", "password", PASSWORD, "roleId", roleId))).isEqualTo(HttpStatus.BAD_REQUEST);
        // A role of another project isn't usable here.
        String otherRole = createRole(root, "other", unique("Theirs"), "USER", List.of());
        assertThat(status(HttpMethod.POST, path, null, root, Map.of("username", name, "email", name + "@acme.dev", "password", PASSWORD, "roleId", otherRole))).isEqualTo(HttpStatus.BAD_REQUEST);
        // A project admin's own token can't reach any of it.
        String projectAdmin = unique("pa");
        register("acme", projectAdmin, "ADMIN", true);
        assertThat(status(HttpMethod.POST, path, null, token("acme", projectAdmin), Map.of("username", name, "email", name + "@acme.dev", "password", PASSWORD, "roleId", roleId))).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(status(HttpMethod.POST, rolesPath("acme"), null, token("acme", projectAdmin), Map.of("name", unique("x"), "permissionKeys", List.of()))).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void roleListsPageAcrossTheDefaultsAndProjectsAndSearch() {
        String root = superadminToken();
        String tag = unique("Page");
        createRole(root, null, tag + "D", "USER", List.of());
        createRole(root, "acme", tag + "A", "USER", List.of());
        createRole(root, "other", tag + "O", "USER", List.of());

        String base = "/superadmin/roles?q=" + tag + "&size=2";
        ResponseEntity<Map> first = call(HttpMethod.GET, base + "&page=0", null, root, null);
        assertThat(((Number) first.getBody().get("total")).intValue()).isEqualTo(3);
        assertThat(roleNames((List) first.getBody().get("items"))).containsExactly("defaults/" + tag + "D", "acme/" + tag + "A");
        assertThat(roleNames((List) call(HttpMethod.GET, base + "&page=1", null, root, null).getBody().get("items"))).containsExactly("other/" + tag + "O");
        // One project shows the defaults plus its own; "*" is the defaults only.
        assertThat(roleNames((List) call(HttpMethod.GET, "/superadmin/roles?q=" + tag + "&customer=acme", null, root, null).getBody().get("items")))
                .containsExactly("defaults/" + tag + "D", "acme/" + tag + "A");
        assertThat(roleNames((List) call(HttpMethod.GET, "/superadmin/roles?q=" + tag + "&customer=*", null, root, null).getBody().get("items")))
                .containsExactly("defaults/" + tag + "D");
    }

    private static List<String> roleNames(List<?> items) {
        return items.stream().map(i -> (((Map) i).get("customer") == null ? "defaults" : ((Map) i).get("customer")) + "/" + ((Map) ((Map) i).get("role")).get("name")).map(String::valueOf).toList();
    }

    private ResponseEntity<Map> setProjectEnabled(String root, String customer, boolean enabled) {
        return call(HttpMethod.PATCH, "/superadmin/projects/" + customer + "/enabled", null, root, Map.of("enabled", enabled));
    }

    @Test
    void aDisabledProjectCannotAuthenticateButTheSuperadminCanStillManageIt() {
        String root = superadminToken();
        String admin = unique("dee");
        String member = unique("mel");
        register("other", member, "USER", false);
        register("other", admin, "ADMIN", true);
        String adminToken = token("other", admin);
        ResponseEntity<Map> session = call(HttpMethod.POST, "/auth/session/login", "other", null, Map.of("username", member, "password", PASSWORD));
        assertThat(session.getStatusCode()).isEqualTo(HttpStatus.OK);
        String memberToken = (String) session.getBody().get("token");

        try {
            ResponseEntity<Map> off = setProjectEnabled(root, "other", false);
            assertThat(off.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(off.getBody()).containsEntry("enabled", false);

            // Nothing in the project can sign in, sign up, refresh, verify or reach its admin routes.
            assertThat(login("other", member).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(status(HttpMethod.POST, "/auth/register", "other", null,
                    Map.of("username", unique("new"), "email", unique("n") + "@other.dev", "password", PASSWORD))).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(status(HttpMethod.POST, "/auth/session/login", "other", null, Map.of("username", member, "password", PASSWORD))).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(status(HttpMethod.GET, "/auth/me", null, memberToken, null)).isEqualTo(HttpStatus.FORBIDDEN);
            assertThat(status(HttpMethod.GET, "/admin/users", null, adminToken, null)).isEqualTo(HttpStatus.FORBIDDEN);
            ResponseEntity<Map> verify = rest.postForEntity("/auth/verify", Map.of("token", adminToken), Map.class);
            assertThat(verify.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
            assertThat(verify.getBody()).containsEntry("valid", false);

            // Other projects are untouched.
            assertThat(login("acme", unique("nobody")).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

            // The superadmin still sees and manages the disabled project.
            ResponseEntity<List> projects = callList("/superadmin/projects", root);
            assertThat(projects.getBody()).anySatisfy(p -> assertThat((Map) p).containsEntry("customer", "other").containsEntry("enabled", false));
            assertThat(status(HttpMethod.GET, "/superadmin/projects/other/users", null, root, null)).isEqualTo(HttpStatus.OK);
        } finally {
            assertThat(setProjectEnabled(root, "other", true).getStatusCode()).isEqualTo(HttpStatus.OK);
        }

        assertThat(login("other", member).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(status(HttpMethod.GET, "/admin/users", null, adminToken, null)).isEqualTo(HttpStatus.OK);
    }

    @Test
    void onlyASuperadminCanSwitchAProjectAndNotTheSecurityTenant() {
        String root = superadminToken();
        assertThat(setProjectEnabled(root, "security", false).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(setProjectEnabled(root, "nope", false).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(status(HttpMethod.PATCH, "/superadmin/projects/acme/enabled", null, root, Map.of())).isEqualTo(HttpStatus.BAD_REQUEST);
        String projectAdmin = unique("pa");
        register("acme", projectAdmin, "ADMIN", true);
        assertThat(status(HttpMethod.PATCH, "/superadmin/projects/acme/enabled", null, token("acme", projectAdmin), Map.of("enabled", false)))
                .isEqualTo(HttpStatus.FORBIDDEN);
        // Still enabled: the admin's own token keeps working.
        assertThat(status(HttpMethod.GET, "/admin/users", null, token("acme", projectAdmin), null)).isEqualTo(HttpStatus.OK);
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

    private static List<String> names(List<?> items) {
        return items.stream().map(i -> ((Map) i).get("customer") + "/" + ((Map) ((Map) i).get("user")).get("username")).map(String::valueOf).toList();
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
