package com.dearlavion.authservice.user;

import com.dearlavion.authservice.access.AccessService;
import com.dearlavion.authservice.common.exception.ConflictException;
import com.dearlavion.authservice.common.exception.NotFoundException;
import com.dearlavion.authservice.common.exception.UnauthorizedException;
import com.dearlavion.authservice.session.RefreshToken;
import com.dearlavion.authservice.superadmin.PermissionRole;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.model.ApprovalStatus;
import com.dearlavion.authservice.user.model.AuthType;
import com.dearlavion.authservice.user.model.Role;
import com.dearlavion.authservice.user.model.User;
import com.dearlavion.authservice.user.request.UserVoRequest;
import com.dearlavion.authservice.user.response.UserView;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Every lookup/write is scoped to a customer's own database, resolved via TenantService. */
@Service
@RequiredArgsConstructor
public class UserService {

    private final TenantService tenants;
    private final UserMapper mapper;
    private final PasswordEncoder passwordEncoder;
    private final AccessService access;

    public User findByUsername(String customer, String username) {
        MongoTemplate db = tenants.db(customer);
        return db.findOne(Query.query(Criteria.where("username").is(username)), User.class);
    }

    public User findByEmail(String customer, String email) {
        MongoTemplate db = tenants.db(customer);
        return db.findOne(Query.query(Criteria.where("email").is(email)), User.class);
    }

    public User loadByUsernameOrThrow(String customer, String username) {
        User user = findByUsername(customer, username);
        if (user == null) throw new NotFoundException("User not found");
        return user;
    }

    public User registerUser(String customer, UserVoRequest vo, AuthType type) {
        MongoTemplate db = tenants.db(customer);
        User user = mapper.toEntity(vo, type);
        try {
            return db.insert(user);
        } catch (DuplicateKeyException e) {
            throw new ConflictException("User already exists");
        }
    }

    public User updateUser(String customer, String username, UserVoRequest u) {
        User user = loadByUsernameOrThrow(customer, username);
        mapper.applyPatch(user, u);
        return tenants.db(customer).save(user);
    }

    public void updatePassword(String customer, String username, String newPassword) {
        User user = loadByUsernameOrThrow(customer, username);
        user.setPassword(passwordEncoder.encode(newPassword));
        tenants.db(customer).save(user);
    }

    /**
     * Sets a new password only if it hasn't changed since {@code user} was read (so a reset link can't be used twice), then
     * ends the user's cookie sessions. Returns false if it had changed.
     */
    public boolean replacePassword(String customer, User user, String newPassword) {
        MongoTemplate db = tenants.db(customer);
        long changed = db.updateFirst(
                Query.query(Criteria.where("id").is(user.getId()).and("password").is(user.getPassword())),
                new Update().set("password", passwordEncoder.encode(newPassword)), User.class).getModifiedCount();
        if (changed == 0) return false;
        db.updateMulti(Query.query(Criteria.where("userId").is(user.getId()).and("revokedAt").is(null)),
                new Update().set("revokedAt", Instant.now()), RefreshToken.class);
        return true;
    }

    /** Every user for a tenant — admin's Users list fetches once and filters/paginates
     * client-side, same convention as the store-engine admin lists. */
    public List<User> listUsers(String customer) {
        return tenants.db(customer).findAll(User.class);
    }

    /** Soft delete/restore — false blocks login (see SimpleAuthStrategy's active check) without
     * touching the document, so nothing elsewhere that references this user by id breaks. */
    public User setActive(String customer, String username, boolean active) {
        User user = loadByUsernameOrThrow(customer, username);
        user.setActive(active);
        return tenants.db(customer).save(user);
    }

    /** Throws 401 unless the account may sign in: approved by a superadmin (if it needed that) and not deactivated. */
    public void assertCanSignIn(User user) {
        if (!user.isApproved()) {
            throw new UnauthorizedException(user.effectiveStatus() == ApprovalStatus.PENDING
                    ? "Account is pending approval" : "Account access was not approved");
        }
        if (!user.isActive()) throw new UnauthorizedException("Account is deactivated");
    }

    public boolean canSignIn(User user) {
        return user != null && user.isActive() && user.isApproved();
    }

    /** An admin account waiting for a superadmin: ADMIN role, PENDING, no permission until approved. */
    public User registerAdminRequest(String customer, UserVoRequest vo) {
        MongoTemplate db = tenants.db(customer);
        User user = mapper.toEntity(vo.withActiveProfile(Role.ADMIN), AuthType.SIMPLE);
        user.setStatus(ApprovalStatus.PENDING);
        try {
            return db.insert(user);
        } catch (DuplicateKeyException e) {
            throw new ConflictException("User already exists");
        }
    }

    /**
     * An account created by a superadmin with a role. An admin-type role means approved on the spot (there is nobody left to
     * approve it); a user-type role is a plain user, like any registered one.
     */
    public User createAsSuperadmin(String customer, UserVoRequest vo, PermissionRole role) {
        MongoTemplate db = tenants.db(customer);
        User user = mapper.toEntity(vo.withActiveProfile(role.getAccountType()), AuthType.SIMPLE);
        // POST /auth/register never stores names (see UserMapper.toEntity); here the superadmin typed them, so keep them.
        if (vo.firstname() != null && !vo.firstname().isBlank()) user.setFirstname(vo.firstname().trim());
        if (vo.lastname() != null && !vo.lastname().isBlank()) user.setLastname(vo.lastname().trim());
        applyRole(user, role);
        try {
            return db.insert(user);
        } catch (DuplicateKeyException e) {
            throw new ConflictException("A user with this username or email already exists");
        }
    }

    /** Gives the user a role: it sets their access, and their legacy account type follows the role's. Assigning is also approving. */
    public User assignRole(String customer, String username, PermissionRole role) {
        User user = loadByUsernameOrThrow(customer, username);
        applyRole(user, role);
        return tenants.db(customer).save(user);
    }

    private static void applyRole(User user, PermissionRole role) {
        user.setRoleId(role.getId());
        user.setActiveProfile(role.getAccountType());
        user.setPermission(null);
        user.setStatus(role.getAccountType() == Role.ADMIN ? ApprovalStatus.APPROVED : null);
    }

    /** Rejecting or sending an admin request back to pending: the account keeps no role while it isn't approved. */
    public User holdRequest(String customer, String username, ApprovalStatus status) {
        User user = loadByUsernameOrThrow(customer, username);
        user.setStatus(status);
        user.setRoleId(null);
        user.setPermission(null);
        return tenants.db(customer).save(user);
    }

    public long countWithRole(String customer, String roleId) {
        return tenants.db(customer).count(Query.query(Criteria.where("roleId").is(roleId)), User.class);
    }

    /** A role's account type changed: everyone holding it follows, so their legacy ADMIN/USER stays in step. */
    public void syncAccountType(String customer, String roleId, Role type) {
        tenants.db(customer).updateMulti(Query.query(Criteria.where("roleId").is(roleId)),
                new Update().set("activeProfile", type)
                        .set("status", type == Role.ADMIN ? ApprovalStatus.APPROVED : null), User.class);
    }

    private static Criteria matching(List<Role> roles, ApprovalStatus status, String q) {
        List<Criteria> all = new ArrayList<>();
        if (roles != null && !roles.isEmpty()) all.add(Criteria.where("activeProfile").in(roles));
        if (status == ApprovalStatus.APPROVED) {
            // Documents written before approvals existed have no status and count as approved.
            all.add(Criteria.where("status").in(Arrays.asList(ApprovalStatus.APPROVED, null)));
        } else if (status != null) {
            all.add(Criteria.where("status").is(status));
        }
        if (q != null && !q.isBlank()) {
            String pattern = ".*" + Pattern.quote(q.trim()) + ".*";
            all.add(new Criteria().orOperator(
                    Criteria.where("username").regex(pattern, "i"),
                    Criteria.where("email").regex(pattern, "i"),
                    Criteria.where("firstname").regex(pattern, "i"),
                    Criteria.where("lastname").regex(pattern, "i")));
        }
        return all.isEmpty() ? new Criteria() : new Criteria().andOperator(all);
    }

    public long count(String customer, List<Role> roles, ApprovalStatus status) {
        return tenants.db(customer).count(Query.query(matching(roles, status, null)), User.class);
    }

    /** Filtered, paged list for the superadmin dashboard, ordered by username. */
    public List<User> search(String customer, List<Role> roles, ApprovalStatus status, String q, int page, int size) {
        return search(customer, roles, status, q, (long) page * size, size);
    }

    /** Same, from an arbitrary offset; the cross-project list pages through several tenants with it. */
    public List<User> search(String customer, List<Role> roles, ApprovalStatus status, String q, long skip, int limit) {
        Query query = Query.query(matching(roles, status, q)).with(Sort.by("username")).skip(skip).limit(limit);
        return tenants.db(customer).find(query, User.class);
    }

    public long countMatching(String customer, List<Role> roles, ApprovalStatus status, String q) {
        return tenants.db(customer).count(Query.query(matching(roles, status, q)), User.class);
    }

    public UserView toView(String customer, User user) {
        return toViews(customer, List.of(user)).get(0);
    }

    /** Views with each user's role name and permissions; the roles are read in one go, not per user. */
    public List<UserView> toViews(String customer, List<User> users) {
        List<String> roleIds = users.stream().map(User::getRoleId).filter(java.util.Objects::nonNull).distinct().toList();
        Map<String, PermissionRole> roles = access.findRoles(customer, roleIds);
        return users.stream().map(u -> {
            PermissionRole role = u.getRoleId() == null ? null : roles.get(u.getRoleId());
            return mapper.toView(u, role == null ? null : role.getName(), access.permissionsOf(u, role));
        }).toList();
    }
}
