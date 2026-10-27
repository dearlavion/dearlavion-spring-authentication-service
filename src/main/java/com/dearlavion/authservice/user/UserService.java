package com.dearlavion.authservice.user;

import com.dearlavion.authservice.common.exception.ConflictException;
import com.dearlavion.authservice.common.exception.NotFoundException;
import com.dearlavion.authservice.common.exception.UnauthorizedException;
import com.dearlavion.authservice.tenant.TenantService;
import com.dearlavion.authservice.user.model.ApprovalStatus;
import com.dearlavion.authservice.user.model.AuthType;
import com.dearlavion.authservice.user.model.Permission;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/** Every lookup/write is scoped to a customer's own database, resolved via TenantService. */
@Service
@RequiredArgsConstructor
public class UserService {

    private final TenantService tenants;
    private final UserMapper mapper;
    private final PasswordEncoder passwordEncoder;

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

    /** Superadmin decision on an ADMIN/STAFF account. Approving needs a permission; anything else clears it. */
    public User decide(String customer, String username, ApprovalStatus status, Permission permission) {
        User user = loadByUsernameOrThrow(customer, username);
        user.setStatus(status);
        user.setPermission(status == ApprovalStatus.APPROVED ? permission : null);
        return tenants.db(customer).save(user);
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
        Query query = Query.query(matching(roles, status, q))
                .with(Sort.by("username")).skip((long) page * size).limit(size);
        return tenants.db(customer).find(query, User.class);
    }

    public long countMatching(String customer, List<Role> roles, ApprovalStatus status, String q) {
        return tenants.db(customer).count(Query.query(matching(roles, status, q)), User.class);
    }

    public UserView toView(User user) {
        return mapper.toView(user);
    }
}
