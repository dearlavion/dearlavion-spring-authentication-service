package com.dearlavion.authservice.user;

import com.dearlavion.authservice.security.AdminAuthFilter;
import com.dearlavion.authservice.security.AdminRequestUser;
import com.dearlavion.authservice.user.model.AuthType;
import com.dearlavion.authservice.user.model.Role;
import com.dearlavion.authservice.user.request.UserVoRequest;
import com.dearlavion.authservice.user.response.UserView;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/** Admin-only user management, scoped to the caller's own tenant (AdminAuthFilter resolves the
 * tenant from the caller's own signed JWT claim, never a client-supplied header). Backs the
 * frontend's /admin/users section. */
@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
public class AdminUserController {

    private final UserService userService;

    @GetMapping
    public List<UserView> list(@RequestAttribute(AdminAuthFilter.ADMIN_USER_ATTRIBUTE) AdminRequestUser admin) {
        return userService.listUsers(admin.customer()).stream().map(userService::toView).toList();
    }

    @GetMapping("/{username}")
    public UserView get(@RequestAttribute(AdminAuthFilter.ADMIN_USER_ATTRIBUTE) AdminRequestUser admin,
                         @PathVariable String username) {
        return userService.toView(userService.loadByUsernameOrThrow(admin.customer(), username));
    }

    /** Creates a regular user. The role in the body is ignored: handing out ADMIN/STAFF is a superadmin decision
     * (see SuperAdminController), otherwise any admin could mint more admins. */
    @PostMapping
    public UserView create(@RequestAttribute(AdminAuthFilter.ADMIN_USER_ATTRIBUTE) AdminRequestUser admin,
                            @RequestBody UserVoRequest body) {
        return userService.toView(userService.registerUser(admin.customer(), body.withActiveProfile(Role.USER), AuthType.SIMPLE));
    }

    @PatchMapping("/{username}")
    public UserView update(@RequestAttribute(AdminAuthFilter.ADMIN_USER_ATTRIBUTE) AdminRequestUser admin,
                            @PathVariable String username, @RequestBody UserVoRequest body) {
        return userService.toView(userService.updateUser(admin.customer(), username, body.withActiveProfile(null)));
    }

    @PatchMapping("/{username}/active")
    public UserView setActive(@RequestAttribute(AdminAuthFilter.ADMIN_USER_ATTRIBUTE) AdminRequestUser admin,
                               @PathVariable String username, @RequestBody Map<String, Boolean> body) {
        return userService.toView(userService.setActive(admin.customer(), username, Boolean.TRUE.equals(body.get("active"))));
    }

    @PatchMapping("/{username}/password")
    public Map<String, String> setPassword(@RequestAttribute(AdminAuthFilter.ADMIN_USER_ATTRIBUTE) AdminRequestUser admin,
                                            @PathVariable String username, @RequestBody Map<String, String> body) {
        userService.updatePassword(admin.customer(), username, body.get("password"));
        return Map.of("message", "Password updated");
    }
}
