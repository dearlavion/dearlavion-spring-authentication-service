package com.dearlavion.authservice.user;

import com.dearlavion.authservice.user.model.AuthType;
import com.dearlavion.authservice.user.model.User;
import com.dearlavion.authservice.user.request.UserVoRequest;
import com.dearlavion.authservice.user.response.UserView;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserMapper {

    private final PasswordEncoder passwordEncoder;

    public User toEntity(UserVoRequest vo, AuthType type) {
        User user = new User();
        user.setUsername(vo.username());
        user.setEmail(vo.email());
        user.setPhone(vo.phone());
        user.setPassword(vo.password() != null ? passwordEncoder.encode(vo.password()) : null);
        // Already gated by the controller (privileged roles need X-Provision-Secret); defaults to USER.
        if (vo.activeProfile() != null) user.setActiveProfile(vo.activeProfile());
        user.setType(type);
        return user;
    }

    public void applyPatch(User user, UserVoRequest u) {
        if (u.firstname() != null) user.setFirstname(u.firstname());
        if (u.lastname() != null) user.setLastname(u.lastname());
        if (u.email() != null) user.setEmail(u.email());
        if (u.phone() != null) user.setPhone(u.phone());
        if (u.activeProfile() != null) user.setActiveProfile(u.activeProfile());
        if (u.image() != null) user.setImage(u.image());
    }

    public UserView toView(User user) {
        return new UserView(
                user.getUsername(), user.getEmail(), user.getFirstname(), user.getLastname(),
                user.getPhone(), user.getImage(), user.getActiveProfile(), user.isActive(),
                user.effectiveStatus(), user.effectivePermission()
        );
    }
}
