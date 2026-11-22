package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.user.model.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * A role ("Admin", "Simple User", "Guest") that links permissions by key. A <em>default</em> role lives in the security
 * tenant's database and every project can assign it; a project can also define its own in its database. Users hold a role by
 * id and their access follows it live: editing the role changes everyone who has it. {@code accountType} is what the legacy
 * {@code activeProfile} (ADMIN or USER) of a holder is derived from, so consumers of /auth/verify keep working.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "roles")
public class PermissionRole {

    @Id
    private String id;
    private String name;
    private String description;
    private Role accountType;
    private List<String> permissionKeys = new ArrayList<>();
    /** Admin and User ship with the service: they can't be deleted, renamed or change account type, but their permissions can be edited. */
    private boolean builtIn;
    private String createdBy;
    private Instant createdAt;
}
