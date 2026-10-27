package com.dearlavion.authservice.superadmin;

import com.dearlavion.authservice.user.model.Permission;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

/**
 * A named permission preset ("Content editor" = READ + MODIFY) a superadmin defines for one project. Kept in that project's
 * own database like its users. Applying a role copies its permission onto the admin; there is no live link, so editing or
 * deleting a role never changes anyone's access.
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "roles")
public class PermissionRole {

    @Id
    private String id;
    private String name;
    private String description;
    private Permission permission;
    private String createdBy;
    private Instant createdAt;
}
