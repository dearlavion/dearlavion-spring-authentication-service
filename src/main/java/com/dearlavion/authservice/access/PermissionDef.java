package com.dearlavion.authservice.access;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

/**
 * A permission a role can link, identified by its unique name, e.g. {@code orders.read} (stored and sent as {@code key}). A <em>default</em> permission lives in the security tenant's
 * database and applies to every project; a project can add its own in its database. {@code read} and {@code modify} are built in
 * (they gate /admin/** on this service) and can't be removed.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "permissions")
public class PermissionDef {

    @Id
    private String id;
    private String key;
    private String description;
    private boolean builtIn;
    private String createdBy;
    private Instant createdAt;
}
