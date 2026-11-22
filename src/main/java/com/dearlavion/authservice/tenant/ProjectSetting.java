package com.dearlavion.authservice.tenant;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

/** Whether authentication is switched on for one project. Kept in the security tenant's database; a project with no document is enabled. */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "project_settings")
public class ProjectSetting {

    /** The customer slug. */
    @Id
    private String customer;
    private boolean enabled;
    private String updatedBy;
    private Instant updatedAt;
}
