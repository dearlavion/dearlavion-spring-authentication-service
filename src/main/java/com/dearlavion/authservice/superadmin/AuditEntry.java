package com.dearlavion.authservice.superadmin;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

/** One superadmin action, kept in the security tenant's database: who did what to whom, in which project. */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "audit_log")
public class AuditEntry {

    @Id
    private String id;
    private Instant at;
    private String actor;
    private String action;
    private String customer;
    private String target;
    private String before;
    private String after;
}
