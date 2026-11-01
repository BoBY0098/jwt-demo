package com.example.jwtdemo.entity;


public enum ProfileStatus {
    ACTIVE,                 // normal working account
    PENDING_VERIFICATION,   // registered but email not confirmed yet
    SUSPENDED,              // temporarily blocked by admin
    DELETED                 // soft-deleted (we keep the row for audit)
}
