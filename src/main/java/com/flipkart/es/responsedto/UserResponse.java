package com.flipkart.es.responsedto;

import com.flipkart.es.enums.UserRole;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class UserResponse {
    private int userId;
    private String username;
    private String userEmail;
    private UserRole userRole;
    private boolean isEmailVerified;
    private boolean isDeleted;
}
