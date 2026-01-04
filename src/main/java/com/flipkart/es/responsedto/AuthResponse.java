package com.flipkart.es.responsedto;

import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class AuthResponse {

    private String userId;
    private String username;
    private String role;
    private boolean isAuthenticated;
    private LocalDateTime accessExpiration;
    private LocalDateTime refreshExpiration;
    
}
