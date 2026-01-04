package com.flipkart.es.entity;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AccessToken {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long accessTokenId;
    private String accessToken;
    private boolean accessTokenIsBlocked;
    private LocalDateTime accessTokenExpirationTime;
    
    @ManyToOne
    private User user;

}
