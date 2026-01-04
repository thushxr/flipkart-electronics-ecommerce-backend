package com.flipkart.es.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.flipkart.es.entity.AccessToken;
import com.flipkart.es.entity.User;

public interface AccessTokenRepository extends JpaRepository<AccessToken, Long>{

    Optional<AccessToken> findByAccessToken(String at);

	List<AccessToken> findByAccessTokenExpirationTimeBefore(LocalDateTime now);

	Optional<AccessToken> findByAccessTokenAndAccessTokenIsBlocked(String at, boolean b);

	List<AccessToken> findByUserAndAccessTokenIsBlocked(User user, boolean isBlocked);

	List<AccessToken> findByUserAndAccessTokenIsBlockedAndAccessTokenNot(User user, boolean isBlocked, String accessToken);
    
}
