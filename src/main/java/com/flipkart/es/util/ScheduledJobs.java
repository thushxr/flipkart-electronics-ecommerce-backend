package com.flipkart.es.util;

import java.time.LocalDateTime;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.flipkart.es.repository.AccessTokenRepository;
import com.flipkart.es.repository.RefreshTokenRepository;

import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class ScheduledJobs {

	private AccessTokenRepository accessTokenRepository;
	private RefreshTokenRepository refreshTokenRepository;

	@Scheduled(cron = "0 0 0 * * *")
	public void deleteExpiredTokens() {

		accessTokenRepository
				.deleteAll(accessTokenRepository.findByAccessTokenExpirationTimeBefore(LocalDateTime.now()));
		refreshTokenRepository
				.deleteAll(refreshTokenRepository.findByRefreshTokenExpirationTimeBefore(LocalDateTime.now()));
	}

}
