package com.flipkart.es.security;

import java.io.IOException;
import java.util.Optional;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.flipkart.es.entity.AccessToken;
import com.flipkart.es.repository.AccessTokenRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@AllArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

	private AccessTokenRepository accessTokenRepository;
	private JWTService jwtService;
	private CustomUserDetailService customUserDetailService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String at = "";
		String rt = "";
		String username = null;
		Cookie[] cookies = request.getCookies();
		
		if(cookies != null) {

			for(Cookie cookie : cookies) {
				if(cookie.getName().equals("at")) at = cookie.getValue();
				if(cookie.getName().equals("rt")) rt = cookie.getValue();
			}

			if(at != null && rt != null) {
				Optional<AccessToken> accessToken = accessTokenRepository.findByAccessTokenAndAccessTokenIsBlocked(at, false);

				if(accessToken == null) throw new RuntimeException("dosen't exist");
				else {
					log.info("Authenticating the token...");
					username = jwtService.extractUsername(at);
					log.info(username);

					if(username == null) throw new RuntimeException("failed to authenticate");

					UserDetails userDetails = customUserDetailService.loadUserByUsername(username);
					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = 
							new UsernamePasswordAuthenticationToken(username, null, userDetails.getAuthorities());

					usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetails(request));
					SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
					log.info("Aunthenicated successfully");
				}
			}
		}

		filterChain.doFilter(request, response);

	}

}
