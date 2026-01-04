package com.flipkart.es.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.flipkart.es.requestdto.AuthRequest;
import com.flipkart.es.requestdto.OtpModel;
import com.flipkart.es.requestdto.UserRequest;
import com.flipkart.es.responsedto.AuthResponse;
import com.flipkart.es.responsedto.UserResponse;
import com.flipkart.es.service.AuthService;
import com.flipkart.es.util.ResponseStructure;
import com.flipkart.es.util.SimpleResponseStructure;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@RestController
@AllArgsConstructor
@RequestMapping("/api/v1")
public class AuthController {

	private AuthService authService;

	@PostMapping("/users/register")
	public ResponseEntity<ResponseStructure<UserResponse>> registerUser(@RequestBody UserRequest userRequest) {
		return authService.registerUser(userRequest);
	}

	@PostMapping("/verify-otp")
	public ResponseEntity<ResponseStructure<UserResponse>> verifyOtp(@RequestBody OtpModel otpModel) {
		return authService.verifyOtp(otpModel);
	}

	@PostMapping("/login")
	public ResponseEntity<ResponseStructure<AuthResponse>> login(
			@CookieValue(name = "at", required = false) String accessToken,
			@CookieValue(name = "rt", required = false) String refreshToken, @RequestBody AuthRequest authRequest,
			HttpServletResponse httpServletResponse) {
		return authService.login(accessToken, refreshToken, authRequest, httpServletResponse);
	}

	@PreAuthorize("hasAuthority('CUSTOMER') OR hasAuthority('SELLER')")
	@PutMapping("/logout")
	public ResponseEntity<SimpleResponseStructure> logout(
			@CookieValue(name = "at", required = false) String accessToken,
			@CookieValue(name = "rt", required = false) String refreshToken, HttpServletResponse response) {
		return authService.logout(accessToken, refreshToken, response);
	}

	@PreAuthorize("hasAuthority('CUSTOMER') OR hasAuthority('SELLER')")
	@PutMapping("/revoke-all")
	public ResponseEntity<SimpleResponseStructure> revokeAll(HttpServletResponse response) {
		return authService.revokeAll(response);
	}

	@PreAuthorize("hasAuthority('CUSTOMER') OR hasAuthority('SELLER')")
	@PutMapping("/revoke-others")
	public ResponseEntity<SimpleResponseStructure> revokeOthers(
			@CookieValue(name = "at", required = false) String accessToken,
			@CookieValue(name = "rt", required = false) String refreshToken) {
		return authService.revokeOthers(accessToken, refreshToken);
	}

//	@PreAuthorize("hasAuthority('CUSTOMER') OR hasAuthority('SELLER')")
	@PutMapping("/refresh")
	public ResponseEntity<SimpleResponseStructure> refreshLogin(
			@CookieValue(name = "at", required = false) String accessToken,
			@CookieValue(name = "rt", required = false) String refreshToken, HttpServletResponse response) {
		return authService.refreshLogin(accessToken, refreshToken, response);
	}

}
