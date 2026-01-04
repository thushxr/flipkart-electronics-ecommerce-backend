package com.flipkart.es.service;

import org.springframework.http.ResponseEntity;

import com.flipkart.es.requestdto.AuthRequest;
import com.flipkart.es.requestdto.OtpModel;
import com.flipkart.es.requestdto.UserRequest;
import com.flipkart.es.responsedto.AuthResponse;
import com.flipkart.es.responsedto.UserResponse;
import com.flipkart.es.util.ResponseStructure;
import com.flipkart.es.util.SimpleResponseStructure;

import jakarta.servlet.http.HttpServletResponse;

public interface AuthService {

	ResponseEntity<ResponseStructure<UserResponse>> registerUser(UserRequest userRequest);

	ResponseEntity<ResponseStructure<UserResponse>> verifyOtp(OtpModel otpModel);

	ResponseEntity<ResponseStructure<AuthResponse>> login(String accessToken, String refreshToken, AuthRequest authRequest,
			HttpServletResponse httpServletResponse);

	ResponseEntity<SimpleResponseStructure> logout(String accessToken, String refreshToken, HttpServletResponse response);

	 ResponseEntity<SimpleResponseStructure> revokeAll(HttpServletResponse response);

	 ResponseEntity<SimpleResponseStructure> revokeOthers(String accessToken, String refreshToken);

	ResponseEntity<SimpleResponseStructure> refreshLogin(String accessToken, String refreshToken, HttpServletResponse response);

}
