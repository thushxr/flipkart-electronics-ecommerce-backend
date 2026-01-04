package com.flipkart.es.serviceimpl;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Random;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.flipkart.es.cache.CacheStore;
import com.flipkart.es.entity.AccessToken;
import com.flipkart.es.entity.Customer;
import com.flipkart.es.entity.RefreshToken;
import com.flipkart.es.entity.Seller;
import com.flipkart.es.entity.User;
import com.flipkart.es.enums.UserRole;
import com.flipkart.es.exception.InvalidOTPException;
import com.flipkart.es.exception.InvalidUserRoleException;
import com.flipkart.es.exception.OTPExpiredException;
import com.flipkart.es.exception.RegistrationSessionExpiredException;
import com.flipkart.es.exception.UserLoggedInException;
import com.flipkart.es.exception.UserNotFoundException;
import com.flipkart.es.exception.UserNotLoggedInException;
import com.flipkart.es.exception.UserRegisteredException;
import com.flipkart.es.repository.AccessTokenRepository;
import com.flipkart.es.repository.CustomerRepository;
import com.flipkart.es.repository.RefreshTokenRepository;
import com.flipkart.es.repository.SellerRepository;
import com.flipkart.es.repository.UserRepository;
import com.flipkart.es.requestdto.AuthRequest;
import com.flipkart.es.requestdto.OtpModel;
import com.flipkart.es.requestdto.UserRequest;
import com.flipkart.es.responsedto.AuthResponse;
import com.flipkart.es.responsedto.UserResponse;
import com.flipkart.es.security.JWTService;
import com.flipkart.es.service.AuthService;
import com.flipkart.es.util.CookieManager;
import com.flipkart.es.util.MessageStructure;
import com.flipkart.es.util.ResponseEntityProxy;
import com.flipkart.es.util.ResponseStructure;
import com.flipkart.es.util.SimpleResponseStructure;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class AuthServiceImpl implements AuthService {

	@Value("${myapp.access.expiry}")
	private long accessTokenExpiryInSeconds;
	@Value("${myapp.refresh.expiry}")
	private long refreshTokenExpiryInSeconds;

	private UserRepository userRepository;
	private SellerRepository sellerRepository;
	private CustomerRepository customerRepository;
	private PasswordEncoder passwordEncoder;
	private CacheStore<String> otpCacheStore;
	private CacheStore<User> userCacheStore;
	private JavaMailSender javaMailSender;
	private AuthenticationManager authenticationManager;
	private CookieManager cookieManager;
	private JWTService jwtService;
	private AccessTokenRepository accessTokenRepository;
	private RefreshTokenRepository refreshTokenRepository;

	public AuthServiceImpl(UserRepository userRepository,
			SellerRepository sellerRepository,
			CustomerRepository customerRepository,
			PasswordEncoder passwordEncoder,
			CacheStore<String> otpCacheStore,
			CacheStore<User> userCacheStore,
			JavaMailSender javaMailSender,
			AuthenticationManager authenticationManager,
			CookieManager cookieManager,
			JWTService jwtService,
			AccessTokenRepository accessTokenRepository,
			RefreshTokenRepository refreshTokenRepository) {
		this.userRepository = userRepository;
		this.sellerRepository = sellerRepository;
		this.customerRepository = customerRepository;
		this.passwordEncoder = passwordEncoder;
		this.otpCacheStore = otpCacheStore;
		this.userCacheStore = userCacheStore;
		this.javaMailSender = javaMailSender;
		this.authenticationManager = authenticationManager;
		this.cookieManager = cookieManager;
		this.jwtService = jwtService;
		this.accessTokenRepository = accessTokenRepository;
		this.refreshTokenRepository = refreshTokenRepository;
	}

	public User saveUser(User user) {

		user.setEmailVerified(true);

		if (user.getUserRole().equals(UserRole.SELLER)) {
			Seller seller = (Seller) user;
			return sellerRepository.save(seller);
		} else {
			Customer customer = (Customer) user;
			return customerRepository.save(customer);
		}
	}


	// mapping
	@SuppressWarnings("unchecked")
	private <T extends User> T mapToRespectiveType(UserRequest userRequest) {

		User user = null;
		switch (UserRole.valueOf(userRequest.getUserRole().toUpperCase())) {
			case SELLER -> {
				user = new Seller();
			}
			case CUSTOMER -> {
				user = new Customer();
			}
			default -> throw new InvalidUserRoleException("User not found with the specified role");
		}

		user.setUsername(userRequest.getUserEmail().split("@")[0].toString());
		user.setUserEmail(userRequest.getUserEmail());
		user.setUserPassword(passwordEncoder.encode(userRequest.getUserPassword()));
		user.setUserRole(UserRole.valueOf(userRequest.getUserRole().toUpperCase()));
		user.setEmailVerified(false);
		user.setDeleted(false);

		return (T) user;

	}

	private UserResponse mapToUserResponse(User user) {

		return UserResponse.builder()
				.userId(user.getUserId())
				.userEmail(user.getUserEmail())
				.username(user.getUsername())
				.userRole(user.getUserRole())
				.isDeleted(user.isDeleted())
				.isEmailVerified(user.isEmailVerified())
				.build();
	}

	private AuthResponse mapToAuthResponse(User user) {
		return AuthResponse.builder()
				.userId(String.valueOf(user.getUserId()))
				.username(user.getUsername())
				.role(user.getUserRole().name())
				.isAuthenticated(true)
				.accessExpiration(LocalDateTime.now().plusSeconds(accessTokenExpiryInSeconds))
				.refreshExpiration(LocalDateTime.now().plusSeconds(refreshTokenExpiryInSeconds))
				.build();
	}


	
	private void blockRefreshToken(List<RefreshToken> refreshTokens) {
		refreshTokens.forEach(refreshToken -> {
			refreshToken.setRefreshTokenIsBlocked(true);
			refreshTokenRepository.save(refreshToken);
		});
	}

	private void blockAccessToken(List<AccessToken> accessTokens) {
		accessTokens.forEach(accessToken -> {
			accessToken.setAccessTokenIsBlocked(true);
			accessTokenRepository.save(accessToken);
		});
	}
	
	
	

	private String generateOTP() {
		return String.valueOf(new Random().nextInt(111111, 999999));
	}

	private void sendOtpToMail(User user, String otp) throws MessagingException {
		sendMail(MessageStructure.builder()
				.to(user.getUserEmail())
				.subject("complete your registration to flipkart electronics")
				.sentDate(new Date())
				.text(
						"<p>Hello " + user.getUsername() + "</p><br>"
								+ "<h1><strong style='color: rgb(50, 93, 249);''>Verification mail</strong></h1>"
								+ "<p>Welcome to flipkart electronics</p>"
								+ "<p>Complete your registration using the OTP</p>"
								+ "<br>"
								+ "<h1><strong style='color: rgb(50, 93, 249);''> " + otp + "</strong></h1>"
								+ "<br>"
								+ "<p>Do not share this otp with anyone</p>"
								+ "<p>If you didn't request for this otp, you can igonre this mail</p>"
								+ "<br>"
								+ "<p>with best regards</p>"
								+ "<p>flipkart electronics team</p>")
				.build());
	}

	private void sendWelcomeMessage(User user) throws MessagingException {
		sendMail(MessageStructure.builder()
				.to(user.getUserEmail())
				.subject("Welcome to flipkart electronics")
				.sentDate(new Date())
				.text(
						"<h1><strong style='color: rgb(50, 93, 249);'> Welcome onboard " + user.getUsername()
								+ " </strong></h1>"
								+ "<h2> Shop with us for you and for your loved ones</h2>"
								+ "<br>"
								+ "<p>Notice: We do not call for verification or bank/payment related issues</p>"
								+ "<p>Please be aware of the fraudsters</p>"
								+ "<br>"
								+ "<h2>Happy shopping</h2>"
								+ "<p>with best regards</p>"
								+ "<p>flipkart electronics team</p>")
				.build());

	}

	@Async
	private void sendMail(MessageStructure messageStructure) throws MessagingException {
		MimeMessage mimeMessage = javaMailSender.createMimeMessage();
		MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, false);
		helper.setTo(messageStructure.getTo());
		helper.setSubject(messageStructure.getSubject());
		helper.setSentDate(messageStructure.getSentDate());
		helper.setText(messageStructure.getText(), true);
		javaMailSender.send(mimeMessage);
	}

	private void grantAccess(HttpServletResponse response, User user) {
		// generating access and refresh token
		String accessToken = jwtService.generateAccessToken(user.getUsername());
		String refreshToken = jwtService.generateRefreshToken(user.getUsername());

		// adding access and refresh tokens cookies to the response
		response.addCookie(cookieManager.cookieConfigure(new Cookie("at", accessToken), accessTokenExpiryInSeconds));
		response.addCookie(cookieManager.cookieConfigure(new Cookie("rt", refreshToken), refreshTokenExpiryInSeconds));

		// saving access token to DB
		accessTokenRepository.save(AccessToken.builder()
				.accessToken(accessToken)
				.accessTokenIsBlocked(false)
				.accessTokenExpirationTime(LocalDateTime.now().plusSeconds(accessTokenExpiryInSeconds))
				.user(user)
				.build());

		refreshTokenRepository.save(RefreshToken.builder()
				.refreshToken(refreshToken)
				.refreshTokenIsBlocked(false)
				.refreshTokenExpirationTime(LocalDateTime.now().plusSeconds(refreshTokenExpiryInSeconds))
				.user(user)
				.build());

	}

	@Override
	public ResponseEntity<ResponseStructure<UserResponse>> registerUser(UserRequest userRequest) {

		try {
			if (!EnumSet.allOf(UserRole.class).contains(UserRole.valueOf(userRequest.getUserRole().toUpperCase()))) {
			}
		} catch (Exception e) {
			throw new InvalidUserRoleException("user role invalid");
		}

		if (userRepository.existsByUserEmail(userRequest.getUserEmail())) {
			throw new UserRegisteredException("user already registered");
		}

		User user = mapToRespectiveType(userRequest);

		String otp = generateOTP();
		userCacheStore.add(userRequest.getUserEmail(), user);
		otpCacheStore.add(userRequest.getUserEmail(), otp);
		
		try {
			sendOtpToMail(user, otp);
		} catch (MessagingException e) {
			log.error("the email address dosen't exist");
		}

		return ResponseEntityProxy.setResponseStructure(HttpStatus.ACCEPTED,
				"Please verify the otp sent to the email " + otp,
				mapToUserResponse(user));
	}

	@Override
	public ResponseEntity<ResponseStructure<UserResponse>> verifyOtp(OtpModel otpModel) {

		String otpFromCache = otpCacheStore.get(otpModel.getUserEmail());
		User user = userCacheStore.get(otpModel.getUserEmail());

		if (otpFromCache == null)
			throw new OTPExpiredException("otp expired");

		if (user == null)
			throw new RegistrationSessionExpiredException("registration session expired");

		if (!otpFromCache.equals(otpModel.getUserOTP()))
			throw new InvalidOTPException("invalid otp exception");

		user = saveUser(user);
		try {
			sendWelcomeMessage(user);
		} catch (MessagingException e) {
			log.error("something went wrong in send welcome message");
		}

		return ResponseEntityProxy.setResponseStructure(HttpStatus.CREATED,
				"user registered successfully", mapToUserResponse(user));

	}

	@Override
	public ResponseEntity<ResponseStructure<AuthResponse>> login(String accessToken, String refreshToken, AuthRequest authRequest,
			HttpServletResponse httpServletResponse) {
		
		if(accessToken != null && refreshToken != null) throw new UserLoggedInException("user already logged In");
		
		String username = authRequest.getUserEmail().split("@")[0];

		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,
				authRequest.getUserPassword());

		Authentication authenticate = authenticationManager.authenticate(token);

		if (!authenticate.isAuthenticated())
			throw new UsernameNotFoundException("failed to authenticate the user");

		// generate the cookies and authresponse and return it to client
		return userRepository.findByUsername(username)
				.map(user -> {
					grantAccess(httpServletResponse, user);

					return ResponseEntityProxy.setResponseStructure(HttpStatus.OK,
							"successfully logged in",
							mapToAuthResponse(user));
				})
				.orElseThrow(() -> new UsernameNotFoundException("user name not found"));

	}

	@Override
	public  ResponseEntity<SimpleResponseStructure> logout(String accessToken, String refreshToken, HttpServletResponse response) {
		
		if(accessToken == null && refreshToken == null) throw new UserNotLoggedInException("user not logged in");

		accessTokenRepository.findByAccessToken(accessToken)
		.ifPresent(accessTokenObj -> {
			accessTokenObj.setAccessTokenIsBlocked(true);
			accessTokenRepository.save(accessTokenObj);
		});
		
		refreshTokenRepository.findByRefreshToken(refreshToken)
		.ifPresent(refreshTokenObj -> {
			refreshTokenObj.setRefreshTokenIsBlocked(true);
			refreshTokenRepository.save(refreshTokenObj);
		});
		
		response.addCookie(cookieManager.invalidateCookie(new Cookie("at", "")));
		response.addCookie(cookieManager.invalidateCookie(new Cookie("rt", "")));
		
		return ResponseEntityProxy.setSimpleResponseStructure(HttpStatus.OK, "logged out successfully");

	}

	@Override
	public  ResponseEntity<SimpleResponseStructure> revokeAll(HttpServletResponse response) {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		if(username.equals("anonymousUser")) throw new UsernameNotFoundException("username not found");
		
		return userRepository.findByUsername(username)
		.map(user -> {
			
			blockAccessToken(accessTokenRepository.findByUserAndAccessTokenIsBlocked(user, false));
			blockRefreshToken(refreshTokenRepository.findByUserAndRefreshTokenIsBlocked(user, false));
			
			response.addCookie(cookieManager.invalidateCookie(new Cookie("at", "")));
			response.addCookie(cookieManager.invalidateCookie(new Cookie("rt", "")));
			
			return ResponseEntityProxy.setSimpleResponseStructure(HttpStatus.OK, "revoked all devices");
		})
		.orElseThrow(() -> new UsernameNotFoundException("username not found"));
	}

	

	@Override
	public  ResponseEntity<SimpleResponseStructure> revokeOthers(String accessToken, String refreshToken) {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		if(username == null) throw new UsernameNotFoundException("username not found");
		
		return userRepository.findByUsername(username)
		.map(user -> {
			blockAccessToken(accessTokenRepository.findByUserAndAccessTokenIsBlockedAndAccessTokenNot(user, false, accessToken));
			blockRefreshToken(refreshTokenRepository.findByUserAndRefreshTokenIsBlockedAndRefreshTokenNot(user, false, refreshToken));
			
			return ResponseEntityProxy.setSimpleResponseStructure(HttpStatus.OK, "revoked all other devices");
		})
		.orElseThrow(() -> new UsernameNotFoundException("username not found"));
	}

	@Override
	public ResponseEntity<SimpleResponseStructure> refreshLogin(String accessToken, String refreshToken, HttpServletResponse response) {	
		
		if(accessToken != null) {
			accessTokenRepository.findByAccessToken(accessToken)
			.map(at -> {
				at.setAccessTokenIsBlocked(true);
				return accessTokenRepository.save(at);
			});
		}
		
		if(refreshToken == null) throw new UserNotLoggedInException("user logged out");
		
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		if(username.equals("anonymousUser")) throw new UsernameNotFoundException("username not found");
		
		return userRepository.findByUsername(username)
		.map(user -> {
			grantAccess(response, user);
			
			refreshTokenRepository.findByRefreshToken(refreshToken)
			.map(rt -> {
				rt.setRefreshTokenIsBlocked(true);
				return refreshTokenRepository.save(rt);
				
			})
			.orElseThrow(() -> new UserNotFoundException("user not found"));
			
			return ResponseEntityProxy.setSimpleResponseStructure(HttpStatus.OK, "token successfuly generated");
		})
		.orElseThrow(() -> new UsernameNotFoundException("user name not found"));
		
	}

	
}