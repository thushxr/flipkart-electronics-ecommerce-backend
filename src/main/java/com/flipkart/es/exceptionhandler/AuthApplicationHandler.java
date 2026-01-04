package com.flipkart.es.exceptionhandler;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.flipkart.es.exception.InvalidOTPException;
import com.flipkart.es.exception.InvalidUserRoleException;
import com.flipkart.es.exception.OTPExpiredException;
import com.flipkart.es.exception.RegistrationSessionExpiredException;
import com.flipkart.es.exception.UserLoggedInException;
import com.flipkart.es.exception.UserNotFoundException;
import com.flipkart.es.exception.UserNotLoggedInException;
import com.flipkart.es.exception.UserRegisteredException;

@RestControllerAdvice
public class AuthApplicationHandler {
    
    public ResponseEntity<Object> structure(HttpStatus status, String message, Object rootCause){
        return new ResponseEntity<Object>(Map.of("status", status.value(), "message", message, "root cause", rootCause), status);
    }

    @ExceptionHandler(UserRegisteredException.class)
    public ResponseEntity<Object> handlesUserVerifiedException(UserRegisteredException exception){
        return structure(HttpStatus.CREATED, exception.getMessage(), "the email you entered already exists");
    }

    @ExceptionHandler(InvalidUserRoleException.class)
    public ResponseEntity<Object> handleInvalidUserRoleException(InvalidUserRoleException exception){
        return structure(HttpStatus.BAD_REQUEST, exception.getMessage(), "user not found with the specified user role");
    }
    
    @ExceptionHandler(OTPExpiredException.class)
    public ResponseEntity<Object> handleOTPExpiredException(OTPExpiredException exception){
        return structure(HttpStatus.FORBIDDEN, exception.getMessage(), "otp session expired");
    }

    @ExceptionHandler(RegistrationSessionExpiredException.class)
    public ResponseEntity<Object> handleRegistrationSessionExpiredException(RegistrationSessionExpiredException exception){
        return structure(HttpStatus.BAD_REQUEST, exception.getMessage(), "registration session expired");
    }

    @ExceptionHandler(InvalidOTPException.class)
    public ResponseEntity<Object> handleInvalidOTPException(InvalidOTPException exception){
        return structure(HttpStatus.BAD_REQUEST, exception.getMessage(), "registration session expired");
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<Object> handleUsernameNotFoundException(UsernameNotFoundException exception){
        return structure(HttpStatus.NOT_FOUND, exception.getMessage(), "user name not found");
    }
    
    @ExceptionHandler(UserNotLoggedInException.class)
    public ResponseEntity<Object> handleUserNotLoggedInException(UserNotLoggedInException exception){
        return structure(HttpStatus.BAD_REQUEST, exception.getMessage(), "user not logged in");
    }
    
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<Object> handleUserNotFoundException(UserNotFoundException exception){
        return structure(HttpStatus.NOT_FOUND, exception.getMessage(), "user not found");
    }
    
    @ExceptionHandler(UserLoggedInException.class)
    public ResponseEntity<Object> handleUserLoggedInException(UserLoggedInException exception){
        return structure(HttpStatus.BAD_REQUEST, exception.getMessage(), "user already logged in");
    }
    
}
