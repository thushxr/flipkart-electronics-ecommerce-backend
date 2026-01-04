package com.flipkart.es.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserRegisteredException extends RuntimeException{
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String message;
}
