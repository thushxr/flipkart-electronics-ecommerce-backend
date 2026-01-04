package com.flipkart.es.requestdto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AuthRequest {

    private String userEmail;
    private String userPassword;
    
}
