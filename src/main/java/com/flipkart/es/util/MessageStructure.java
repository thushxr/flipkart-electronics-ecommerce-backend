package com.flipkart.es.util;

import java.util.Date;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class MessageStructure {
 private String to;
 private String subject;
 private Date sentDate;
 private String text;
}
