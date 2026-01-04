package com.flipkart.es.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.flipkart.es.entity.User;

public interface UserRepository extends JpaRepository<User, Integer>{

	boolean existsByUserEmail(String userEmail);

    Optional<User> findByUsername(String username);

    List<User> findByIsEmailVerified(boolean isEmailVerified);

}
