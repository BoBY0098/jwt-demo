package com.example.jwtdemo.service;

import com.example.jwtdemo.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Bridge between Spring Security and our JPA UserEntity.
 *
 * Why @Transactional(readOnly = true)?
 * - loadUserByUsername is called on every authenticated request (via Jwt filter → UserDetailsService
 *   on refresh, and also by AuthenticationManager on login).
 * - We only READ data → mark the transaction read-only so Hibernate can optimise
 *   (no dirty checking, possible read-only connection from the pool).
 * - The transaction also keeps the persistence context open long enough for the
 *   LAZY roles collection to be initialized if we used a JOIN FETCH.
 */
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * This is the method Spring Security calls.
     * We deliberately use the JOIN FETCH version so roles are present
     * and getAuthorities() never triggers a second query.
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsernameWithRoles(username)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found with username: " + username));
    }
}
