package com.example.jwtdemo.service;

import com.example.jwtdemo.entity.ProfileStatus;
import com.example.jwtdemo.entity.RoleEntity;
import com.example.jwtdemo.entity.UserEntity;
import com.example.jwtdemo.repository.RoleRepository;
import com.example.jwtdemo.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Application service for user management.
 *
 * Rules of thumb for @Transactional:
 * 1. Put it on the service layer (not on repositories or controllers).
 * 2. Use readOnly = true for pure read methods → performance + clarity.
 * 3. One business use-case = one transactional method.
 * 4. Never catch-and-ignore exceptions inside a @Transactional method
 *    if you still want the transaction to roll back.
 */
@Service
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Read-only method – Hibernate skips dirty checking.
     * Uses the JOIN FETCH query → only 1 SQL statement even though we touch roles.
     */
    @Transactional(readOnly = true)
    public List<UserEntity> findAllUsersWithRoles() {
        return userRepository.findAllWithRoles();
    }

    /**
     * Another read-only example.
     */
    @Transactional(readOnly = true)
    public UserEntity findByUsername(String username) {
        return userRepository.findByUsernameWithRoles(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }

    /**
     * Write method – default @Transactional (readOnly=false).
     * If any exception propagates, the whole transaction rolls back.
     */
    @Transactional
    public UserEntity register(String username, String rawPassword, String email) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already taken");
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already taken");
        }

        RoleEntity userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not seeded"));

        UserEntity user = new UserEntity(username,
                passwordEncoder.encode(rawPassword),
                email);
        user.setProfileStatus(ProfileStatus.PENDING_VERIFICATION);
        user.addRole(userRole);

        return userRepository.save(user);
    }

    /**
     * Change profile status – classic write use-case.
     */
    @Transactional
    public void changeProfileStatus(String username, ProfileStatus newStatus) {
        UserEntity user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
        user.setProfileStatus(newStatus);
        // no need to call save() – the entity is managed inside the transaction
        // and Hibernate will detect the dirty field on flush/commit
    }
}
