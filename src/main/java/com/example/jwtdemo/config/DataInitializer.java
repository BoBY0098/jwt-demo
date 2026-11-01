package com.example.jwtdemo.config;

import com.example.jwtdemo.entity.ProfileStatus;
import com.example.jwtdemo.entity.RoleEntity;
import com.example.jwtdemo.entity.UserEntity;
import com.example.jwtdemo.repository.RoleRepository;
import com.example.jwtdemo.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Runs once on application startup and seeds the demo users + roles.
 * Why ApplicationRunner instead of @PostConstruct?
 * - Guarantees the ApplicationContext (and therefore all beans) is fully ready.
 * - We can inject repositories and PasswordEncoder safely.
 */
@Component
public class DataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(RoleRepository roleRepository,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        // 1. Roles
        RoleEntity userRole = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(new RoleEntity("ROLE_USER")));

        RoleEntity adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseGet(() -> roleRepository.save(new RoleEntity("ROLE_ADMIN")));

        log.info("Roles ready: {}, {}", userRole.getName(), adminRole.getName());

        // 2. Demo users (same credentials as the old in-memory version)
        if (!userRepository.existsByUsername("user")) {
            UserEntity user = new UserEntity("user",
                    passwordEncoder.encode("password"),
                    "user@example.com");
            user.setProfileStatus(ProfileStatus.ACTIVE);
            user.addRole(userRole);
            userRepository.save(user);
            log.info("Created demo user: user / password");
        }

        if (!userRepository.existsByUsername("admin")) {
            UserEntity admin = new UserEntity("admin",
                    passwordEncoder.encode("admin123"),
                    "admin@example.com");
            admin.setProfileStatus(ProfileStatus.ACTIVE);
            admin.addRole(userRole);
            admin.addRole(adminRole);
            userRepository.save(admin);
            log.info("Created demo user: admin / admin123");
        }
    }
}
