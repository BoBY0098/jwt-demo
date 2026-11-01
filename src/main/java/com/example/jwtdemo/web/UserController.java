package com.example.jwtdemo.web;

import com.example.jwtdemo.entity.ProfileStatus;
import com.example.jwtdemo.entity.UserEntity;
import com.example.jwtdemo.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/api/users")
@Tag(name = "Users", description = "User management (demo)")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    @Operation(summary = "List all users with their roles (JOIN FETCH – no N+1)")
    @PreAuthorize("hasRole('ADMIN')")
    public List<Map<String, Object>> listUsers() {
        return userService.findAllUsersWithRoles().stream()
                .map(this::toMap)
                .toList();
    }

    @GetMapping("/{username}")
    @Operation(summary = "Get one user with roles")
    @PreAuthorize("hasRole('ADMIN') or #username == authentication.name")
    public Map<String, Object> getUser(@PathVariable String username) {
        return toMap(userService.findByUsername(username));
    }

    @PatchMapping("/{username}/status")
    @Operation(summary = "Change profile status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> changeStatus(@PathVariable String username,
                                             @RequestParam ProfileStatus status) {
        userService.changeProfileStatus(username, status);
        return ResponseEntity.noContent().build();
    }

    private Map<String, Object> toMap(UserEntity u) {
        return Map.of(
                "id", u.getId(),
                "username", u.getUsername(),
                "email", u.getEmail(),
                "profileStatus", u.getProfileStatus().name(),
                "enabled", u.isEnabled(),
                "roles", u.getRoles().stream().map(r -> r.getName()).toList()
        );
    }
}
