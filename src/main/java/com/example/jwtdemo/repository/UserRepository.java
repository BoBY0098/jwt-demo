package com.example.jwtdemo.repository;

import com.example.jwtdemo.entity.UserEntity;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByUsername(String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    /**
     * Solution 1 – JOIN FETCH (JPQL)
     */
    @Query("""
            SELECT DISTINCT u FROM UserEntity u
            LEFT JOIN FETCH u.roles
            WHERE u.username = :username
            """)
    Optional<UserEntity> findByUsernameWithRoles(@Param("username") String username);

    @Query("""
            SELECT DISTINCT u FROM UserEntity u
            LEFT JOIN FETCH u.roles
            """)
    List<UserEntity> findAllWithRoles();

    /**
     * Solution 2 – @EntityGraph (Spring Data JPA magic)
     *   Declares which associations to fetch eagerly for this method only.
     */
    @EntityGraph(attributePaths = {"roles"})
    @Query("SELECT u FROM UserEntity u WHERE u.username = :username")
    Optional<UserEntity> findByUsernameWithRolesEntityGraph(@Param("username") String username);
}
