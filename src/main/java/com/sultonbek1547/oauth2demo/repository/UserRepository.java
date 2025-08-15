package com.sultonbek1547.oauth2demo.repository;

import com.sultonbek1547.oauth2demo.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByEmail(String email);
    
    Optional<User> findByUsername(String username);
    
    boolean existsByEmail(String email);
    
    boolean existsByUsername(String username);
    
    @Query("SELECT u FROM User u WHERE u.email = :email AND u.enabled = true")
    Optional<User> findActiveUserByEmail(@Param("email") String email);
    
    @Query("SELECT u FROM User u WHERE u.passwordResetToken = :token AND u.passwordResetTokenExpiry > :now")
    Optional<User> findByValidPasswordResetToken(@Param("token") String token, @Param("now") LocalDateTime now);
    
    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginTime WHERE u.email = :email")
    void updateLastLoginTime(@Param("email") String email, @Param("loginTime") LocalDateTime loginTime);
    
    @Modifying
    @Query("DELETE FROM User u WHERE u.enabled = false AND u.createdAt < :cutoffDate")
    void deleteUnverifiedUsersOlderThan(@Param("cutoffDate") LocalDateTime cutoffDate);
}