package com.sultonbek1547.oauth2demo.repository;

import com.sultonbek1547.oauth2demo.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    
    Optional<RefreshToken> findByToken(String token);
    
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = :token AND rt.user.email = :email")
    Optional<RefreshToken> findByTokenAndUserEmail(@Param("token") String token, @Param("email") String email);
    
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user.email = :email")
    Optional<RefreshToken> findByUserEmail(@Param("email") String email);
    
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.user.id = :userId")
    void deleteByUserId(@Param("userId") Long userId);
    
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.user.email = :email")
    void deleteByUserEmail(@Param("email") String email);
    
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.token = :token AND rt.user.email = :email")
    void deleteByTokenAndUserEmail(@Param("token") String token, @Param("email") String email);
    
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
    
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.user.id = :userId")
    long countByUserId(@Param("userId") Long userId);
    
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.user.id = :userId ORDER BY rt.createdAt DESC")
    java.util.List<RefreshToken> findByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId);
}