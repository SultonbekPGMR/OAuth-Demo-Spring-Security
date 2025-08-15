package com.sultonbek1547.oauth2demo.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

@Component
@Slf4j
public class JwtTokenUtil {

    private String jwtSecret = "ThisIsASecretKeyThatIsAtLeast32CharactersLongThisIsASecretKeyThatIsAtLeast32CharactersLong";

     // 15 minutes
    private static final long accessTokenExpirationMs = 900000L;

    private static final long refreshTokenExpirationMs = 2592000000L;

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateAccessToken(UserDetails userDetails, Set<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);
        claims.put("type", "access");
        return createToken(claims, userDetails.getUsername(), accessTokenExpirationMs);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");
        return createToken(claims, userDetails.getUsername(), refreshTokenExpirationMs);
    }

    public String generatePasswordResetToken(String email) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "password-reset");
        return createToken(claims, email, 3600000); // 1 hour
    }

    public String generateEmailVerificationToken(String email) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "email-verification");
        return createToken(claims, email, 86400000); // 24 hours
    }

    private String createToken(Map<String, Object> claims, String subject, long expirationTime) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime);

        return Jwts.builder().claims(claims).subject(subject).issuedAt(now).expiration(expiryDate)
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public String getTokenType(String token) {
        return getClaimFromToken(token, claims -> (String) claims.get("type"));
    }

    @SuppressWarnings("unchecked")
    public Set<String> getRolesFromToken(String token) {
        return getClaimFromToken(token, claims -> (Set<String>) claims.get("roles"));
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    private Claims getAllClaimsFromToken(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .build().parseSignedClaims(token).getPayload();
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired: {}", e.getMessage());
            throw e;
        } catch (UnsupportedJwtException e) {
            log.error("JWT token is unsupported: {}", e.getMessage());
            throw e;
        } catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
            throw e;
        } catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
            throw e;
        } catch (IllegalArgumentException e) {
            log.error("JWT token compact of handler are invalid: {}", e.getMessage());
            throw e;
        }
    }

    public boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            final String username = getUsernameFromToken(token);
            return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
        } catch (JwtException | IllegalArgumentException e) {
            log.error("JWT validation failed: {}", e.getMessage());
            return false;
        }
    }

    public boolean isAccessToken(String token) {
        try {
            return "access".equals(getTokenType(token));
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isRefreshToken(String token) {
        try {
            return "refresh".equals(getTokenType(token));
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isPasswordResetToken(String token) {
        try {
            return "password-reset".equals(getTokenType(token));
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public boolean isEmailVerificationToken(String token) {
        try {
            return "email-verification".equals(getTokenType(token));
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}