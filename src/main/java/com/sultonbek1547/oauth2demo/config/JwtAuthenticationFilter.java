package com.sultonbek1547.oauth2demo.config;

import com.sultonbek1547.oauth2demo.util.CustomUserDetailsService;
import com.sultonbek1547.oauth2demo.util.JwtTokenUtil;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String requestURI = request.getRequestURI();
        final String authHeader = request.getHeader("Authorization");

        log.debug("Incoming request: {}", requestURI);
        log.debug("Authorization header: {}", authHeader);

        // Skip JWT validation for public endpoints
        if (isPublicEndpoint(requestURI)) {
            log.debug("Skipping JWT validation for public endpoint: {}", requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = null;
        String username = null;

        // Extract JWT from Authorization header
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7);
            log.debug("Extracted JWT: {}", jwt);

            try {
                // Only process access tokens
                if (!jwtTokenUtil.isAccessToken(jwt)) {
                    log.warn("Invalid token type provided for authentication: {}", jwt);
                    filterChain.doFilter(request, response);
                    return;
                }

                username = jwtTokenUtil.getUsernameFromToken(jwt);
                log.debug("Username extracted from JWT: {}", username);

            } catch (ExpiredJwtException e) {
                log.debug("JWT token expired: {}", e.getMessage());
                request.setAttribute("expired", e.getMessage());
            } catch (JwtException | IllegalArgumentException e) {
                log.warn("JWT token validation failed: {}", e.getMessage());
                request.setAttribute("invalid", e.getMessage());
            }
        } else {
            log.debug("No valid Authorization header found");
        }

        // Authenticate user if token is valid and no authentication exists
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                log.debug("Loading user details for: {}", username);
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                log.debug("Validating token for user: {}", username);
                if (jwtTokenUtil.validateToken(jwt, userDetails)) {
                    log.debug("Token is valid. Setting authentication for user: {}", username);

                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                    userDetails,
                                    null,
                                    userDetails.getAuthorities()
                            );

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("User '{}' authenticated successfully", username);
                } else {
                    log.warn("JWT token validation failed for user: {}", username);
                }

            } catch (Exception e) {
                log.error("Failed to authenticate user: {}", e.getMessage(), e);
            }
        } else {
            log.debug("Skipping authentication - username is null or authentication already exists");
        }

        filterChain.doFilter(request, response);
    }
    private boolean isPublicEndpoint(String requestURI) {
        return requestURI.equals("/api/v1/auth/login") ||
                requestURI.equals("/api/v1/auth/register") ||
                requestURI.startsWith("/actuator/health") ||
                requestURI.startsWith("/actuator/info") ||
                requestURI.startsWith("/v3/api-docs") ||
                requestURI.startsWith("/swagger-ui") ||
                requestURI.equals("/swagger-ui.html");
    }

}
