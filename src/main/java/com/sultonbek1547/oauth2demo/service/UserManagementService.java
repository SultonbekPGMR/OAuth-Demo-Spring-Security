package com.sultonbek1547.oauth2demo.service;

import com.sultonbek1547.oauth2demo.entity.RefreshToken;
import com.sultonbek1547.oauth2demo.entity.Role;
import com.sultonbek1547.oauth2demo.entity.User;
import com.sultonbek1547.oauth2demo.exception.AuthenticationException;
import com.sultonbek1547.oauth2demo.exception.InvalidTokenException;
import com.sultonbek1547.oauth2demo.exception.UserAlreadyExistsException;
import com.sultonbek1547.oauth2demo.model.*;
import com.sultonbek1547.oauth2demo.repository.RefreshTokenRepository;
import com.sultonbek1547.oauth2demo.repository.RoleRepository;
import com.sultonbek1547.oauth2demo.repository.UserRepository;
import com.sultonbek1547.oauth2demo.util.CustomUserPrincipal;
import com.sultonbek1547.oauth2demo.util.EmailService;
import com.sultonbek1547.oauth2demo.util.JwtTokenUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserManagementService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenUtil jwtTokenUtil;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;

    @Transactional
    public AuthResponseDto register(RegisterRequestDto request) {
        log.info("Registering new user with email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("User with email already exists");
        }

        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already taken");
        }

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .enabled(false) // Email verification required
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .createdAt(LocalDateTime.now())
                .roles(getDefaultRoles())
                .build();

        user = userRepository.save(user);

        // Send email verification
        String emailVerificationToken = jwtTokenUtil.generateEmailVerificationToken(user.getEmail());
        emailService.sendEmailVerification(user.getEmail(), emailVerificationToken);

        UserDetails userDetails = new CustomUserPrincipal(user);
        Set<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        String accessToken = jwtTokenUtil.generateAccessToken(userDetails, roles);
        String refreshToken = jwtTokenUtil.generateRefreshToken(userDetails);

        saveRefreshToken(user, refreshToken);

        log.info("User registered successfully: {}", user.getEmail());

        return AuthResponseDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(900) // 15 minutes
                .user(UserDto.fromEntity(user))
                .build();
    }

    @Transactional
    public AuthResponseDto login(LoginRequestDto request) {
        log.info("Attempting login for user: {}", request.getEmail());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );

            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            User user = userPrincipal.user();

            if (!user.getEnabled()) {
                throw new AuthenticationException("Account is not verified. Please check your email.");
            }

            Set<String> roles = user.getRoles().stream()
                    .map(Role::getName)
                    .collect(Collectors.toSet());

            String accessToken = jwtTokenUtil.generateAccessToken(userPrincipal, roles);
            String refreshToken = jwtTokenUtil.generateRefreshToken(userPrincipal);

            // Invalidate old refresh tokens and save new one
            refreshTokenRepository.deleteByUserId(user.getId());
            saveRefreshToken(user, refreshToken);

            // Update last login
            user.setLastLoginAt(LocalDateTime.now());
            userRepository.save(user);

            log.info("User logged in successfully: {}", request.getEmail());

            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(900) // 15 minutes
                    .user(UserDto.fromEntity(user))
                    .build();

        } catch (BadCredentialsException e) {
            log.warn("Invalid login attempt for user: {}", request.getEmail());
            throw new AuthenticationException("Invalid email or password");
        }
    }

    @Transactional
    public AuthResponseDto refreshToken(String refreshTokenValue) {
        log.info("Attempting token refresh");

        if (!jwtTokenUtil.isRefreshToken(refreshTokenValue)) {
            throw new InvalidTokenException("Invalid refresh token type");
        }

        if (jwtTokenUtil.isTokenExpired(refreshTokenValue)) {
            throw new InvalidTokenException("Refresh token expired");
        }

        String email = jwtTokenUtil.getUsernameFromToken(refreshTokenValue);
        
        RefreshToken storedToken = refreshTokenRepository.findByTokenAndUserEmail(refreshTokenValue, email)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        if (storedToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(storedToken);
            throw new InvalidTokenException("Refresh token expired");
        }

        User user = storedToken.getUser();
        CustomUserPrincipal userPrincipal = new CustomUserPrincipal(user);
        
        Set<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet());

        String newAccessToken = jwtTokenUtil.generateAccessToken(userPrincipal, roles);
        String newRefreshToken = jwtTokenUtil.generateRefreshToken(userPrincipal);

        // Update refresh token
        refreshTokenRepository.delete(storedToken);
        saveRefreshToken(user, newRefreshToken);

        log.info("Token refreshed successfully for user: {}", email);

        return AuthResponseDto.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(900) // 15 minutes
                .user(UserDto.fromEntity(user))
                .build();
    }

    @Transactional
    public void logout(String refreshToken) {
        log.info("Processing logout request");
        
        if (refreshToken != null && jwtTokenUtil.isRefreshToken(refreshToken)) {
            String email = jwtTokenUtil.getUsernameFromToken(refreshToken);
            refreshTokenRepository.deleteByTokenAndUserEmail(refreshToken, email);
            log.info("User logged out successfully: {}", email);
        }
    }

    @Transactional
    public void logoutAllDevices(String email) {
        log.info("Logging out all devices for user: {}", email);
        refreshTokenRepository.deleteByUserEmail(email);
    }

    @Transactional
    public void verifyEmail(String token) {
        if (!jwtTokenUtil.isEmailVerificationToken(token) || jwtTokenUtil.isTokenExpired(token)) {
            throw new InvalidTokenException("Invalid or expired verification token");
        }

        String email = jwtTokenUtil.getUsernameFromToken(token);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidTokenException("User not found"));

        user.setEnabled(true);
        user.setEmailVerifiedAt(LocalDateTime.now());
        userRepository.save(user);

        log.info("Email verified successfully for user: {}", email);
    }

    @Transactional
    public void forgotPassword(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);
        
        if (userOpt.isPresent()) {
            User user = userOpt.get();
            String resetToken = jwtTokenUtil.generatePasswordResetToken(email);
            
            user.setPasswordResetToken(resetToken);
            user.setPasswordResetTokenExpiry(LocalDateTime.now().plusHours(1));
            userRepository.save(user);
            
            emailService.sendPasswordReset(email, resetToken);
            log.info("Password reset email sent to: {}", email);
        } else {
            log.warn("Password reset requested for non-existent email: {}", email);
            // Don't reveal whether email exists or not
        }
    }

    @Transactional
    public void resetPassword(ResetPasswordRequestDto request) {
        if (!jwtTokenUtil.isPasswordResetToken(request.getToken()) || 
            jwtTokenUtil.isTokenExpired(request.getToken())) {
            throw new InvalidTokenException("Invalid or expired reset token");
        }

        String email = jwtTokenUtil.getUsernameFromToken(request.getToken());
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidTokenException("User not found"));

        if (!request.getToken().equals(user.getPasswordResetToken()) ||
            user.getPasswordResetTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new InvalidTokenException("Invalid or expired reset token");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Invalidate all refresh tokens
        refreshTokenRepository.deleteByUserId(user.getId());

        log.info("Password reset successfully for user: {}", email);
    }

    @Transactional
    public void changePassword(String email, ChangePasswordRequestDto request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new AuthenticationException("Current password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setPasswordChangedAt(LocalDateTime.now());
        userRepository.save(user);

        // Invalidate all refresh tokens except current session
        // You might want to keep current session active
        log.info("Password changed successfully for user: {}", email);
    }

    @Transactional(readOnly = true)
    public UserProfileDto getUserProfile(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));
        
        return UserProfileDto.fromEntity(user);
    }

    @Transactional
    public UserProfileDto updateUserProfile(String email, UpdateProfileRequestDto request) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationException("User not found"));

        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }
        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }
        if (request.getPhoneNumber() != null) {
            user.setPhoneNumber(request.getPhoneNumber());
        }
        
        user.setUpdatedAt(LocalDateTime.now());
        user = userRepository.save(user);

        log.info("Profile updated for user: {}", email);
        return UserProfileDto.fromEntity(user);
    }

    private Set<Role> getDefaultRoles() {
        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName("ROLE_USER");
                    newRole.setDescription("Default user role");
                    return roleRepository.save(newRole);
                });
        roles.add(userRole);
        return roles;
    }

    private void saveRefreshToken(User user, String tokenValue) {
        RefreshToken refreshToken = RefreshToken.builder()
                .token(tokenValue)
                .user(user)
                .expiryDate(LocalDateTime.now().plusDays(30))
                .build();
        refreshTokenRepository.save(refreshToken);
    }
}