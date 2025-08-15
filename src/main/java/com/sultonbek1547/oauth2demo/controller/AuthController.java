package com.sultonbek1547.oauth2demo.controller;

import com.sultonbek1547.oauth2demo.model.*;
import com.sultonbek1547.oauth2demo.service.UserManagementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
public class AuthController {

    private final UserManagementService userManagementService;

    @PostMapping("/register")
    @Operation(summary = "Register a new user", description = "Create a new user account")
    @ApiResponse(responseCode = "201", description = "User registered successfully")
    @ApiResponse(responseCode = "400", description = "Invalid input data")
    @ApiResponse(responseCode = "409", description = "User already exists")
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> register(
            @Valid @RequestBody RegisterRequestDto request,
            HttpServletRequest httpRequest) {

        log.info("Registration attempt for email: {} from IP: {}",
                request.getEmail(), getClientIpAddress(httpRequest));

        AuthResponseDto response = userManagementService.register(request);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDto.success("User registered successfully. Please verify your email.", response));
    }

    @PostMapping("/login")
    @Operation(summary = "Authenticate user", description = "Login with email and password")
    @ApiResponse(responseCode = "200", description = "Login successful")
    @ApiResponse(responseCode = "401", description = "Invalid credentials")
    @ApiResponse(responseCode = "423", description = "Account locked")
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> login(
            @Valid @RequestBody LoginRequestDto request,
            HttpServletRequest httpRequest) {

        log.info("Login attempt for email: {} from IP: {}",
                request.getEmail(), getClientIpAddress(httpRequest));

        AuthResponseDto response = userManagementService.login(request);

        return ResponseEntity.ok(ApiResponseDto.success("Login successful", response));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token", description = "Get a new access token using refresh token")
    @ApiResponse(responseCode = "200", description = "Token refreshed successfully")
    @ApiResponse(responseCode = "401", description = "Invalid refresh token")
    public ResponseEntity<ApiResponseDto<AuthResponseDto>> refreshToken(
            @Valid @RequestBody TokenRefreshRequestDto request) {

        log.debug("Token refresh attempt");

        AuthResponseDto response = userManagementService.refreshToken(request.getRefreshToken());

        return ResponseEntity.ok(ApiResponseDto.success("Token refreshed successfully", response));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout user", description = "Invalidate refresh token")
    @ApiResponse(responseCode = "200", description = "Logout successful")
    public ResponseEntity<ApiResponseDto<Void>> logout(
            @RequestBody(required = false) TokenRefreshRequestDto request,
            @AuthenticationPrincipal UserDetails userDetails) {

        String refreshToken = request != null ? request.getRefreshToken() : null;
        userManagementService.logout(refreshToken);

        if (userDetails != null) {
            log.info("User logged out: {}", userDetails.getUsername());
        }

        return ResponseEntity.ok(ApiResponseDto.success("Logout successful"));
    }

    @PostMapping("/logout-all")
    @Operation(summary = "Logout from all devices", description = "Invalidate all refresh tokens for the user")
    @ApiResponse(responseCode = "200", description = "Logged out from all devices")
    public ResponseEntity<ApiResponseDto<Void>> logoutAllDevices(
            @AuthenticationPrincipal UserDetails userDetails) {

        userManagementService.logoutAllDevices(userDetails.getUsername());

        log.info("User logged out from all devices: {}", userDetails.getUsername());

        return ResponseEntity.ok(ApiResponseDto.success("Logged out from all devices successfully"));
    }

    @GetMapping("/verify-email")
    @Operation(summary = "Verify email address", description = "Verify user email using verification token")
    @ApiResponse(responseCode = "200", description = "Email verified successfully")
    @ApiResponse(responseCode = "400", description = "Invalid or expired token")
    public ResponseEntity<ApiResponseDto<Void>> verifyEmail(@RequestParam String token) {

        log.info("Email verification attempt with token");

        userManagementService.verifyEmail(token);

        return ResponseEntity.ok(ApiResponseDto.success("Email verified successfully"));
    }

    @PostMapping("/resend-verification")
    @Operation(summary = "Resend email verification", description = "Send a new email verification token")
    @ApiResponse(responseCode = "200", description = "Verification email sent")
    @ApiResponse(responseCode = "400", description = "Invalid email or already verified")
    public ResponseEntity<ApiResponseDto<Void>> resendEmailVerification(
            @Valid @RequestBody ResendEmailVerificationRequestDto request) {

        log.info("Resend verification requested for email: {}", request.getEmail());

        // This would need to be implemented in UserManagementService
        // userManagementService.resendEmailVerification(request.getEmail());

        return ResponseEntity.ok(ApiResponseDto.success("If the email exists and is not verified, a verification email has been sent"));
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Request password reset", description = "Send password reset email")
    @ApiResponse(responseCode = "200", description = "Reset email sent if user exists")
    public ResponseEntity<ApiResponseDto<Void>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequestDto request,
            HttpServletRequest httpRequest) {

        log.info("Password reset requested for email: {} from IP: {}",
                request.getEmail(), getClientIpAddress(httpRequest));

        userManagementService.forgotPassword(request.getEmail());

        return ResponseEntity.ok(ApiResponseDto.success("If the email exists, a password reset link has been sent"));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password", description = "Reset password using reset token")
    @ApiResponse(responseCode = "200", description = "Password reset successfully")
    @ApiResponse(responseCode = "400", description = "Invalid or expired token")
    public ResponseEntity<ApiResponseDto<Void>> resetPassword(
            @Valid @RequestBody ResetPasswordRequestDto request,
            HttpServletRequest httpRequest) {

        log.info("Password reset attempt from IP: {}", getClientIpAddress(httpRequest));

        userManagementService.resetPassword(request);

        return ResponseEntity.ok(ApiResponseDto.success("Password reset successfully"));
    }

    @PostMapping("/change-password")
    @Operation(summary = "Change password", description = "Change password for authenticated user")
    @ApiResponse(responseCode = "200", description = "Password changed successfully")
    @ApiResponse(responseCode = "400", description = "Invalid current password")
    public ResponseEntity<ApiResponseDto<Void>> changePassword(
            @Valid @RequestBody ChangePasswordRequestDto request,
            @AuthenticationPrincipal UserDetails userDetails) {

        log.info("Password change request for user: {}", userDetails.getUsername());

        userManagementService.changePassword(userDetails.getUsername(), request);

        return ResponseEntity.ok(ApiResponseDto.success("Password changed successfully"));
    }

    @GetMapping("/profile")
    @Operation(summary = "Get user profile", description = "Get current user profile information")
    @ApiResponse(responseCode = "200", description = "Profile retrieved successfully")
    public ResponseEntity<ApiResponseDto<UserProfileDto>> getUserProfile(
            @AuthenticationPrincipal UserDetails userDetails) {

        UserProfileDto profile = userManagementService.getUserProfile(userDetails.getUsername());

        return ResponseEntity.ok(ApiResponseDto.success("Profile retrieved successfully", profile));
    }

    @PutMapping("/profile")
    @Operation(summary = "Update user profile", description = "Update current user profile information")
    @ApiResponse(responseCode = "200", description = "Profile updated successfully")
    public ResponseEntity<ApiResponseDto<UserProfileDto>> updateUserProfile(
            @Valid @RequestBody UpdateProfileRequestDto request,
            @AuthenticationPrincipal UserDetails userDetails) {

        log.info("Profile update request for user: {}", userDetails.getUsername());

        UserProfileDto updatedProfile = userManagementService.updateUserProfile(
                userDetails.getUsername(), request);

        return ResponseEntity.ok(ApiResponseDto.success("Profile updated successfully", updatedProfile));
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}