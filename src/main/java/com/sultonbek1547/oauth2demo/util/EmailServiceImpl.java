package com.sultonbek1547.oauth2demo.util;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;
    
    @Value("${app.mail.from:noreply@yourcompany.com}")
    private String fromEmail;
    
    @Value("${app.frontend.url:http://localhost:3000}")
    private String frontendUrl;

    @Override
    @Async
    public void sendEmailVerification(String email, String token) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            
            helper.setFrom(fromEmail);
            helper.setTo(email);
            helper.setSubject("Verify Your Email Address");
            
            String verificationUrl = frontendUrl + "/verify-email?token=" + token;
            String content = buildEmailVerificationContent(verificationUrl);
            
            helper.setText(content, true);
            
//            mailSender.send(message);
            log.info("Email verification sent to: {}. message:"+message, email);
            
        } catch (MessagingException e) {
            log.error("Failed to send email verification to: {}", email, e);
            throw new RuntimeException("Failed to send email", e);
        }
    }

    @Override
    @Async
    public void sendPasswordReset(String email, String token) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            
            helper.setFrom(fromEmail);
            helper.setTo(email);
            helper.setSubject("Password Reset Request");
            
            String resetUrl = frontendUrl + "/reset-password?token=" + token;
            String content = buildPasswordResetContent(resetUrl);
            
            helper.setText(content, true);
            
            mailSender.send(message);
            log.info("Password reset email sent to: {}", email);
            
        } catch (MessagingException e) {
            log.error("Failed to send password reset email to: {}", email, e);
            throw new RuntimeException("Failed to send email", e);
        }
    }

    @Override
    @Async
    public void sendWelcomeEmail(String email, String fullName) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true);
            
            helper.setFrom(fromEmail);
            helper.setTo(email);
            helper.setSubject("Welcome to Our Platform");
            
            String content = buildWelcomeContent(fullName);
            helper.setText(content, true);
            
            mailSender.send(message);
            log.info("Welcome email sent to: {}", email);
            
        } catch (MessagingException e) {
            log.error("Failed to send welcome email to: {}", email, e);
            throw new RuntimeException("Failed to send email", e);
        }
    }

    private String buildEmailVerificationContent(String verificationUrl) {
        return String.format("""
            <html>
            <body>
                <h2>Email Verification</h2>
                <p>Thank you for registering! Please click the link below to verify your email address:</p>
                <p><a href="%s" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
                <p>This link will expire in 24 hours.</p>
                <p>If you didn't create an account, please ignore this email.</p>
            </body>
            </html>
            """, verificationUrl);
    }

    private String buildPasswordResetContent(String resetUrl) {
        return String.format("""
            <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>We received a request to reset your password. Click the link below to set a new password:</p>
                <p><a href="%s" style="background-color: #dc3545; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request a password reset, please ignore this email.</p>
            </body>
            </html>
            """, resetUrl);
    }

    private String buildWelcomeContent(String fullName) {
        return String.format("""
            <html>
            <body>
                <h2>Welcome, %s!</h2>
                <p>Your account has been successfully verified and is now active.</p>
                <p>You can now enjoy all the features of our platform.</p>
                <p>If you have any questions, feel free to contact our support team.</p>
            </body>
            </html>
            """, fullName);
    }
}