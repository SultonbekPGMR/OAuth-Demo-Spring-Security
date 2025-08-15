package com.sultonbek1547.oauth2demo.util;

public interface EmailService {
    void sendEmailVerification(String email, String token);
    void sendPasswordReset(String email, String token);
    void sendWelcomeEmail(String email, String fullName);
}