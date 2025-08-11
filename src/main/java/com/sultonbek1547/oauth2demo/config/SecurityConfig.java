package com.sultonbek1547.oauth2demo.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {

        return httpSecurity
                .authorizeHttpRequests(auth -> {
                            auth.requestMatchers("/").permitAll();
                            auth.anyRequest().authenticated();
                        }
                )
                .oauth2Login(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults())
                .logout(logout -> logout
                        .logoutUrl("/logout")                // Optional, default is /logout
                        .logoutSuccessUrl("/")               // Where to go after logout
                        .invalidateHttpSession(true)        // Invalidate session
                        .clearAuthentication(true)          // Clear authentication info
                        .deleteCookies("JSESSIONID")        // Delete cookies
                )
                .logout(logout -> logout
                        .logoutUrl("/api/logout")             // Custom logout endpoint for mobile


                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                )
                .build();

    }

}
