package com.sultonbek1547.oauth2demo.config;

import com.sultonbek1547.oauth2demo.entity.Role;
import com.sultonbek1547.oauth2demo.entity.User;
import com.sultonbek1547.oauth2demo.repository.RoleRepository;
import com.sultonbek1547.oauth2demo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class AdminInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        if (userRepository.count() == 0) {
            Role adminRole = roleRepository.findByName("ROLE_ADMIN")
                    .orElseThrow(() -> new RuntimeException("ROLE_ADMIN not found."));

            User admin = User.builder()
                    .username("admin")
                    .email("admin")
                    .password(passwordEncoder.encode("admin"))
                    .enabled(true)
                    .roles(Set.of(adminRole))
                    .build();

            userRepository.save(admin);
            System.out.println("✅ Default admin user created: admin / admin123");
        }
    }
}
