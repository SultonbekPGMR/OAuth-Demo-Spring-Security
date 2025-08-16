package com.sultonbek1547.oauth2demo.config;

import com.sultonbek1547.oauth2demo.entity.Role;
import com.sultonbek1547.oauth2demo.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RoleInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) {
        createRoleIfNotExists("ROLE_ADMIN", "Administrator with full privileges");
        createRoleIfNotExists("ROLE_CLIENT", "Default user role");
    }

    private void createRoleIfNotExists(String roleName, String description) {
        roleRepository.findByName(roleName).orElseGet(() -> {
            Role role = Role.builder()
                    .name(roleName)
                    .description(description)
                    .build();
            return roleRepository.save(role);
        });
    }
}
