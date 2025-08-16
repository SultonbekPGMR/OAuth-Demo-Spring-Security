package com.sultonbek1547.oauth2demo.controller;

import com.sultonbek1547.oauth2demo.model.ApiResponseDto;
import com.sultonbek1547.oauth2demo.model.UserDto;
import com.sultonbek1547.oauth2demo.service.UserManagementService;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin", description = "Admin endpoints")
public class AdminController {

    private final UserManagementService userManagementService;


    @GetMapping("/users")
    @ApiResponse(responseCode = "200", description = "Users fetched")
    public ResponseEntity<ApiResponseDto<Page<UserDto>>> getClients(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size
    ) {
        Pageable pageable = PageRequest.of(page, size);
        Page<UserDto> clients = userManagementService.getClients(pageable);
        log.debug("clients"+clients.getContent());
        return ApiResponseDto.ok("Users fetched", clients);
    }

}
