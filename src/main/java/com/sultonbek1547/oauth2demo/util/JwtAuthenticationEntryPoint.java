package com.sultonbek1547.oauth2demo.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sultonbek1547.oauth2demo.model.ApiResponseDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;

@Component
@Slf4j
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, 
                        HttpServletResponse response, 
                        AuthenticationException authException) throws IOException {
        
        log.warn("Unauthorized access attempt: {} - {}", request.getRequestURI(), authException.getMessage());
        
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        
        String message = "Authentication required";
        
        // Check for specific JWT errors
        if (request.getAttribute("expired") != null) {
            message = "Access token expired";
        } else if (request.getAttribute("invalid") != null) {
            message = "Invalid access token";
        }

        ApiResponseDto<Object> errorResponse = ApiResponseDto.builder()
                .success(false)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
        
        objectMapper.writeValue(response.getOutputStream(), errorResponse);
    }
}
