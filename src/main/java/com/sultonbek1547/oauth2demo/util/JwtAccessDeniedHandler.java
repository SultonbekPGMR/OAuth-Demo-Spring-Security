package com.sultonbek1547.oauth2demo.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sultonbek1547.oauth2demo.model.ApiResponseDto;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class JwtAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void handle(HttpServletRequest request, 
                      HttpServletResponse response, 
                      AccessDeniedException accessDeniedException) throws IOException {
        
        log.warn("Access denied: {} - {}", request.getRequestURI(), accessDeniedException.getMessage());
        
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        
        ApiResponseDto<Object> errorResponse = ApiResponseDto.error("Access denied - insufficient privileges");
        
        objectMapper.writeValue(response.getOutputStream(), errorResponse);
    }
}