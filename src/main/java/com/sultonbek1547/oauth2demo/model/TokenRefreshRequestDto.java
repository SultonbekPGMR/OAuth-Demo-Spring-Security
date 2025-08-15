package com.sultonbek1547.oauth2demo.model;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenRefreshRequestDto {
    
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}