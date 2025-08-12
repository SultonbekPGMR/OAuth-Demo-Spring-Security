package com.sultonbek1547.oauth2demo.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
@Data
public class JwtProperties {
    private String secretKey = "5tku82rXjZpIGAajn/JSjq7gPJdsOT4QRrYWdxoFosZq0FZTeSD9uXxGkdTQi5lR";
    private long expiration = 86400000;

}