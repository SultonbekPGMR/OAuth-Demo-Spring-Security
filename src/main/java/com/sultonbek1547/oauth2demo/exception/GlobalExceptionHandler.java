package com.sultonbek1547.oauth2demo.exception;

import com.sultonbek1547.oauth2demo.model.ApiResponseDto;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDto<Map<String, String>>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        log.warn("Validation errors: {}", errors);

        return ApiResponseDto.badRequest("Validation failed");
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleAuthenticationException(
            AuthenticationException ex, WebRequest request) {

        log.warn("Authentication error: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.unauthorized(ex.getMessage());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleBadCredentialsException(
            BadCredentialsException ex, WebRequest request) {

        log.warn("Bad credentials: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.unauthorized("Invalid email or password");
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleUsernameNotFoundException(
            UsernameNotFoundException ex, WebRequest request) {

        log.warn("User not found: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.unauthorized("Invalid email or password");
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleInvalidTokenException(
            InvalidTokenException ex, WebRequest request) {

        log.warn("Invalid token: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.unauthorized(ex.getMessage());
    }

    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleExpiredJwtException(
            ExpiredJwtException ex, WebRequest request) {

        log.warn("Expired JWT: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.unauthorized("Token expired");
    }

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleJwtException(
            JwtException ex, WebRequest request) {

        log.warn("JWT error: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.unauthorized("Invalid token");
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleUserAlreadyExistsException(
            UserAlreadyExistsException ex, WebRequest request) {

        log.warn("User already exists: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.error(ex.getMessage(), HttpStatus.CONFLICT);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleUserNotFoundException(
            UserNotFoundException ex, WebRequest request) {

        log.warn("User not found: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.notFound(ex.getMessage());
    }

    @ExceptionHandler(AccountNotVerifiedException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleAccountNotVerifiedException(
            AccountNotVerifiedException ex, WebRequest request) {

        log.warn("Account not verified: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.error(ex.getMessage(), HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleAccessDeniedException(
            AccessDeniedException ex, WebRequest request) {

        log.warn("Access denied: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.error("Access denied - insufficient privileges", HttpStatus.FORBIDDEN);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleDataIntegrityViolationException(
            DataIntegrityViolationException ex, WebRequest request) {

        log.error("Data integrity violation: {} for request: {}", ex.getMessage(), request.getDescription(false));

        String message = "Data integrity violation";
        if (ex.getMessage() != null) {
            if (ex.getMessage().contains("email")) {
                message = "Email already exists";
            } else if (ex.getMessage().contains("username")) {
                message = "Username already exists";
            }
        }

        return ApiResponseDto.error(message, HttpStatus.CONFLICT);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleHttpMessageNotReadableException(
            HttpMessageNotReadableException ex, WebRequest request) {

        log.warn("Invalid JSON: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.badRequest("Invalid JSON format");
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleMissingServletRequestParameterException(
            MissingServletRequestParameterException ex, WebRequest request) {

        log.warn("Missing parameter: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.badRequest("Missing required parameter: " + ex.getParameterName());
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleMethodArgumentTypeMismatchException(
            MethodArgumentTypeMismatchException ex, WebRequest request) {

        log.warn("Type mismatch: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.badRequest("Invalid parameter type for: " + ex.getName());
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleNoHandlerFoundException(
            NoHandlerFoundException ex, WebRequest request) {

        log.warn("No handler found: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.notFound("Endpoint not found");
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleIllegalArgumentException(
            IllegalArgumentException ex, WebRequest request) {

        log.warn("Illegal argument: {} for request: {}", ex.getMessage(), request.getDescription(false));

        return ApiResponseDto.badRequest("Invalid request: " + ex.getMessage());
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiResponseDto<Void>> handleRuntimeException(
            RuntimeException ex, WebRequest request) {

        log.error("Runtime exception: {} for request: {}", ex.getMessage(), request.getDescription(false), ex);

        return ApiResponseDto.error("An error occurred while processing your request", HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponseDto<Void>> handleGenericException(
            Exception ex, WebRequest request) {

        log.error("Unexpected error: {} for request: {}", ex.getMessage(), request.getDescription(false), ex);

        return ApiResponseDto.error("An unexpected error occurred", HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
