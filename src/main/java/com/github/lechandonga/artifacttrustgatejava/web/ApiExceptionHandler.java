package com.github.lechandonga.artifacttrustgatejava.web;

import com.github.lechandonga.artifacttrustgatejava.model.ServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ServiceException.class)
    public ResponseEntity<Map<String, String>> handle(ServiceException e) {
        HttpStatus status = e.code().name().contains("BAD_REQUEST")
                ? HttpStatus.BAD_REQUEST : HttpStatus.CONFLICT;
        return ResponseEntity.status(status).body(Map.of(
                "code", e.code().name(),
                "message", e.getMessage() == null ? "" : e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleIllegalArg(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of(
                "code", "REJECT_BAD_REQUEST",
                "message", e.getMessage() == null ? "" : e.getMessage()));
    }
}
