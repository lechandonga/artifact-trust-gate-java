package com.github.lechandonga.artifacttrustgatejava.model;

public class ServiceException extends RuntimeException {
    private final DecisionCode code;

    public ServiceException(DecisionCode code, String message) {
        super(message);
        this.code = code;
    }

    public DecisionCode code() {
        return code;
    }
}
