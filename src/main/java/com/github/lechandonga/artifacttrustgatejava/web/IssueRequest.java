package com.github.lechandonga.artifacttrustgatejava.web;

public record IssueRequest(String keyId, String artifact, String issuer,
                           Long issuedAt, Long notBefore, Long notAfter) {
}
