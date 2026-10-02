package com.github.lechandonga.artifacttrustgatejava.tests.support;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.lechandonga.artifacttrustgatejava.crypto.RsaSignatureService;
import com.github.lechandonga.artifacttrustgatejava.service.AdminService;
import com.github.lechandonga.artifacttrustgatejava.service.AdmissionService;
import com.github.lechandonga.artifacttrustgatejava.service.AttestationService;
import com.github.lechandonga.artifacttrustgatejava.service.PolicyService;
import com.github.lechandonga.artifacttrustgatejava.service.VerificationService;
import com.github.lechandonga.artifacttrustgatejava.store.AuditStore;
import com.github.lechandonga.artifacttrustgatejava.store.KeyStore;
import com.github.lechandonga.artifacttrustgatejava.store.PolicyStore;
import com.github.lechandonga.artifacttrustgatejava.store.RevocationLedger;

import java.nio.file.Path;
import java.time.Clock;

/**
 * 在临时目录上手工组装全套服务（不走 Spring），
 * 每个用例独立数据目录，从根上避免缓存/文件串数据。
 */
public record LocalHarness(
        Path dataDir,
        ObjectMapper mapper,
        TestClock clock,
        RsaSignatureService rsa,
        KeyStore keyStore,
        RevocationLedger revocationLedger,
        PolicyStore policyStore,
        AuditStore auditStore,
        AdminService adminService,
        AttestationService attestationService,
        VerificationService verificationService,
        PolicyService policyService,
        AdmissionService admissionService
) {

    public static LocalHarness create(Path dataDir, TestClock clock) {
        ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
        String dir = dataDir.toString();
        KeyStore keyStore = new KeyStore(mapper, dir);
        RevocationLedger revocationLedger = new RevocationLedger(mapper, dir);
        PolicyStore policyStore = new PolicyStore(mapper, dir);
        AuditStore auditStore = new AuditStore(mapper, dir);
        RsaSignatureService rsa = new RsaSignatureService();

        AdminService adminService = new AdminService(keyStore, revocationLedger, policyStore, rsa, clock);
        AttestationService attestationService = new AttestationService(
                mapper, keyStore, revocationLedger, rsa, clock);
        VerificationService verificationService = new VerificationService(
                keyStore, rsa, attestationService);
        PolicyService policyService = new PolicyService(policyStore);
        AdmissionService admissionService = new AdmissionService(
                verificationService, policyService, revocationLedger, auditStore, mapper, clock);

        return new LocalHarness(dataDir, mapper, clock, rsa, keyStore, revocationLedger,
                policyStore, auditStore, adminService, attestationService, verificationService,
                policyService, admissionService);
    }

    public static LocalHarness create(Path dataDir) {
        return create(dataDir, new TestClock(java.time.Instant.parse("2026-01-10T08:00:00Z")));
    }
}
