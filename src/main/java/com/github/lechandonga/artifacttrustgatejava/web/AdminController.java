package com.github.lechandonga.artifacttrustgatejava.web;

import com.github.lechandonga.artifacttrustgatejava.model.Attestation;
import com.github.lechandonga.artifacttrustgatejava.model.KeyBookSnapshot;
import com.github.lechandonga.artifacttrustgatejava.model.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyRule;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyVersion;
import com.github.lechandonga.artifacttrustgatejava.model.Revocation;
import com.github.lechandonga.artifacttrustgatejava.service.AdminService;
import com.github.lechandonga.artifacttrustgatejava.service.AttestationService;
import com.github.lechandonga.artifacttrustgatejava.crypto.Digests;
import com.github.lechandonga.artifacttrustgatejava.store.KeyStore;
import com.github.lechandonga.artifacttrustgatejava.store.PolicyStore;
import com.github.lechandonga.artifacttrustgatejava.store.RevocationLedger;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final AdminService adminService;
    private final AttestationService attestationService;
    private final KeyStore keyStore;
    private final RevocationLedger revocationLedger;
    private final PolicyStore policyStore;

    public AdminController(AdminService adminService, AttestationService attestationService,
                           KeyStore keyStore, RevocationLedger revocationLedger,
                           PolicyStore policyStore) {
        this.adminService = adminService;
        this.attestationService = attestationService;
        this.keyStore = keyStore;
        this.revocationLedger = revocationLedger;
        this.policyStore = policyStore;
    }

    public record IssueRequest(String keyId, String contentJson, Long ttlSeconds) {
    }

    public record RevokeRequest(Instant effectiveAt, String reason) {
    }

    /** 本地演示签发：对制品内容指纹签发一份证明。 */
    @PostMapping("/attestations/issue")
    public Attestation issue(@RequestBody IssueRequest request) {
        String digest = Digests.artifactDigest(request.contentJson());
        Duration ttl = Duration.ofSeconds(request.ttlSeconds() == null ? 3600 : request.ttlSeconds());
        return attestationService.issue(request.keyId(), digest, ttl);
    }

    @PostMapping("/keys")
    public KeyMaterial createKey(@RequestParam String keyId) {
        return adminService.generateKey(keyId);
    }

    @PostMapping("/keys/rotate")
    public KeyMaterial rotate(@RequestParam String oldKeyId, @RequestParam String newKeyId) {
        return adminService.rotate(oldKeyId, newKeyId);
    }

    /** 吊销密钥：effectiveAt 为生效时间（可未来），拒绝倒填。 */
    @PostMapping("/keys/{keyId}/revoke")
    public KeyBookSnapshot revoke(@PathVariable String keyId, @RequestBody RevokeRequest request) {
        return adminService.revoke(keyId, request.effectiveAt(), request.reason());
    }

    @GetMapping("/keys")
    public List<KeyMaterial> keys() {
        return keyStore.findAll();
    }

    @GetMapping("/revocations")
    public List<Revocation> revocations() {
        return revocationLedger.findAll();
    }

    /** 发布新的不可变策略版本。matchKeyId 留空表示默认规则。 */
    @PostMapping("/policies")
    public PolicyVersion publishPolicy(@RequestBody List<PolicyRule> rules) {
        return adminService.publishPolicy(rules);
    }

    @GetMapping("/policies")
    public List<PolicyVersion> policies() {
        return policyStore.findAll();
    }

    @GetMapping("/keybook/latest")
    public Map<String, Object> latestKeyBook() {
        KeyBookSnapshot snapshot = revocationLedger.latestSnapshot(Instant.now());
        return Map.of("version", snapshot.version(), "revocations", snapshot.revocations());
    }
}
