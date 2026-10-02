package com.github.lechandonga.artifacttrustgatejava.web;

import com.github.lechandonga.artifacttrustgatejava.service.AdmissionService;
import com.github.lechandonga.artifacttrustgatejava.service.AttestationIssuer;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/gate")
public class GateController {

    private final AdmissionService admissionService;
    private final AttestationIssuer issuer;

    public GateController(AdmissionService admissionService, AttestationIssuer issuer) {
        this.admissionService = admissionService;
        this.issuer = issuer;
    }

    /** 提交制品 + 证明做准入校验。 */
    @PostMapping("/admissions")
    public AdmissionDecision admit(@RequestBody AdmissionRequest request) {
        return admissionService.admit(request);
    }

    /** 幂等查询：读取首次审计结论。 */
    @GetMapping("/admissions/{requestId}")
    public ResponseEntity<AdmissionDecision> get(@PathVariable String requestId) {
        return admissionService.findAudited(requestId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** 本地签发证明（模拟可信签发端）。 */
    @PostMapping("/attestations")
    public Map<String, String> issue(@RequestBody IssueRequest request) {
        long now = System.currentTimeMillis();
        long issuedAt = request.issuedAt() == null ? now : request.issuedAt();
        long notBefore = request.notBefore() == null ? now : request.notBefore();
        long notAfter = request.notAfter() == null ? now + 365L * 24 * 3600 * 1000
                : request.notAfter();
        String attestation = issuer.issue(request.keyId(), request.artifact(),
                request.issuer(), issuedAt, notBefore, notAfter);
        return Map.of("attestation", attestation);
    }

    /** 吊销密钥，可携带未来/历史生效时间。 */
    @PostMapping("/keys/revoke")
    public Map<String, String> revoke(@RequestBody RevokeRequest request) {
        long at = request.revokedAt() == null ? System.currentTimeMillis() : request.revokedAt();
        issuer.revoke(request.keyId(), at, request.reason());
        return Map.of("keyId", request.keyId(), "revokedAt", String.valueOf(at));
    }
}
