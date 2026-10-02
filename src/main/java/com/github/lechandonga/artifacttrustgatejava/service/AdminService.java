package com.github.lechandonga.artifacttrustgatejava.service;

import com.github.lechandonga.artifacttrustgatejava.crypto.RsaSignatureService;
import com.github.lechandonga.artifacttrustgatejava.model.DecisionCode;
import com.github.lechandonga.artifacttrustgatejava.model.KeyBookSnapshot;
import com.github.lechandonga.artifacttrustgatejava.model.KeyMaterial;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyRule;
import com.github.lechandonga.artifacttrustgatejava.model.PolicyVersion;
import com.github.lechandonga.artifacttrustgatejava.model.Revocation;
import com.github.lechandonga.artifacttrustgatejava.model.ServiceException;
import com.github.lechandonga.artifacttrustgatejava.store.KeyStore;
import com.github.lechandonga.artifacttrustgatejava.store.PolicyStore;
import com.github.lechandonga.artifacttrustgatejava.store.RevocationLedger;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * 管理面：密钥登记/轮换、带生效时间的吊销（仅追加）、策略版本发布。
 */
@Service
public class AdminService {

    private final KeyStore keyStore;
    private final RevocationLedger revocationLedger;
    private final PolicyStore policyStore;
    private final RsaSignatureService rsa;
    private final Clock clock;

    public AdminService(KeyStore keyStore, RevocationLedger revocationLedger, PolicyStore policyStore,
                        RsaSignatureService rsa, Clock clock) {
        this.keyStore = keyStore;
        this.revocationLedger = revocationLedger;
        this.policyStore = policyStore;
        this.rsa = rsa;
        this.clock = clock;
    }

    public KeyMaterial generateKey(String keyId) {
        if (keyStore.find(keyId).isPresent()) {
            throw new ServiceException(DecisionCode.REJECT_BAD_REQUEST, "密钥 ID 已存在: " + keyId);
        }
        KeyPair pair = rsa.generateKeyPair();
        KeyMaterial material = new KeyMaterial(keyId,
                rsa.publicKeyToPem(pair.getPublic()),
                rsa.privateKeyToPem(pair.getPrivate()),
                Instant.now(clock), null);
        return keyStore.save(material);
    }

    /**
     * 轮换：登记新密钥，并把旧密钥标记为 replacedBy（旧密钥材料保留以验证历史制品）。
     */
    public KeyMaterial rotate(String oldKeyId, String newKeyId) {
        KeyMaterial old = keyStore.find(oldKeyId)
                .orElseThrow(() -> new ServiceException(DecisionCode.REJECT_KEY_UNKNOWN,
                        "旧密钥不存在: " + oldKeyId));
        KeyMaterial fresh = generateKey(newKeyId);
        keyStore.save(new KeyMaterial(old.keyId(), old.publicKeyPem(), old.privateKeyPem(),
                old.createdAt(), newKeyId));
        return fresh;
    }

    /**
     * 吊销：带生效时间，仅追加。
     * 拒绝倒填（revokedAt 早于登记时间），保证“历史判定不被后来的记录改写”；
     * 允许未来时间（定时吊销，未生效前旧证明、新签发照常）。
     */
    public synchronized KeyBookSnapshot revoke(String keyId, Instant effectiveAt, String reason) {
        keyStore.find(keyId)
                .orElseThrow(() -> new ServiceException(DecisionCode.REJECT_KEY_UNKNOWN,
                        "密钥不存在: " + keyId));
        Instant registeredAt = Instant.now(clock);
        if (effectiveAt.isBefore(registeredAt.minus(Duration.ofSeconds(1)))) {
            throw new ServiceException(DecisionCode.REJECT_BAD_REQUEST,
                    "拒绝倒填吊销：生效时间 " + effectiveAt + " 早于登记时间 " + registeredAt);
        }
        boolean duplicate = revocationLedger.findAll().stream()
                .anyMatch(r -> r.keyId().equals(keyId) && r.revokedAt().equals(effectiveAt));
        if (duplicate) {
            throw new ServiceException(DecisionCode.REJECT_BAD_REQUEST,
                    "该密钥的相同生效时间吊销记录已存在: " + keyId + " @ " + effectiveAt);
        }
        return revocationLedger.append(new Revocation(keyId, effectiveAt, registeredAt,
                reason == null ? "" : reason));
    }

    public PolicyVersion publishPolicy(List<PolicyRule> rules) {
        int nextVersion = policyStore.latest().map(PolicyVersion::version).orElse(0) + 1;
        if (rules == null || rules.isEmpty()) {
            throw new ServiceException(DecisionCode.REJECT_BAD_REQUEST, "策略规则不能为空");
        }
        return policyStore.append(new PolicyVersion(nextVersion, Instant.now(clock), List.copyOf(rules)));
    }
}
