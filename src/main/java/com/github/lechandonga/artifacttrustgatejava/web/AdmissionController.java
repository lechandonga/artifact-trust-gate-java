package com.github.lechandonga.artifacttrustgatejava.web;

import com.github.lechandonga.artifacttrustgatejava.model.AdmissionRequest;
import com.github.lechandonga.artifacttrustgatejava.model.AuditRecord;
import com.github.lechandonga.artifacttrustgatejava.model.DecisionResult;
import com.github.lechandonga.artifacttrustgatejava.service.AdmissionService;
import com.github.lechandonga.artifacttrustgatejava.store.AuditStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admission")
public class AdmissionController {

    private final AdmissionService admissionService;
    private final AuditStore auditStore;

    public AdmissionController(AdmissionService admissionService, AuditStore auditStore) {
        this.admissionService = admissionService;
        this.auditStore = auditStore;
    }

    /**
     * 提交制品做准入校验。重复提交（制品/证明/评估上下文相同）返回一致结论，
     * reusedAuditRecord=true 且不新增审计记录。
     */
    @PostMapping("/submit")
    public DecisionResult submit(@RequestBody AdmissionRequest request) {
        return admissionService.submit(request);
    }

    @GetMapping("/audit")
    public List<AuditRecord> audit() {
        return auditStore.findAll();
    }
}
