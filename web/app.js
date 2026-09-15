
const state = {
    investigation: null,
    analysis: null,
    report: null,
    progressTimer: null,
};

const els = {};

document.addEventListener("DOMContentLoaded", () => {
    cacheElements();
    bindEvents();
    resetApplication();
});

function cacheElements() {
    const ids = [
        "welcome",
        "analyzing",
        "results",

        "uploadForm",
        "dropZone",
        "browseButton",
        "fileInput",
        "fileName",
        "uploadButton",
        "uploadError",

        "newInvestigation",

        "progressBar",
        "analysisStage",
        "analysisFile",
        "stepEvidence",
        "stepHeaders",
        "stepThreat",
        "stepForensics",

        "caseFilename",
        "caseId",

        "riskScore",
        "riskVerdict",
        "verdict",
        "threatCount",
        "integrity",

        "executiveSummary",
        "threatList",

        "urlList",
        "domainList",
        "ipList",

        "identitySender",
        "identityReplyTo",
        "identityReturnPath",
        "authenticationFindings",
        "identityFindings",

        "senderIp",
        "senderCountry",
        "senderRegion",
        "senderCity",
        "senderIsp",
        "senderAsn",
        "senderHostname",
        "geoSource",
        "infrastructureFullData",

        "attachmentList",

        "forensicSummary",
        "timelineList",
        "counterfactualList",
        "attackGraph",
        "custodyList",
    ];

    ids.forEach(id => {
        els[id] = document.getElementById(id);
    });
}

function bindEvents() {
    /*
     * FILE PICKER
     */
    if (els.browseButton && els.fileInput) {
        els.browseButton.addEventListener("click", event => {
            event.preventDefault();
            event.stopPropagation();
            els.fileInput.click();
        });

        els.fileInput.addEventListener("change", () => {
            const file = els.fileInput.files?.[0];

            if (!file) {
                return;
            }

            selectFile(file);
        });
    }

    /*
     * FORM / ANALYZE BUTTON
     */
    if (els.uploadForm) {
        els.uploadForm.addEventListener("submit", handleUpload);
    }

    /*
     * NEW INVESTIGATION
     */
    if (els.newInvestigation) {
        els.newInvestigation.addEventListener(
            "click",
            resetApplication
        );
    }

    /*
     * TABS
     */
    document.querySelectorAll(".tab").forEach(tab => {
        tab.addEventListener("click", () => {
            const tabName = tab.dataset.tab;

            if (!tabName) {
                return;
            }

            document.querySelectorAll(".tab").forEach(item => {
                item.classList.remove("active");
            });

            document.querySelectorAll(".tab-panel").forEach(panel => {
                panel.classList.remove("active");
            });

            tab.classList.add("active");

            const panel = document.getElementById(
                `tab-${tabName}`
            );

            if (panel) {
                panel.classList.add("active");
            }
        });
    });

    /*
     * DRAG AND DROP
     */
    if (els.dropZone && els.fileInput) {
        ["dragenter", "dragover"].forEach(eventName => {
            els.dropZone.addEventListener(
                eventName,
                event => {
                    event.preventDefault();
                    event.stopPropagation();
                    els.dropZone.classList.add("dragging");
                }
            );
        });

        ["dragleave", "drop"].forEach(eventName => {
            els.dropZone.addEventListener(
                eventName,
                event => {
                    event.preventDefault();
                    event.stopPropagation();
                    els.dropZone.classList.remove("dragging");
                }
            );
        });

        els.dropZone.addEventListener("drop", event => {
            const file = event.dataTransfer?.files?.[0];

            if (!file) {
                return;
            }

            selectFile(file);
        });
    }
}

function selectFile(file) {
    if (!file) {
        return;
    }

    if (
        !file.name.toLowerCase().endsWith(".eml")
    ) {
        showError("Please select an .eml email evidence file.");
        return;
    }

    clearError();

    try {
        const transfer = new DataTransfer();
        transfer.items.add(file);
        els.fileInput.files = transfer.files;
    } catch (error) {
        console.warn(
            "Could not programmatically update file input:",
            error
        );
    }

    if (els.fileName) {
        els.fileName.textContent = file.name;
    }

    if (els.uploadButton) {
        els.uploadButton.disabled = false;
    }
}

async function handleUpload(event) {
    event.preventDefault();
    event.stopPropagation();

    clearError();

    const file = els.fileInput?.files?.[0];

    if (!file) {
        showError("Select an .eml evidence file first.");
        return;
    }

    if (
        !file.name.toLowerCase().endsWith(".eml")
    ) {
        showError("Only .eml evidence files are supported.");
        return;
    }

    /*
     * LOCK BUTTON
     */
    if (els.uploadButton) {
        els.uploadButton.disabled = true;
        els.uploadButton.textContent = "Analyzing...";
    }

    showScreen("analyzing");
    startAnalysisProgress(file.name);

    const formData = new FormData();
    formData.append("file", file, file.name);

    try {
        const response = await fetch(
            "/api/investigations/analyze",
            {
                method: "POST",
                body: formData,
                headers: {
                    Accept: "application/json",
                },
            }
        );

        const rawText = await response.text();

        let payload;

        try {
            payload = rawText
                ? JSON.parse(rawText)
                : {};
        } catch {
            throw new Error(
                `Server returned invalid JSON (${response.status}).`
            );
        }

        if (!response.ok) {
            throw new Error(
                payload.detail ||
                payload.message ||
                `Analysis failed with HTTP ${response.status}.`
            );
        }

        stopAnalysisProgress();

        loadInvestigation(payload);

    } catch (error) {
        console.error(
            "Sentinel AI analysis error:",
            error
        );

        stopAnalysisProgress();

        showScreen("welcome");

        showError(
            error?.message ||
            "Could not analyze the email."
        );

        if (els.uploadButton) {
            els.uploadButton.disabled = false;
            els.uploadButton.textContent = "Analyze Email";
        }
    }
}

function startAnalysisProgress(filename) {
    stopAnalysisProgress();

    if (els.analysisFile) {
        els.analysisFile.textContent = filename;
    }

    if (els.progressBar) {
        els.progressBar.style.width = "5%";
    }

    if (els.analysisStage) {
        els.analysisStage.textContent =
            "Initializing forensic engine...";
    }

    [
        els.stepEvidence,
        els.stepHeaders,
        els.stepThreat,
        els.stepForensics,
    ].forEach(step => {
        if (step) {
            step.classList.remove("active");
            step.classList.remove("complete");
        }
    });

    const stages = [
        {
            progress: 20,
            stage: "Preserving evidence...",
            step: els.stepEvidence,
        },
        {
            progress: 40,
            stage: "Parsing headers and identity...",
            step: els.stepHeaders,
        },
        {
            progress: 70,
            stage: "Correlating threat indicators...",
            step: els.stepThreat,
        },
        {
            progress: 90,
            stage: "Building forensic reconstruction...",
            step: els.stepForensics,
        },
    ];

    let index = 0;

    state.progressTimer = setInterval(() => {
        if (index >= stages.length) {
            stopAnalysisProgress();
            return;
        }

        const item = stages[index];

        if (item.step) {
            item.step.classList.add("active");

            if (index > 0 && stages[index - 1].step) {
                stages[index - 1].step.classList.remove("active");
                stages[index - 1].step.classList.add("complete");
            }
        }

        if (els.progressBar) {
            els.progressBar.style.width =
                `${item.progress}%`;
        }

        if (els.analysisStage) {
            els.analysisStage.textContent =
                item.stage;
        }

        index++;
    }, 800);
}

function stopAnalysisProgress() {
    if (state.progressTimer) {
        clearInterval(state.progressTimer);
        state.progressTimer = null;
    }
}

function loadInvestigation(payload) {
    const root = parseValue(payload) || {};

    state.investigation = root;

    state.analysis =
        parseValue(root.analysis) || root;

    state.report =
        parseValue(root.report) || {};

    renderDashboard();

    if (els.progressBar) {
        els.progressBar.style.width = "100%";
    }

    if (els.analysisStage) {
        els.analysisStage.textContent =
            "Investigation complete.";
    }

    setTimeout(() => {
        showScreen("results");

        requestAnimationFrame(() => {
            increasePostAnalysisFontSize(4);
        });
    }, 150);
}

function renderDashboard() {
    const data = state.investigation || {};
    const analysis = state.analysis || {};
    const report = state.report || {};

    renderCase(data);
    renderRisk(data, analysis);
    renderOverview(data, analysis, report);
    renderThreats(data, analysis);
    renderLinks(data, analysis);
    renderIdentity(data, analysis);
    renderInfrastructure(data, analysis);
    renderAttachments(data, analysis);
    renderForensics(data, analysis, report);
}

function renderCase(data) {
    setText(
        els.caseFilename,
        data.filename ||
        data.original_filename ||
        "Unknown"
    );

    setText(
        els.caseId,
        data.investigation_id ||
        "Unknown"
    );
}

function renderRisk(data, analysis) {
    const score = number(
        data.risk_score,
        analysis.risk_score,
        analysis.risk?.score
    );

    const backendVerdict = text(
        data.verdict,
        analysis.verdict,
        analysis.risk?.verdict,
        ""
    );

    const confidence = number(
        data.confidence,
        analysis.confidence,
        analysis.risk?.confidence
    );

    const threats = collectFindings(
        data,
        analysis
    );

    /*
     * FOUR LEVEL VERDICT
     *
     * 0 - 14   SAFE
     * 15 - 34  LOW
     * 35 - 79  DANGER
     * 80 - 100 CRITICAL
     */
    let verdict;

    if (score >= 80) {
        verdict = "critical";
    } else if (score >= 35) {
        verdict = "danger";
    } else if (score >= 15) {
        verdict = "low";
    } else {
        verdict = "safe";
    }

    const normalizedBackendVerdict =
        backendVerdict.toLowerCase().trim();

    if (
        !score &&
        [
            "critical",
            "danger",
            "malicious",
            "threat"
        ].includes(normalizedBackendVerdict)
    ) {
        verdict =
            normalizedBackendVerdict === "critical"
                ? "critical"
                : "danger";
    }

    setText(
        els.riskScore,
        `${Math.round(score)}`
    );

    setText(
        els.riskVerdict,
        verdict.toUpperCase()
    );

    setText(
        els.verdict,
        verdict.toUpperCase()
    );

    setText(
        els.threatCount,
        threats.length
    );

    setText(
        els.integrity,
        data.evidence_integrity ||
        analysis.evidence_integrity ||
        "Verified"
    );

    if (els.riskScore) {
        els.riskScore.classList.remove(
            "risk-safe",
            "risk-low",
            "risk-medium",
            "risk-high",
            "risk-critical"
        );

        if (score >= 80) {
            els.riskScore.classList.add(
                "risk-critical"
            );
        } else if (score >= 35) {
            els.riskScore.classList.add(
                "risk-high"
            );
        } else if (score >= 15) {
            els.riskScore.classList.add(
                "risk-low"
            );
        } else {
            els.riskScore.classList.add(
                "risk-safe"
            );
        }
    }

    if (els.verdict) {
        els.verdict.dataset.verdict =
            verdict.toLowerCase();
    }

    document.body.dataset.confidence =
        String(confidence);
}

function renderOverview(data, analysis, report) {
    const summary = text(
        data.executive_summary,
        report.executive_summary,
        analysis.executive_summary,
        "No executive summary was returned."
    );

    setHTML(
        els.executiveSummary,
        formatText(summary)
    );
}


/* =========================================================
   THREATS
========================================================= */

function renderThreats(data, analysis) {
    const findings = collectFindings(
        data,
        analysis
    );

    if (!findings.length) {
        setEmpty(
            els.threatList,
            "No confirmed threats identified."
        );
        return;
    }

    setHTML(
        els.threatList,
        findings.map((finding, index) => {

            if (typeof finding === "string") {
                return `
                    <article class="finding-card">

                        <div class="finding-top">

                            <strong>
                                Finding ${index + 1}
                            </strong>

                            <span class="severity-badge">
                                THREAT
                            </span>

                        </div>

                        <p>
                            ${formatText(finding)}
                        </p>

                    </article>
                `;
            }

            const title = text(
                finding.title,
                finding.name,
                finding.finding,
                `Finding ${index + 1}`
            );

            const description = text(
                finding.description,
                finding.explanation,
                finding.message,
                finding.details,
                ""
            );

            const severity = text(
                finding.severity,
                finding.level,
                finding.risk,
                finding.threat_level,
                "THREAT"
            );

            const confidence =
                finding.confidence !== undefined
                    ? formatConfidence(
                        finding.confidence
                    )
                    : "";

            const evidence = uniqueStrings(
                finding.supporting_indicators,
                finding.evidence,
                finding.indicators,
                finding.evidence_items
            );

            return `
                <article class="
                    finding-card
                    severity-${escapeHtml(
                        severity.toLowerCase()
                    )}
                ">

                    <div class="finding-top">

                        <strong>
                            Finding ${index + 1}
                        </strong>

                        <span class="severity-badge">
                            ${escapeHtml(
                                severity.toUpperCase()
                            )}
                        </span>

                    </div>

                    <div class="finding-title">
                        ${escapeHtml(title)}
                    </div>

                    ${
                        description
                            ? `
                                <p>
                                    ${formatText(
                                        description
                                    )}
                                </p>
                            `
                            : ""
                    }

                    ${
                        confidence
                            ? `
                                <small>
                                    Confidence:
                                    ${escapeHtml(
                                        confidence
                                    )}
                                </small>
                            `
                            : ""
                    }

                    ${
                        evidence.length
                            ? `
                                <div class="data-section">

                                    <div class="attachment-section-title">
                                        EVIDENCE
                                    </div>

                                    ${evidence.map(
                                        indicator => `
                                            <div class="data-row">

                                                <span>
                                                    Evidence
                                                </span>

                                                <strong class="mono">
                                                    ${escapeHtml(
                                                        indicator
                                                    )}
                                                </strong>

                                            </div>
                                        `
                                    ).join("")}

                                </div>
                            `
                            : finding.supporting_indicators
                                ? `
                                    <div class="data-section">

                                        <div class="attachment-section-title">
                                            EVIDENCE
                                        </div>

                                        ${renderValueRows(
                                            array(
                                                finding.supporting_indicators
                                            ),
                                            "Evidence"
                                        )}

                                    </div>
                                `
                                : ""
                    }

                </article>
            `;
        }).join("")
    );
}


/* =========================================================
   LINKS
========================================================= */

function renderLinks(data, analysis) {
    const urls = uniqueStrings(
        data.urls,
        analysis.urls,
        analysis.indicators?.urls,
        analysis.extracted_indicators?.urls
    );

    const domains = uniqueStrings(
        data.domains,
        analysis.domains,
        analysis.indicators?.domains,
        analysis.extracted_indicators?.domains
    );

    const ips = uniqueStrings(
        data.ip_addresses,
        analysis.ip_addresses,
        analysis.indicators?.ip_addresses,
        analysis.extracted_indicators?.ip_addresses
    );

    renderList(
        els.urlList,
        urls,
        "No URLs detected."
    );

    renderList(
        els.domainList,
        domains,
        "No domains detected."
    );

    renderList(
        els.ipList,
        ips,
        "No IP addresses detected."
    );
}


/* =========================================================
   IDENTITY
========================================================= */

function renderIdentity(data, analysis) {
    const identity = object(
        data.identity,
        analysis.identity
    );

    const authentication = object(
        data.authentication,
        analysis.authentication
    );

    setText(
        els.identitySender,
        identity.sender ||
        identity.from ||
        analysis.email?.sender ||
        "Not available"
    );

    setText(
        els.identityReplyTo,
        identity.reply_to ||
        identity.replyTo ||
        analysis.email?.reply_to ||
        "Not available"
    );

    setText(
        els.identityReturnPath,
        identity.return_path ||
        identity.returnPath ||
        analysis.email?.return_path ||
        "Not available"
    );

    const authenticationFindings = array(
        authentication.findings,
        data.authentication_findings,
        analysis.authentication_findings
    );

    const identityFindings = array(
        identity.findings,
        data.identity_findings,
        analysis.identity_findings
    );

    if (authenticationFindings.length) {
        setHTML(
            els.authenticationFindings,
            renderValueRows(
                authenticationFindings,
                "Authentication"
            )
        );
    } else {
        setHTML(
            els.authenticationFindings,
            renderObject(authentication)
        );
    }

    if (identityFindings.length) {
        setHTML(
            els.identityFindings,
            renderValueRows(
                identityFindings,
                "Identity"
            )
        );
    } else {
        setEmpty(
            els.identityFindings,
            "No identity findings returned."
        );
    }
}


/* =========================================================
   INFRASTRUCTURE
========================================================= */

function renderInfrastructure(data, analysis) {
    const infrastructure = array(
        data.infrastructure,
        analysis.infrastructure,
        analysis.infrastructure_intelligence,
        analysis.sender_infrastructure
    );

    const first = infrastructure[0] || {};

    const geo = object(
        first.geo,
        first.geolocation,
        first.geo_location,
        first.location,
        first.geoip,
        first.geo_ip,
        analysis.geo,
        analysis.geolocation,
        data.geo,
        data.geolocation
    );

    const network = object(
        first.network,
        first.network_intelligence,
        first.infrastructure,
        analysis.network,
        analysis.infrastructure_intelligence
    );

    setText(
        els.senderIp,
        text(
            first.ip_address,
            first.ip,
            first.address,
            geo.ip_address,
            geo.ip,
            data.sender_ip,
            analysis.sender_ip,
            "Not identified"
        )
    );

    setText(
        els.senderCountry,
        text(
            first.country,
            first.country_name,
            geo.country,
            geo.country_name,
            geo.country_code,
            network.country,
            "Not available"
        )
    );

    setText(
        els.senderRegion,
        text(
            first.region,
            first.region_name,
            first.state,
            first.state_name,
            first.province,
            first.province_name,
            geo.region,
            geo.region_name,
            geo.state,
            geo.state_name,
            geo.province,
            geo.province_name,
            "Not available"
        )
    );

    setText(
        els.senderCity,
        text(
            first.city,
            first.city_name,
            geo.city,
            geo.city_name,
            "Not available"
        )
    );

    setText(
        els.senderIsp,
        text(
            first.isp,
            first.isp_name,
            first.org,
            first.organization,
            first.organization_name,
            geo.isp,
            geo.organization,
            network.isp,
            network.organization,
            "Not available"
        )
    );

    setText(
        els.senderAsn,
        text(
            first.asn,
            first.as_number,
            first.asn_number,
            first.asn_name,
            geo.asn,
            network.asn,
            "Not available"
        )
    );

    setText(
        els.senderHostname,
        text(
            first.hostname,
            first.host,
            first.reverse_dns,
            first.reverse_dns_hostname,
            geo.hostname,
            "Not available"
        )
    );

    setText(
        els.geoSource,
        text(
            first.source,
            first.geolocation_source,
            first.geo_source,
            geo.source,
            geo.provider,
            network.source,
            "Backend infrastructure intelligence"
        )
    );

    if (els.infrastructureFullData) {
        if (!infrastructure.length) {
            els.infrastructureFullData.innerHTML = "";
        } else {
            els.infrastructureFullData.innerHTML =
                infrastructure.map(
                    (item, index) => `
                        <div class="finding-card">

                            <div class="finding-top">
                                <strong>
                                    Infrastructure ${index + 1}
                                </strong>
                            </div>

                            ${renderObject(item)}

                        </div>
                    `
                ).join("");
        }
    }
}


/* =========================================================
   ATTACHMENTS
========================================================= */

function renderAttachments(data, analysis) {
    const attachmentAnalysis = uniqueValues(
        data.attachment_analysis,
        analysis.attachment_analysis,
        analysis.attachment_findings
    );

    const richerSources = [
        analysis.attachments,
        analysis.attachment_details,
        analysis.attachment_forensics,
        analysis.parsed_attachments,
        analysis.parsed_email?.attachments,
        data.attachments,
    ];

    const richerAttachments = [];

    richerSources.forEach(source => {
        array(source).forEach(item => {
            if (
                item &&
                typeof item === "object" &&
                !Array.isArray(item)
            ) {
                richerAttachments.push(item);
            }
        });
    });

    const uniqueRichAttachments = [];
    const seenRich = new Set();

    richerAttachments.forEach(item => {
        const key = JSON.stringify(item);

        if (seenRich.has(key)) {
            return;
        }

        seenRich.add(key);
        uniqueRichAttachments.push(item);
    });

    if (
        !attachmentAnalysis.length &&
        !uniqueRichAttachments.length
    ) {
        setEmpty(
            els.attachmentList,
            "No email attachment analysis returned."
        );
        return;
    }

    const cards = [];

    attachmentAnalysis.forEach(
        (item, index) => {

            if (
                item &&
                typeof item === "object"
            ) {
                return;
            }

            const value = String(item || "").trim();

            if (!value) {
                return;
            }

            const status =
                getAttachmentStatus(value);

            cards.push(`
                <article class="attachment">

                    <div class="attachment-header">

                        <div>
                            <div class="attachment-name">
                                Attachment Analysis
                            </div>

                            <div class="attachment-subtitle">
                                Attachment ${index + 1}
                            </div>
                        </div>

                        <span class="
                            attachment-badge
                            ${
                                status === "THREAT"
                                    ? "danger"
                                    : "neutral"
                            }
                        ">
                            ${escapeHtml(status)}
                        </span>

                    </div>

                    <div class="attachment-section">

                        <div class="attachment-section-title">
                            BACKEND ANALYSIS
                        </div>

                        <div class="finding">
                            ${formatText(value)}
                        </div>

                    </div>

                </article>
            `);
        }
    );

    uniqueRichAttachments.forEach(
        (item, index) => {

            const filename =
                item.filename ||
                item.file_name ||
                item.attachment_filename ||
                item.name ||
                `Attachment ${index + 1}`;

            const mime =
                item.content_type ||
                item.mime_type ||
                item.media_type ||
                "Unknown MIME";

            const extension =
                item.extension ||
                getFileExtension(filename) ||
                "Unknown";

            const size =
                item.size_bytes ??
                item.size ??
                item.file_size ??
                "Unknown";

            const sha256 =
                item.sha256 ||
                item.sha256_hash ||
                item.hash ||
                "";

            const status =
                getAttachmentObjectStatus(item);

            cards.push(`
                <article class="attachment">

                    <div class="attachment-header">

                        <div>
                            <div class="attachment-name">
                                ${escapeHtml(filename)}
                            </div>

                            <div class="attachment-subtitle">
                                Attachment ${index + 1}
                            </div>
                        </div>

                        <span class="
                            attachment-badge
                            ${
                                status === "THREAT"
                                    ? "danger"
                                    : "neutral"
                            }
                        ">
                            ${escapeHtml(status)}
                        </span>

                    </div>

                    <div class="attachment-details">

                        <div class="attachment-detail">
                            <small>MIME TYPE</small>
                            <strong>
                                ${escapeHtml(mime)}
                            </strong>
                        </div>

                        <div class="attachment-detail">
                            <small>EXTENSION</small>
                            <strong>
                                ${escapeHtml(
                                    String(extension)
                                )}
                            </strong>
                        </div>

                        <div class="attachment-detail">
                            <small>SIZE</small>
                            <strong>
                                ${escapeHtml(
                                    formatBytes(size)
                                )}
                            </strong>
                        </div>

                        <div class="attachment-detail">
                            <small>SHA-256</small>
                            <strong>
                                ${escapeHtml(
                                    sha256 || "Not returned"
                                )}
                            </strong>
                        </div>

                    </div>

                    <div class="attachment-section">

                        <div class="attachment-section-title">
                            BACKEND RESPONSE
                        </div>

                        ${renderObject(item)}

                    </div>

                </article>
            `);
        }
    );

    if (!cards.length) {
        setEmpty(
            els.attachmentList,
            "No email attachment analysis returned."
        );
        return;
    }

    setHTML(
        els.attachmentList,
        cards.join("")
    );
}

function getAttachmentStatus(value) {
    const normalized =
        String(value || "")
            .toLowerCase()
            .replace(/\s+/g, " ")
            .trim();

    if (!normalized) {
        return "UNKNOWN";
    }

    const negativePatterns = [
        "no threat",
        "no threats",
        "no malicious",
        "no malware",
        "no phishing",
        "no suspicious",
        "not malicious",
        "not a threat",
        "not suspicious",
        "not detected",
        "not identified",
        "did not identify",
        "didn't identify",
        "did not detect",
        "didn't detect",
        "no evidence",
        "no security threat",
        "no threat detected",
        "no malicious content",
        "no malicious attachment",
        "no malicious file",
        "benign",
        "clean",
        "safe",
    ];

    if (
        negativePatterns.some(
            pattern => normalized.includes(pattern)
        )
    ) {
        return "SAFE";
    }

    const unsafePatterns = [
        "unsafe",
        "malicious attachment",
        "malicious file",
        "malware",
        "ransomware",
        "trojan",
        "payload",
        "exploit",
        "credential theft",
        "credential harvesting",
        "phishing attachment",
        "malicious content",
        "confirmed threat",
        "high risk",
        "critical risk",
        "dangerous attachment",
        "dangerous file",
    ];

    if (
        unsafePatterns.some(
            pattern => normalized.includes(pattern)
        )
    ) {
        return "THREAT";
    }

    return "UNKNOWN";
}

function getAttachmentObjectStatus(item) {
    if (
        item.is_threat === false ||
        item.threat === false ||
        item.malicious === false ||
        item.is_malicious === false
    ) {
        return "SAFE";
    }

    if (
        item.is_threat === true ||
        item.threat === true ||
        item.malicious === true ||
        item.is_malicious === true
    ) {
        return "THREAT";
    }

    const combinedText = JSON.stringify(item)
        .toLowerCase();

    if (
        containsNegativeThreatStatement(
            combinedText
        )
    ) {
        return "SAFE";
    }

    const verdict = text(
        item.verdict,
        item.classification,
        item.status,
        item.security_verdict,
        ""
    ).toLowerCase().trim();

    if (
        [
            "safe",
            "benign",
            "clean",
            "not malicious",
            "not suspicious",
            "no threat",
        ].includes(verdict)
    ) {
        return "SAFE";
    }

    if (
        [
            "malicious",
            "threat",
            "confirmed threat",
            "dangerous",
        ].includes(verdict)
    ) {
        return "THREAT";
    }

    const severity = text(
        item.severity,
        item.risk,
        item.threat_level,
        ""
    ).toLowerCase().trim();

    if (
        [
            "critical",
            "high",
        ].includes(severity)
    ) {
        return "THREAT";
    }

    return "UNKNOWN";
}


/* =========================================================
   FORENSICS
========================================================= */

function renderForensics(data, analysis, report) {
    const summary = text(
        report.executive_summary,
        data.executive_summary,
        analysis.executive_summary,
        "No forensic summary returned."
    );

    const score = number(
        data.risk_score,
        analysis.risk_score,
        analysis.risk?.score
    );

    const verdict = text(
        data.verdict,
        analysis.verdict,
        analysis.risk?.verdict,
        "unknown"
    );

    const confidence = number(
        data.confidence,
        analysis.confidence,
        analysis.risk?.confidence
    );

    const findingCount =
        collectFindings(data, analysis).length;

    setHTML(
        els.forensicSummary,
        `
            <div class="forensic-report">

                <div class="report-title">

                    <span>
                        SECURITY INVESTIGATION REPORT
                    </span>

                    <strong>
                        ${escapeHtml(
                            text(
                                data.investigation_id,
                                "UNKNOWN CASE"
                            )
                        )}
                    </strong>

                </div>

                <div class="report-meta">

                    <div>
                        <span>VERDICT</span>
                        <strong>
                            ${escapeHtml(
                                verdict.toUpperCase()
                            )}
                        </strong>
                    </div>

                    <div>
                        <span>RISK</span>
                        <strong>
                            ${Math.round(score)}/100
                        </strong>
                    </div>

                    <div>
                        <span>CONFIDENCE</span>
                        <strong>
                            ${formatConfidence(confidence)}
                        </strong>
                    </div>

                    <div>
                        <span>FINDINGS</span>
                        <strong>
                            ${findingCount}
                        </strong>
                    </div>

                </div>

                <div class="report-section">

                    <h3>Executive Finding</h3>

                    <p>
                        ${formatText(summary)}
                    </p>

                </div>

                <div class="report-section">

                    <h3>Evidence Identity</h3>

                    <div class="data-row">
                        <span>Filename</span>
                        <strong>
                            ${escapeHtml(
                                text(
                                    data.filename,
                                    "Unknown"
                                )
                            )}
                        </strong>
                    </div>

                    <div class="data-row">
                        <span>Evidence ID</span>
                        <strong class="mono">
                            ${escapeHtml(
                                text(
                                    data.evidence_id,
                                    "Unknown"
                                )
                            )}
                        </strong>
                    </div>

                    <div class="data-row">
                        <span>SHA-256</span>
                        <strong class="mono">
                            ${escapeHtml(
                                text(
                                    data.sha256,
                                    "Unavailable"
                                )
                            )}
                        </strong>
                    </div>

                    <div class="data-row">
                        <span>Media Type</span>
                        <strong>
                            ${escapeHtml(
                                text(
                                    data.media_type,
                                    "message/rfc822"
                                )
                            )}
                        </strong>
                    </div>

                </div>

                <div class="report-section">

                    <h3>Evidence Integrity</h3>

                    <p>
                        ${formatText(
                            text(
                                data.evidence_integrity,
                                "Evidence integrity verified through preserved SHA-256 evidence."
                            )
                        )}
                    </p>

                </div>

                <div class="report-section">

                    <h3>Security Evidence Summary</h3>

                    ${renderEvidenceSummary(
                        data,
                        analysis
                    )}

                </div>

                <div class="report-section">

                    <h3>Analyst Assessment</h3>

                    ${renderRecommendations(
                        report,
                        analysis
                    )}

                </div>

            </div>
        `
    );

    renderTimeline(
        data.timeline ||
        analysis.timeline
    );

    renderCounterfactuals(
        data.counterfactual_scenarios ||
        analysis.counterfactual?.scenarios
    );

    renderAttackGraph(
        data.evidence_graph ||
        analysis.evidence_graph ||
        analysis.attack_graph
    );

    renderCustody(
        data.custody ||
        []
    );
}

function renderEvidenceSummary(data, analysis) {
    const urls = uniqueStrings(
        data.urls,
        analysis.urls
    );

    const domains = uniqueStrings(
        data.domains,
        analysis.domains
    );

    const ips = uniqueStrings(
        data.ip_addresses,
        analysis.ip_addresses
    );

    const findings =
        collectFindings(data, analysis);

    const correlations = array(
        data.correlated_findings,
        analysis.correlated_findings
    );

    const attachments = uniqueValues(
        data.attachment_analysis,
        analysis.attachment_analysis
    );

    return [
        ["URLs", urls.length],
        ["Domains", domains.length],
        ["IP addresses", ips.length],
        ["Threat findings", findings.length],
        ["Correlated findings", correlations.length],
        ["Attachments", attachments.length],
    ].map(([label, value]) => `
        <div class="data-row">

            <span>
                ${escapeHtml(label)}
            </span>

            <strong>
                ${escapeHtml(String(value))}
            </strong>

        </div>
    `).join("");
}

function renderRecommendations(report, analysis) {
    const recommendations = array(
        report.recommendations,
        report.recommended_actions,
        analysis.recommendations,
        analysis.recommended_actions
    );

    if (!recommendations.length) {
        return `
            <p>
                No automated remediation recommendations
                were returned by the backend.
                Analyst review is recommended before
                containment or release decisions.
            </p>
        `;
    }

    return `
        <ul>
            ${recommendations.map(item => `
                <li>
                    ${formatValue(item)}
                </li>
            `).join("")}
        </ul>
    `;
}

function renderTimeline(timeline) {
    const events = array(timeline);

    if (!events.length) {
        setEmpty(
            els.timelineList,
            "No timestamped forensic events returned."
        );
        return;
    }

    setHTML(
        els.timelineList,
        events.map(event => `
            <article class="timeline-item">

                <strong>
                    ${escapeHtml(
                        text(
                            event.title,
                            event.event_type,
                            "Forensic Event"
                        )
                    )}
                </strong>

                <time>
                    ${escapeHtml(
                        text(
                            event.timestamp,
                            "Unknown timestamp"
                        )
                    )}
                </time>

                <p>
                    ${formatText(
                        text(
                            event.description,
                            "No description."
                        )
                    )}
                </p>

                ${
                    event.source
                        ? `
                            <small>
                                Source:
                                ${escapeHtml(
                                    event.source
                                )}
                            </small>
                        `
                        : ""
                }

            </article>
        `).join("")
    );
}

function renderCounterfactuals(scenarios) {
    const items = array(scenarios);

    if (!items.length) {
        setEmpty(
            els.counterfactualList,
            "No counterfactual scenarios returned."
        );
        return;
    }

    setHTML(
        els.counterfactualList,
        items.map(item => `
            <article class="finding-card">

                <div class="finding-top">

                    <strong>
                        ${escapeHtml(
                            text(
                                item.removed_indicator,
                                item.scenario_id,
                                "Evidence removed"
                            )
                        )}
                    </strong>

                </div>

                <div class="data-row">
                    <span>Original score</span>
                    <strong>
                        ${formatValue(
                            item.original_score
                        )}
                    </strong>
                </div>

                <div class="data-row">
                    <span>Counterfactual score</span>
                    <strong>
                        ${formatValue(
                            item.counterfactual_score
                        )}
                    </strong>
                </div>

                <div class="data-row">
                    <span>Score delta</span>
                    <strong>
                        ${formatValue(
                            item.score_delta
                        )}
                    </strong>
                </div>

                <div class="data-row">
                    <span>Original verdict</span>
                    <strong>
                        ${escapeHtml(
                            text(
                                item.original_verdict,
                                "Unknown"
                            )
                        )}
                    </strong>
                </div>

                <div class="data-row">
                    <span>Counterfactual verdict</span>
                    <strong>
                        ${escapeHtml(
                            text(
                                item.counterfactual_verdict,
                                "Unknown"
                            )
                        )}
                    </strong>
                </div>

                <p>
                    ${formatText(
                        text(
                            item.explanation,
                            "No explanation returned."
                        )
                    )}
                </p>

            </article>
        `).join("")
    );
}

function renderAttackGraph(graph) {
    const graphs = array(graph);

    if (!graphs.length) {
        setEmpty(
            els.attackGraph,
            "No evidence relationship graph returned."
        );
        return;
    }

    const graphData = graphs[0] || {};

    const nodes = array(
        graphData.nodes
    );

    const edges = array(
        graphData.edges
    );

    setHTML(
        els.attackGraph,
        `
            <div class="graph-summary">

                <strong>
                    ${nodes.length}
                </strong>

                nodes

                <span>•</span>

                <strong>
                    ${edges.length}
                </strong>

                relationships

            </div>

            <div class="graph-nodes">

                ${nodes.map(node => `
                    <div class="graph-node">

                        <small>
                            ${escapeHtml(
                                text(
                                    node.type,
                                    "evidence"
                                )
                            )}
                        </small>

                        <strong>
                            ${escapeHtml(
                                text(
                                    node.label,
                                    node.id,
                                    "Unknown"
                                )
                            )}
                        </strong>

                    </div>
                `).join("")}

            </div>

            ${
                edges.length
                    ? `
                        <div class="graph-edges">

                            ${edges.map(edge => `
                                <div class="data-row">

                                    <span>
                                        ${escapeHtml(
                                            text(
                                                edge.source,
                                                "?"
                                            )
                                        )}

                                        →

                                        ${escapeHtml(
                                            text(
                                                edge.target,
                                                "?"
                                            )
                                        )}
                                    </span>

                                    <strong>
                                        ${escapeHtml(
                                            text(
                                                edge.relationship,
                                                "related"
                                            )
                                        )}
                                    </strong>

                                </div>
                            `).join("")}

                        </div>
                    `
                    : ""
            }
        `
    );
}

function renderCustody(custody) {
    const events = array(custody);

    if (!events.length) {
        setEmpty(
            els.custodyList,
            "No chain-of-custody events returned."
        );
        return;
    }

    setHTML(
        els.custodyList,
        events.map(event => `
            <article class="timeline-item">

                <strong>
                    ${escapeHtml(
                        text(
                            event.event_type,
                            "Custody event"
                        )
                    )}
                </strong>

                <time>
                    ${escapeHtml(
                        text(
                            event.timestamp,
                            "Unknown timestamp"
                        )
                    )}
                </time>

                <p>
                    ${formatText(
                        text(
                            event.description,
                            ""
                        )
                    )}
                </p>

                <small>
                    Actor:
                    ${escapeHtml(
                        text(
                            event.actor,
                            "unknown"
                        )
                    )}
                </small>

                ${
                    event.evidence_sha256
                        ? `
                            <small class="mono">
                                SHA-256:
                                ${escapeHtml(
                                    event.evidence_sha256
                                )}
                            </small>
                        `
                        : ""
                }

            </article>
        `).join("")
    );
}


/* =========================================================
   THREAT TRIAGE
========================================================= */

function collectFindings(data, analysis) {
    const explicitThreatSources = [
        data.threat_findings,
        analysis.threat_findings,
        data.correlated_findings,
        analysis.correlated_findings,
    ];

    const genericFindingSources = [
        data.findings,
        analysis.findings,
        analysis.risk?.findings,
    ];

    const result = [];
    const seen = new Set();

    explicitThreatSources.forEach(source => {
        array(source).forEach(item => {

            if (!item) {
                return;
            }

            if (typeof item === "string") {
                if (!isRealThreatText(item)) {
                    return;
                }

                const key =
                    item.trim().toLowerCase();

                if (seen.has(key)) {
                    return;
                }

                seen.add(key);
                result.push(item);

                return;
            }

            if (
                typeof item === "object" &&
                isRealThreatFinding(item)
            ) {
                const key =
                    getFindingKey(item);

                if (seen.has(key)) {
                    return;
                }

                seen.add(key);
                result.push(item);
            }
        });
    });

    genericFindingSources.forEach(source => {
        array(source).forEach(item => {

            if (!item) {
                return;
            }

            if (typeof item === "string") {
                if (!isRealThreatText(item)) {
                    return;
                }

                const key =
                    item.trim().toLowerCase();

                if (seen.has(key)) {
                    return;
                }

                seen.add(key);
                result.push(item);

                return;
            }

            if (
                typeof item === "object" &&
                isRealThreatFinding(item)
            ) {
                const key =
                    getFindingKey(item);

                if (seen.has(key)) {
                    return;
                }

                seen.add(key);
                result.push(item);
            }
        });
    });

    return result;
}

function getFindingKey(finding) {
    return JSON.stringify([
        finding.finding_id,
        finding.title,
        finding.name,
        finding.finding,
        finding.description,
        finding.severity,
        finding.level,
        finding.confidence,
    ]);
}

function isRealThreatFinding(finding) {
    if (
        !finding ||
        typeof finding !== "object"
    ) {
        return false;
    }

    if (
        finding.is_threat === false ||
        finding.threat === false ||
        finding.malicious === false ||
        finding.is_malicious === false
    ) {
        return false;
    }

    if (
        finding.is_threat === true ||
        finding.threat === true ||
        finding.malicious === true ||
        finding.is_malicious === true
    ) {
        const explicitText = [
            finding.title,
            finding.name,
            finding.finding,
            finding.description,
            finding.explanation,
            finding.message,
            finding.details,
        ].filter(Boolean).join(" ");

        if (
            containsNegativeThreatStatement(
                explicitText
            )
        ) {
            return false;
        }

        return true;
    }

    const severity = text(
        finding.severity,
        finding.level,
        finding.risk,
        finding.threat_level,
        finding.priority,
        ""
    ).toLowerCase().trim();

    const verdict = text(
        finding.verdict,
        finding.threat_verdict,
        finding.classification,
        finding.status,
        ""
    ).toLowerCase().trim();

    const type = text(
        finding.type,
        finding.category,
        finding.finding_type,
        finding.indicator_type,
        ""
    ).toLowerCase();

    const title = text(
        finding.title,
        finding.name,
        finding.finding,
        ""
    ).toLowerCase();

    const description = text(
        finding.description,
        finding.explanation,
        finding.message,
        finding.details,
        ""
    ).toLowerCase();

    const textBlob = `
        ${title}
        ${type}
        ${verdict}
        ${severity}
        ${description}
    `.replace(/\s+/g, " ").trim();

    if (
        containsNegativeThreatStatement(
            textBlob
        )
    ) {
        return false;
    }

    const informationalWords = [
        "observed",
        "observation",
        "extracted",
        "present",
        "available",
        "url anomaly",
        "url observed",
        "domain observed",
        "ip observed",
        "link observed",
        "indicator observed",
        "header observed",
        "metadata",
        "informational",
        "info",
    ];

    const isObservation =
        informationalWords.some(
            word => textBlob.includes(word)
        );

    if (isObservation) {
        const explicitlySerious = [
            "critical",
            "high",
            "malicious",
            "confirmed threat",
            "active threat",
            "dangerous",
            "compromised",
        ].some(
            word => textBlob.includes(word)
        );

        if (!explicitlySerious) {
            return false;
        }
    }

    if (
        [
            "critical",
            "high",
            "severe",
        ].includes(severity)
    ) {
        return true;
    }

    if (
        [
            "malicious",
            "confirmed threat",
            "true positive",
            "dangerous",
            "compromised",
        ].includes(verdict)
    ) {
        return true;
    }

    const threatWords = [
        "phishing",
        "malware",
        "credential theft",
        "credential harvesting",
        "ransomware",
        "trojan",
        "payload",
        "exploit",
        "command and control",
        "command & control",
        "c2",
        "backdoor",
        "impersonation",
        "spoofing",
        "malicious attachment",
        "malicious file",
        "malicious url",
        "malicious domain",
        "malicious ip",
    ];

    return threatWords.some(
        word => textBlob.includes(word)
    );
}

function isRealThreatText(value) {
    const normalized =
        String(value || "")
            .toLowerCase()
            .replace(/\s+/g, " ")
            .trim();

    if (!normalized) {
        return false;
    }

    if (
        containsNegativeThreatStatement(
            normalized
        )
    ) {
        return false;
    }

    const observationWords = [
        "observed",
        "extracted",
        "url anomaly",
        "url observed",
        "domain observed",
        "ip observed",
        "link observed",
        "indicator observed",
        "informational",
        "metadata",
    ];

    if (
        observationWords.some(
            word => normalized.includes(word)
        )
    ) {
        const explicitThreat =
            [
                "malicious",
                "confirmed threat",
                "active threat",
                "dangerous",
                "compromised",
            ].some(
                word => normalized.includes(word)
            );

        if (!explicitThreat) {
            return false;
        }
    }

    const seriousWords = [
        "phishing",
        "malware",
        "credential theft",
        "credential harvesting",
        "ransomware",
        "trojan",
        "payload",
        "exploit",
        "command and control",
        "command & control",
        "c2",
        "backdoor",
        "impersonation",
        "spoofing",
        "malicious attachment",
        "malicious file",
        "malicious url",
        "malicious domain",
        "malicious ip",
    ];

    return seriousWords.some(
        word => normalized.includes(word)
    );
}

function containsNegativeThreatStatement(value) {
    const normalized =
        String(value || "")
            .toLowerCase()
            .replace(/\s+/g, " ")
            .trim();

    if (!normalized) {
        return false;
    }

    const negativePatterns = [
        "did not identify",
        "didn't identify",
        "did not detect",
        "didn't detect",

        "no evidence",
        "no strong evidence",

        "no threat",
        "no threats",

        "no malicious",
        "no malware",
        "no phishing",
        "no suspicious",

        "not malicious",
        "not a threat",
        "not suspicious",

        "not identified",
        "not detected",

        "no significant threat",
        "no significant security",

        "no confirmed threat",
        "no confirmed threats",

        "no high-confidence threat",
        "no high confidence threat",

        "no observable threat",
        "no observable finding",

        "absence of",

        "without evidence of",

        "failed to identify",
        "failed to detect",

        "minimal risk",
        "low risk",

        "benign",
        "clean",
        "safe",
    ];

    return negativePatterns.some(
        pattern => normalized.includes(pattern)
    );
}


/* =========================================================
   GENERIC RENDER HELPERS
========================================================= */

function renderList(element, values, emptyMessage) {
    if (!element) {
        return;
    }

    if (!values.length) {
        setEmpty(
            element,
            emptyMessage
        );
        return;
    }

    setHTML(
        element,
        values.map(value => `
            <div class="data-row">

                <span class="mono">
                    ${escapeHtml(value)}
                </span>

            </div>
        `).join("")
    );
}

function renderValueRows(values, label) {
    return values.map(value => `
        <div class="data-row">

            <span>
                ${escapeHtml(label)}
            </span>

            <strong>
                ${formatValue(value)}
            </strong>

        </div>
    `).join("");
}

function renderObject(value) {
    if (
        value === null ||
        value === undefined
    ) {
        return "";
    }

    if (
        typeof value !== "object" ||
        Array.isArray(value)
    ) {
        return `
            <div class="data-row">

                <span>
                    Value
                </span>

                <strong>
                    ${formatValue(value)}
                </strong>

            </div>
        `;
    }

    return Object.entries(value)
        .filter(
            ([, item]) =>
                item !== null &&
                item !== undefined
        )
        .map(([key, item]) => `
            <div class="data-row">

                <span>
                    ${escapeHtml(
                        humanize(key)
                    )}
                </span>

                <strong>
                    ${formatValue(item)}
                </strong>

            </div>
        `).join("");
}

function showScreen(name) {
    [
        "welcome",
        "analyzing",
        "results",
    ].forEach(screen => {

        const element = els[screen];

        if (!element) {
            return;
        }

        element.classList.toggle(
            "active",
            screen === name
        );

        element.classList.toggle(
            "hidden",
            screen !== name
        );
    });
}

function resetApplication() {
    stopAnalysisProgress();

    resetPostAnalysisFontSize();

    state.investigation = null;
    state.analysis = null;
    state.report = null;

    if (els.fileInput) {
        els.fileInput.value = "";
    }

    if (els.fileName) {
        els.fileName.textContent =
            "No file selected";
    }

    if (els.uploadButton) {
        els.uploadButton.disabled = true;
        els.uploadButton.textContent =
            "Analyze Email";
    }

    clearError();

    showScreen("welcome");

    document.querySelectorAll(".tab")
        .forEach((tab, index) => {
            tab.classList.toggle(
                "active",
                index === 0
            );
        });

    document.querySelectorAll(".tab-panel")
        .forEach((panel, index) => {
            panel.classList.toggle(
                "active",
                index === 0
            );
        });
}

function showError(message) {
    if (!els.uploadError) {
        return;
    }

    els.uploadError.hidden = false;
    els.uploadError.textContent =
        String(message || "Unknown error.");
}

function clearError() {
    if (!els.uploadError) {
        return;
    }

    els.uploadError.hidden = true;
    els.uploadError.textContent = "";
}

function parseValue(value) {
    if (
        typeof value !== "string"
    ) {
        return value;
    }

    try {
        return JSON.parse(value);
    } catch {
        return value;
    }
}

function object(...values) {
    for (const value of values) {
        const parsed = parseValue(value);

        if (
            parsed &&
            typeof parsed === "object" &&
            !Array.isArray(parsed)
        ) {
            return parsed;
        }
    }

    return {};
}

function array(...values) {
    const result = [];

    values.forEach(value => {
        const parsed = parseValue(value);

        if (Array.isArray(parsed)) {
            result.push(...parsed);
            return;
        }

        if (
            parsed &&
            typeof parsed === "object"
        ) {
            result.push(parsed);
        }
    });

    return result;
}

function uniqueStrings(...values) {
    const result = [];
    const seen = new Set();

    values.forEach(value => {
        const parsed = parseValue(value);

        const items = Array.isArray(parsed)
            ? parsed
            : (
                parsed === undefined ||
                parsed === null
                    ? []
                    : [parsed]
            );

        items.forEach(item => {

            if (
                item === null ||
                item === undefined
            ) {
                return;
            }

            if (
                typeof item === "object"
            ) {
                return;
            }

            const string =
                String(item).trim();

            if (
                !string ||
                seen.has(string)
            ) {
                return;
            }

            seen.add(string);
            result.push(string);
        });
    });

    return result;
}

function uniqueValues(...values) {
    const result = [];
    const seen = new Set();

    values.forEach(value => {
        const parsed = parseValue(value);

        const items = Array.isArray(parsed)
            ? parsed
            : (
                parsed === undefined ||
                parsed === null
                    ? []
                    : [parsed]
            );

        items.forEach(item => {

            if (
                item === null ||
                item === undefined
            ) {
                return;
            }

            const key =
                typeof item === "object"
                    ? JSON.stringify(item)
                    : String(item);

            if (seen.has(key)) {
                return;
            }

            seen.add(key);
            result.push(item);
        });
    });

    return result;
}

function number(...values) {
    for (const value of values) {
        const parsed = Number(value);

        if (
            Number.isFinite(parsed)
        ) {
            return parsed;
        }
    }

    return 0;
}

function text(...values) {
    for (const value of values) {
        if (
            value !== undefined &&
            value !== null &&
            String(value).trim()
        ) {
            return String(value);
        }
    }

    return "";
}

function formatValue(value) {
    if (
        value === null ||
        value === undefined
    ) {
        return "—";
    }

    if (typeof value === "boolean") {
        return value ? "Yes" : "No";
    }

    if (
        typeof value === "object"
    ) {
        return `
            <pre class="value-json">${escapeHtml(
                JSON.stringify(
                    value,
                    null,
                    2
                )
            )}</pre>
        `;
    }

    return escapeHtml(
        String(value)
    );
}

/*
 * CONFIDENCE DISPLAY
 *
 * Backend:
 *   0.38
 *
 * Frontend:
 *   38%
 *
 * Values already expressed as 38 stay 38%.
 */
function formatConfidence(value) {
    const numeric = Number(value);

    if (!Number.isFinite(numeric)) {
        return "—";
    }

    const percentage =
        numeric >= 0 &&
        numeric <= 1
            ? numeric * 100
            : numeric;

    return `${Math.round(percentage)}%`;
}

function formatText(value) {
    return escapeHtml(
        String(value || "")
    ).replace(
        /\r?\n/g,
        "<br>"
    );
}

function humanize(value) {
    return String(value)
        .replaceAll("_", " ")
        .replace(
            /\b\w/g,
            char => char.toUpperCase()
        );
}

function setText(element, value) {
    if (!element) {
        return;
    }

    element.textContent =
        text(value, "—");
}

function setHTML(element, html) {
    if (!element) {
        return;
    }

    element.innerHTML =
        html || "";
}

function setEmpty(element, message) {
    if (!element) {
        return;
    }

    element.innerHTML = `
        <div class="empty-state">
            ${escapeHtml(message)}
        </div>
    `;
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}

function getFileExtension(filename) {
    const name = String(filename || "");
    const index = name.lastIndexOf(".");

    if (index <= 0) {
        return "";
    }

    return name.slice(index).toLowerCase();
}

function formatBytes(value) {
    if (
        value === null ||
        value === undefined ||
        value === "" ||
        Number.isNaN(Number(value))
    ) {
        return String(value || "Unknown");
    }

    const bytes = Number(value);

    if (bytes < 1024) {
        return `${bytes} B`;
    }

    if (bytes < 1024 * 1024) {
        return `${(bytes / 1024).toFixed(1)} KB`;
    }

    if (bytes < 1024 * 1024 * 1024) {
        return `${(
            bytes /
            (1024 * 1024)
        ).toFixed(1)} MB`;
    }

    return `${(
        bytes /
        (1024 * 1024 * 1024)
    ).toFixed(1)} GB`;
}


/* =========================================================
   POST-ANALYSIS FONT SIZE
========================================================= */

function increasePostAnalysisFontSize(amount = 4) {
    const elements = Array.from(
        document.querySelectorAll(
            "#results, #results *"
        )
    );

    const updates = [];

    elements.forEach(element => {
        if (
            [
                "SCRIPT",
                "STYLE",
                "SVG",
                "PATH",
                "IMG",
                "VIDEO",
                "CANVAS"
            ].includes(element.tagName)
        ) {
            return;
        }

        if (!element.dataset.sentinelOriginalFontSize) {
            const computed =
                window.getComputedStyle(element).fontSize;

            const size =
                parseFloat(computed);

            if (!Number.isFinite(size)) {
                return;
            }

            element.dataset.sentinelOriginalFontSize =
                String(size);
        }

        const original =
            parseFloat(
                element.dataset.sentinelOriginalFontSize
            );

        if (!Number.isFinite(original)) {
            return;
        }

        updates.push([
            element,
            `${original + amount}px`
        ]);
    });

    updates.forEach(([element, size]) => {
        element.style.fontSize = size;
    });
}

function resetPostAnalysisFontSize() {
    document
        .querySelectorAll(
            "#results [data-sentinel-original-font-size]"
        )
        .forEach(element => {
            element.style.fontSize = "";
            delete element.dataset.sentinelOriginalFontSize;
        });
}
