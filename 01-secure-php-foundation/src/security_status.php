<?php function render_security_status() { ?>
<style>
    .security-badge-container {
        margin-top: 2rem;
        padding: 1.5rem;
        background: #1a1a1a;
        border-radius: 8px;
        border: 1px solid #333;
    }
    .security-title {
        color: #bb86fc;
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 1rem;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .security-badges {
        display: flex;
        flex-wrap: wrap;
        gap: 0.8rem;
    }
    .badge {
        display: inline-flex;
        align-items: center;
        padding: 0.4rem 0.8rem;
        border-radius: 4px;
        background: rgba(3, 218, 198, 0.1);
        border: 1px solid rgba(3, 218, 198, 0.2);
        color: #03dac6;
        font-size: 0.8rem;
        font-weight: 500;
    }
    .badge.active::before {
        content: "●";
        margin-right: 0.4rem;
        color: #03dac6;
    }
</style>

<div class="security-badge-container">
    <div class="security-title">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        Active Security Measures
    </div>
    <div class="security-badges">
        <span class="badge active" title="Prevent ClickJacking">X-Frame-Options: DENY</span>
        <span class="badge active" title="Prevent MIME-Sniffing">X-C-Type: no-sniff</span>
        <span class="badge active" title="Strict Content Sources">CSP Enforced</span>
        <span class="badge active" title="No Raw Errors Leaked">Error Suppression</span>
        <span class="badge active" title="SQL Injection Protection">Prepared Statements</span>
        <span class="badge active" title="Database Hardening">Strict SQL Mode</span>
        <span class="badge active" title="Data Integrity">Input Sanitization</span>
    </div>
</div>
<?php } ?>
