/**
 * Ardyn AI - Inference Loading States & Streaming
 * Shows progress indicators for long-running TEE inference
 */

class ArdynInferenceUI {
    constructor() {
        this.inferenceStartTime = null;
        this.progressInterval = null;
        this.modelLatencies = {
            "deepseek-r1:70b": 90,  // seconds
            "ingu627/llama4-scout-q4": 15
        };
    }

    showLoading(model, container) {
        """Show loading indicator for inference."""
        this.inferenceStartTime = Date.now();
        const expectedSeconds = this.modelLatencies[model] || 30;
        
        const loadingHTML = `
            <div class="inference-loading" id="inferenceLoading">
                <div class="loading-header">
                    <div class="tee-badge">🔒 TEE Protected</div>
                    <div class="model-info">${this.getModelDisplayName(model)}</div>
                </div>
                <div class="progress-container">
                    <div class="progress-bar">
                        <div class="progress-fill" id="progressFill"></div>
                    </div>
                    <div class="progress-text">
                        <span id="progressPercent">0%</span>
                        <span id="progressTime">~${expectedSeconds}s estimated</span>
                    </div>
                </div>
                <div class="loading-steps">
                    <div class="step active" id="step1">
                        <span class="step-icon">🛡️</span>
                        <span class="step-text">Safety scrub</span>
                    </div>
                    <div class="step" id="step2">
                        <span class="step-icon">🔐</span>
                        <span class="step-text">TEE encryption</span>
                    </div>
                    <div class="step" id="step3">
                        <span class="step-icon">🧠</span>
                        <span class="step-text">Reasoning</span>
                    </div>
                    <div class="step" id="step4">
                        <span class="step-icon">✓</span>
                        <span class="step-text">Citation check</span>
                    </div>
                </div>
                <div class="privacy-notice">
                    Your data is encrypted and will be cryptographically destroyed after processing
                </div>
            </div>
        `;
        
        container.insertAdjacentHTML('beforeend', loadingHTML);
        this.startProgress(model, expectedSeconds);
    }

    startProgress(model, expectedSeconds) {
        """Animate progress bar."""
        let progress = 0;
        const fill = document.getElementById('progressFill');
        const percent = document.getElementById('progressPercent');
        const timeText = document.getElementById('progressTime');
        
        // Update steps based on time
        const stepTiming = [
            { step: 'step1', at: 0 },
            { step: 'step2', at: expectedSeconds * 0.1 },
            { step: 'step3', at: expectedSeconds * 0.2 },
            { step: 'step4', at: expectedSeconds * 0.8 }
        ];
        
        this.progressInterval = setInterval(() => {
            const elapsed = (Date.now() - this.inferenceStartTime) / 1000;
            progress = Math.min((elapsed / expectedSeconds) * 100, 95);  // Cap at 95% until complete
            
            if (fill) fill.style.width = `${progress}%`;
            if (percent) percent.textContent = `${Math.round(progress)}%`;
            if (timeText) {
                const remaining = Math.max(0, Math.round(expectedSeconds - elapsed));
                timeText.textContent = remaining > 0 ? `~${remaining}s remaining` : 'Finalizing...';
            }
            
            // Update step indicators
            stepTiming.forEach(({step, at}) => {
                if (elapsed >= at) {
                    const el = document.getElementById(step);
                    if (el) {
                        el.classList.add('active');
                        el.classList.add('completed');
                    }
                }
            });
            
        }, 1000);
    }

    hideLoading() {
        """Hide loading indicator."""
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
        }
        const loading = document.getElementById('inferenceLoading');
        if (loading) {
            loading.remove();
        }
    }

    getModelDisplayName(model) {
        const names = {
            "deepseek-r1:70b": "DeepSeek-R1 70B (Clinical & Legal Strategy)",
            "ingu627/llama4-scout-q4": "Llama 4 Scout Q4 (Fast Operations)"
        };
        return names[model] || model;
    }

    showDeathCertificate(certData) {
        """Show death certificate after inference."""
        return `
            <div class="death-certificate-banner">
                <span class="cert-icon">🔒</span>
                <span class="cert-text">Data Destroyed</span>
                <span class="cert-hash" title="${certData}">${certData.substring(0, 16)}...</span>
                <button class="cert-verify" onclick="verifyCertificate('${certData}')">Verify</button>
            </div>
        `;
    }
}

// CSS for loading states
const loadingStyles = `
.inference-loading {
    background: linear-gradient(135deg, #1e3a5f 0%, #2d4a6f 100%);
    border-radius: 12px;
    padding: 20px;
    margin: 16px 0;
    color: white;
    font-family: 'Inter', sans-serif;
}

.loading-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 16px;
}

.tee-badge {
    background: rgba(45, 90, 61, 0.8);
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 0.8rem;
    font-weight: 600;
}

.model-info {
    font-size: 0.9rem;
    opacity: 0.9;
}

.progress-container {
    margin-bottom: 16px;
}

.progress-bar {
    background: rgba(255,255,255,0.2);
    border-radius: 4px;
    height: 8px;
    overflow: hidden;
}

.progress-fill {
    background: linear-gradient(90deg, #2d5a3d, #4ade80);
    height: 100%;
    width: 0%;
    transition: width 0.5s ease;
}

.progress-text {
    display: flex;
    justify-content: space-between;
    margin-top: 8px;
    font-size: 0.85rem;
    opacity: 0.9;
}

.loading-steps {
    display: flex;
    justify-content: space-between;
    margin: 16px 0;
    padding: 12px;
    background: rgba(0,0,0,0.2);
    border-radius: 8px;
}

.step {
    text-align: center;
    opacity: 0.4;
    transition: opacity 0.3s;
}

.step.active {
    opacity: 1;
}

.step.completed .step-icon {
    color: #4ade80;
}

.step-icon {
    display: block;
    font-size: 1.5rem;
    margin-bottom: 4px;
}

.step-text {
    font-size: 0.75rem;
}

.privacy-notice {
    text-align: center;
    font-size: 0.8rem;
    opacity: 0.7;
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid rgba(255,255,255,0.1);
}

.death-certificate-banner {
    background: #f0fdf4;
    border: 1px solid #86efac;
    border-radius: 8px;
    padding: 12px 16px;
    margin-top: 12px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 0.9rem;
}

.death-certificate-banner .cert-icon {
    font-size: 1.2rem;
}

.death-certificate-banner .cert-text {
    font-weight: 600;
    color: #166534;
}

.death-certificate-banner .cert-hash {
    font-family: monospace;
    color: #64748b;
    font-size: 0.8rem;
}

.death-certificate-banner .cert-verify {
    margin-left: auto;
    background: #2d5a3d;
    color: white;
    border: none;
    padding: 4px 12px;
    border-radius: 4px;
    font-size: 0.8rem;
    cursor: pointer;
}
`;

// Inject styles
const styleSheet = document.createElement('style');
styleSheet.textContent = loadingStyles;
document.head.appendChild(styleSheet);

// Export
window.ArdynInferenceUI = ArdynInferenceUI;
