/**
 * 17_healthy_status.js
 * Contains all logic for building and rendering the Healthy Status / Executive Summary view.
 */

// --- IMPORTS ---
import { handleTabClick, log } from '../utils.js';

// Initialize global variable
if (!window.lastHealthyStatusFindings) {
    window.lastHealthyStatusFindings = [];
}

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildHealthyStatusView = () => {
    const container = document.getElementById('healthy-status-view');
    if (!container) return;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Healthy Status</h2>
                <p class="text-sm text-gray-500">Summary of Findings and Report Generation.</p>
            </div>
        </header>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex space-x-6" id="healthy-status-tabs">
                <a href="#" data-tab="hs-findings-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Findings</a>
                <a href="#" data-tab="hs-report-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Generate Report</a>
            </nav>
        </div>

        <div id="healthy-status-tab-content-container">
            <div id="hs-findings-content" class="healthy-status-tab-content">
                <div class="mb-4">
                    <label for="healthy-status-region-filter" class="block text-sm font-medium text-gray-700">Filter by Region:</label>
                    <select id="healthy-status-region-filter" class="mt-1 block w-full md:w-96 pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-[#eb3496] focus:border-[#eb3496] sm:text-sm rounded-md">
                        <option value="all">All Regions</option>
                    </select>
                </div>
                <div id="healthy-status-container">
                    <div class="text-center py-16 bg-white rounded-lg">
                        <h3 class="mt-2 text-lg font-medium text-[#204071]">Waiting for analysis</h3>
                        <p class="mt-1 text-sm text-gray-500">Status findings will appear here after analyzing an account.</p>
                    </div>
                </div>
            </div>

            <div id="hs-report-content" class="healthy-status-tab-content hidden"></div>
        </div>
    `;

    const tabsNav = container.querySelector('#healthy-status-tabs');
    if (tabsNav) {
        tabsNav.addEventListener('click', handleTabClick(tabsNav, '.healthy-status-tab-content'));
    }
    
    // Build the report view immediately after creating the container
    buildGeminiReportView();
};

// This function is also exported because it's called from the main app.js
export const buildGeminiReportView = () => {
    const container = document.getElementById('hs-report-content');
    if (!container) return;

    const defaultPrompt = `Actúa como un consultor de ciberseguridad senior de la empresa [Nombre de tu Empresa]. El destinatario de este correo es nuestro cliente, una persona con un rol de liderazgo técnico (CTO, Tech Lead).

Tu tarea es redactar un borrador de correo electrónico claro y conciso para notificar al cliente sobre los hallazgos de seguridad identificados en su cuenta de AWS.

El correo debe tener la siguiente estructura:

**Asunto:** Resumen Ejecutivo: Hallazgos de Seguridad en su Cuenta de AWS

**Cuerpo del Correo:**

* **Saludo:** Un saludo profesional (ej: "Estimado/a [Nombre del Cliente],").
* **Introducción (1 párrafo):** Informa brevemente que se ha completado una revisión de seguridad y que a continuación se presentan los resultados clave.
* **Resumen de Hallazgos:** Presenta una lista de viñetas (bullet points). Para **cada tipo de hallazgo** identificado en el JSON que te proporciono, incluye una viñeta con:
    * El **título del hallazgo**.
    * Entre paréntesis, su **severidad**.
    * Una **breve descripción (1-2 frases)** del riesgo de negocio asociado. **No incluyas la lista detallada de recursos afectados**, solo el resumen del problema.
* **Recomendación Principal:** Basado en los hallazgos, ofrece una recomendación general y priorizada (ej: "Recomendamos centrar los esfuerzos iniciales en solucionar los hallazgos de severidad Crítica y Alta, especialmente los relacionados con la gestión de identidades y accesos.").
* **Próximos Pasos:** Propón agendar una reunión para revisar el informe técnico completo y coordinar el plan de remediación.
* **Cierre:** Un cierre cordial y profesional.

El objetivo es que el cliente entienda rápidamente qué problemas existen y cuál es su impacto, sin abrumarlo con detalles técnicos en el primer contacto. Asegúrate de que **todos los tipos de hallazgos** estén listados.

A continuación te proporciono los hallazgos en formato JSON:`;

    container.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-1 text-[#204071]">Generate Report with AI (Gemini)</h3>
            <p class="text-sm text-gray-500 mb-4">This tool will use the findings to generate a draft executive report.</p>
            
            <div class="mb-4">
                <label for="gemini-api-key" class="block text-sm font-medium text-gray-700 mb-1">Your Google AI Studio (Gemini) API Key</label>
                <input type="password" id="gemini-api-key" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5" placeholder="Paste your API key here">
                <p class="text-xs text-gray-500 mt-1">Your key is used directly from your browser to call the Google API and is not stored anywhere.</p>
            </div>

            <div class="mb-4">
                <label for="gemini-region-filter" class="block text-sm font-medium text-gray-700 mb-1">Filter Findings by Region (Optional)</label>
                <select id="gemini-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5">
                    <option value="all">All Regions</option>
                </select>
            </div>

            <div class="mb-4">
                <label for="gemini-prompt" class="block text-sm font-medium text-gray-700 mb-1">Prompt for Gemini (Editable)</label>
                <textarea id="gemini-prompt" rows="10" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono">${defaultPrompt}</textarea>
            </div>

            <button id="generate-gemini-report-btn" class="bg-[#eb3496] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#d42c86] transition flex items-center justify-center space-x-2">
                <span id="gemini-btn-text">Generate Draft Email</span>
                <div id="gemini-spinner" class="spinner hidden"></div>
            </button>

            <div id="gemini-report-output" class="mt-6 hidden">
                 <h4 class="font-bold text-lg mb-2 text-[#204071]">Email Draft:</h4>
                 <div id="gemini-report-content" class="bg-slate-50 p-4 rounded-lg border text-sm whitespace-pre-wrap"></div>
            </div>
        </div>
    `;

    // Add event listener after the button is created
    const genButton = document.getElementById('generate-gemini-report-btn');
    if (genButton) {
        genButton.addEventListener('click', generateGeminiReport);
    }
};

// --- INTERNAL MODULE FUNCTIONS ---
export const generateGeminiReport = async () => {
    const apiKey = document.getElementById('gemini-api-key')?.value.trim();
    const userPrompt = document.getElementById('gemini-prompt')?.value.trim();
    const reportOutputContainer = document.getElementById('gemini-report-output');
    const reportContentDiv = document.getElementById('gemini-report-content');
    const runBtn = document.getElementById('generate-gemini-report-btn');
    const btnText = document.getElementById('gemini-btn-text');
    const spinner = document.getElementById('gemini-spinner');

    if (!apiKey) {
        alert('Please enter your Gemini API Key.');
        return;
    }
    
    if (!window.lastHealthyStatusFindings || window.lastHealthyStatusFindings.length === 0) {
        alert('There are no findings to generate a report. Please run an analysis first.');
        return;
    }

    if (runBtn) runBtn.disabled = true;
    if (spinner) spinner.classList.remove('hidden');
    if (btnText) btnText.textContent = 'Generating...';
    if (reportOutputContainer) reportOutputContainer.classList.add('hidden');
    if (reportContentDiv) reportContentDiv.textContent = 'Contacting the Gemini API...';
    log('Generating report with Gemini...', 'info');

    const selectedRegion = document.getElementById('gemini-region-filter')?.value || 'all';
    let findingsForReport = window.lastHealthyStatusFindings;

    if (selectedRegion !== 'all') {
        log(`Filtering findings for region: ${selectedRegion}`, 'info');
        findingsForReport = window.lastHealthyStatusFindings.map(finding => {
            const affectedInRegion = finding.affected_resources.filter(res => 
                res.region === selectedRegion || res.region === 'Global'
            );
            if (affectedInRegion.length > 0) {
                return { ...finding, affected_resources: affectedInRegion };
            }
            return null;
        }).filter(Boolean);
    }

    const findingsJson = JSON.stringify(findingsForReport, null, 2);
    const fullPrompt = `${userPrompt}\n\n${findingsJson}`;
    const API_ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${apiKey}`;

    try {
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: fullPrompt }] }]
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Gemini API Error: ${errorData.error?.message || 'Unknown API error'}`);
        }

        const data = await response.json();
        const reportText = data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response generated';
        
        if (reportContentDiv) reportContentDiv.textContent = reportText;
        if (reportOutputContainer) reportOutputContainer.classList.remove('hidden');
        log('Report generated by Gemini successfully.', 'success');

    } catch (error) {
        const errorMsg = `Error generating report:\n${error.message}`;
        if (reportContentDiv) reportContentDiv.textContent = errorMsg;
        if (reportOutputContainer) reportOutputContainer.classList.remove('hidden');
        log(`Error in Gemini API call: ${error.message}`, 'error');
    } finally {
        if (runBtn) runBtn.disabled = false;
        if (spinner) spinner.classList.add('hidden');
        if (btnText) btnText.textContent = 'Generate Draft Email';
    }
};

// Sample rule checking function - you'll need to implement the actual rules
export const check_healthy_status_rules = (auditData) => {
    const findings = [];
    
    try {
        // Example: Check for MFA rule
        const users = auditData.iam?.results?.users || [];
        const noMfaUsers = users.filter(user => 
            !user.MFADevices || user.MFADevices.length === 0
        ).map(user => user.UserName || 'Unknown user');
        
        if (noMfaUsers.length > 0) {
            findings.push({
                rule_id: "IAM_001",
                section: "Identity & Access",
                name: "User without MFA enabled",
                severity: "HIGH",
                description: "IAM users without Multi-Factor Authentication (MFA) enabled pose a significant security risk.",
                remediation: "Enable MFA for all IAM users, especially those with console access.",
                affected_resources: noMfaUsers.map(name => ({ resource: name, region: 'Global' }))
            });
        }

        // Example: Check for GuardDuty rule
        const guarddutyStatus = auditData.guardduty?.results?.status || [];
        const disabledGuardDuty = guarddutyStatus.filter(status => 
            status.Status !== "Enabled"
        ).map(status => status.Region);
        
        if (disabledGuardDuty.length > 0) {
            findings.push({
                rule_id: "GUARDDUTY_001",
                section: "Security Services",
                name: "GuardDuty not enabled in some regions",
                severity: "MEDIUM",
                description: "AWS GuardDuty provides threat detection but is not enabled in all regions.",
                remediation: "Enable GuardDuty in all active AWS regions for comprehensive threat detection.",
                affected_resources: disabledGuardDuty.map(region => ({ resource: 'GuardDuty Service', region }))
            });
        }

        // Add more rules here as needed...

    } catch (error) {
        console.error('Error in rule checking:', error);
        log(`Error checking rules: ${error.message}`, 'error');
    }

    return findings;
};

export const renderHealthyStatusFindings = (findings) => {
    const container = document.getElementById('healthy-status-container');
    if (!container) return;

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <div class="flex items-center justify-center text-green-600">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-patch-check-fill mr-3" viewBox="0 0 16 16"><path d="M10.067.87a2.89 2.89 0 0 0-4.134 0l-.622.638-.89-.011a2.89 2.89 0 0 0-2.924 2.924l.01.89-.636.622a2.89 2.89 0 0 0 0 4.134l.637.622-.011.89a2.89 2.89 0 0 0 2.924 2.924l.89-.01.622.636a2.89 2.89 0 0 0 4.134 0l.622-.637.89.01a2.89 2.89 0 0 0 2.924-2.924l-.01-.89.636-.622a2.89 2.89 0 0 0 0-4.134l-.637-.622.011-.89a2.89 2.89 0 0 0-2.924-2.924l-.89.01zm.287 5.984-3 3a.5.5 0 0 1-.708 0l-1.5-1.5a.5.5 0 1 1 .708-.708L7 8.793l2.646-2.647a.5.5 0 0 1 .708.708"/></svg>
                    <p class="text-center font-semibold text-lg">¡Congratulations! No findings were found for the selected region.</p>
                </div>
            </div>
        `;
        return;
    }

    // Sort findings by severity
    const severityOrder = { 'Crítico': 1, 'Alto': 2, 'Medio': 3, 'Bajo': 4 };
    const sortedFindings = [...findings].sort((a, b) => (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99));

    container.innerHTML = '';
    
    sortedFindings.forEach(finding => {
        let borderColor = 'border-gray-500';
        if (finding.severity === 'Crítico') borderColor = 'border-red-600';
        if (finding.severity === 'Alto') borderColor = 'border-red-500';
        if (finding.severity === 'Medio') borderColor = 'border-yellow-500';
        if (finding.severity === 'Bajo') borderColor = 'border-blue-500';

        // Create display format for affected resources
        const affectedResourcesWithDisplay = (finding.affected_resources || []).map(res => {
            if (typeof res === 'object' && res.resource && res.region) {
                return {
                    ...res,
                    display: `${res.resource} (${res.region})`
                };
            } else if (typeof res === 'string') {
                return {
                    resource: res,
                    region: 'Global',
                    display: `${res} (Global)`
                };
            } else {
                return {
                    resource: 'Unknown',
                    region: 'Global',
                    display: 'Unknown (Global)'
                };
            }
        });

        const affectedResourcesHtml = affectedResourcesWithDisplay.map(res => 
            `<li>${res.display}</li>`
        ).join('');
        
        const resourcesCount = affectedResourcesWithDisplay.length;

        const card = `
            <div class="bg-white p-4 rounded-xl mb-4 border-l-4 ${borderColor} shadow-sm">
                <h3 class="text-xl font-bold text-[#204071]">${finding.name || 'Unknown finding'} <span class="text-sm font-normal text-gray-500">(${finding.severity || 'UNKNOWN'})</span></h3>
                <p class="text-gray-600 mt-2 text-sm">${finding.description || 'No description available'}</p>
                <div class="mt-4">
                    <details class="group">
                        <summary class="font-semibold text-gray-800 text-sm cursor-pointer list-none flex items-center">
                            <svg class="w-4 h-4 mr-2 group-open:rotate-90 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                            Affected Resources (${resourcesCount}):
                        </summary>
                        <ul class="list-disc list-inside text-sm text-gray-700 bg-gray-50 p-2 rounded-md mt-2 font-mono ml-6">
                            ${affectedResourcesHtml}
                        </ul>
                    </details>
                </div>
                <div class="mt-4">
                    <h4 class="font-semibold text-gray-800 text-sm">Recommended Solution:</h4>
                    <p class="text-gray-600 text-sm">${finding.remediation || 'No remediation information available'}</p>
                </div>
            </div>
        `;
        container.innerHTML += card;
    });
};

export const populateHealthyStatusFilter = (findings) => {
    const select = document.getElementById('healthy-status-region-filter');
    if (!select) return;

    const regions = new Set();
    regions.add('all');
    
    (findings || []).forEach(finding => {
        (finding.affected_resources || []).forEach(res => {
            if (res.region) {
                regions.add(res.region);
            }
        });
    });

    select.innerHTML = '';
    const sortedRegions = Array.from(regions).sort();
    sortedRegions.forEach(region => {
        const option = document.createElement('option');
        option.value = region;
        option.textContent = region === 'all' ? 'All Regions' : region;
        select.appendChild(option);
    });

    // Remove existing event listeners
    const newSelect = select.cloneNode(true);
    select.parentNode.replaceChild(newSelect, select);
    
    // Add new event listener
    newSelect.addEventListener('change', (e) => {
        const selectedRegion = e.target.value;
        let filteredFindings = window.lastHealthyStatusFindings || [];
        
        if (selectedRegion !== 'all') {
            filteredFindings = (window.lastHealthyStatusFindings || []).filter(finding =>
                (finding.affected_resources || []).some(res => 
                    res.region === selectedRegion || res.region === 'Global'
                )
            );
        }
        renderHealthyStatusFindings(filteredFindings);
    });
};