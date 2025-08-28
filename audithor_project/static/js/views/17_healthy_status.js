/**
 * 17_healthy_status.js
 * Contains all logic for building and rendering the Healthy Status / Executive Summary view.
 */

// --- IMPORTS ---
import { handleTabClick, log } from '../utils.js';


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
                    <select id="healthy-status-region-filter" class="mt-1 block w-full md:w-96 pl-3 pr-10 py-2 text-base border-gray-300 focus:outline-none focus:ring-[#eb3496] focus:border-[#eb3496] sm:text-sm rounded-md"></select>
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
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.healthy-status-tab-content'));
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



// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

export const generateGeminiReport = async () => {
    const apiKey = document.getElementById('gemini-api-key').value.trim();
    const userPrompt = document.getElementById('gemini-prompt').value.trim();
    const reportOutputContainer = document.getElementById('gemini-report-output');
    const reportContentDiv = document.getElementById('gemini-report-content');
    const runBtn = document.getElementById('generate-gemini-report-btn');
    const btnText = document.getElementById('gemini-btn-text');
    const spinner = document.getElementById('gemini-spinner');

    if (!apiKey) {
        alert('Please enter your Gemini API Key.');
        return;
    }
    if (window.lastHealthyStatusFindings.length === 0) {
        alert('There are no findings to generate a report. Please run an analysis first.');
        return;
    }

    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Generating...';
    reportOutputContainer.classList.add('hidden');
    reportContentDiv.textContent = 'Contacting the Gemini API...';
    log('Generating report with Gemini...', 'info');

    const selectedRegion = document.getElementById('gemini-region-filter').value;
    let findingsForReport = window.lastHealthyStatusFindings;

    if (selectedRegion !== 'all') {
        log(`Filtering findings for region: ${selectedRegion}`, 'info');
        findingsForReport = window.lastHealthyStatusFindings.map(finding => {
            const affectedInRegion = finding.affected_resources.filter(res => res.region === selectedRegion || res.region === 'Global');
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
            throw new Error(`Gemini API Error: ${errorData.error.message}`);
        }

        const data = await response.json();
        const reportText = data.candidates[0].content.parts[0].text;
        
        reportContentDiv.textContent = reportText;
        reportOutputContainer.classList.remove('hidden');
        log('Report generated by Gemini successfully.', 'success');

    } catch (error) {
        reportContentDiv.textContent = `Error generating report:\n${error.message}`;
        reportOutputContainer.classList.remove('hidden');
        log(`Error in Gemini API call: ${error.message}`, 'error');
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Generate Draft Email';
    }
};

export const check_healthy_status_rules = (auditData) => {
    const findings = [];
    
    // Example: Check for MFA rule
    const users = auditData.iam?.results?.users || [];
    const noMfaUsers = users.filter(user => user.MFADevices.length === 0).map(user => user.UserName);
    if (noMfaUsers.length > 0) {
        findings.push({
            rule_id: "IAM_001",
            section: "Identity & Access",
            name: "User without MFA enabled",
            severity: "HIGH",
            description: "An IAM user does not have Multi-Factor Authentication (MFA) enabled.",
            remediation: "Enable MFA for the affected user(s).",
            affected_resources: noMfaUsers.map(name => ({ resource: name, region: 'Global' }))
        });
    }

    // Example: Check for GuardDuty rule
    const guarddutyStatus = auditData.guardduty?.results?.status || [];
    const disabledGuardDuty = guarddutyStatus.filter(status => status.Status !== "Enabled").map(status => status.Region);
    if (disabledGuardDuty.length > 0) {
        findings.push({
            rule_id: "GUARDDUTY_001",
            section: "Security Services",
            name: "GuardDuty not enabled in some regions",
            severity: "LOW",
            description: "AWS GuardDuty is not enabled in one or more regions.",
            remediation: "Enable GuardDuty in the affected region(s).",
            affected_resources: disabledGuardDuty.map(region => ({ resource: 'GuardDuty', region }))
        });
    }

    return findings;
};

export const renderHealthyStatusFindings = (findings) => {
    const container = document.getElementById('healthy-status-container');
    if (!container) return;

    if (findings.length === 0) {
        container.innerHTML = `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <p class="text-center text-gray-500">Good job! No findings were detected in this analysis.</p>
            </div>
        `;
        return;
    }

    const groupedFindings = findings.reduce((acc, finding) => {
        const key = finding.section;
        if (!acc[key]) {
            acc[key] = [];
        }
        acc[key].push(finding);
        return acc;
    }, {});

    let html = '';
    for (const section in groupedFindings) {
        html += `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 mb-6">
                <h3 class="font-bold text-lg mb-4 text-[#204071]">${section} Findings</h3>
                <div class="space-y-4">
        `;

        groupedFindings[section].forEach(finding => {
            const severityClass = finding.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                                  finding.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                                  finding.severity === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                                  'bg-gray-100 text-gray-800';
            const resourcesHtml = finding.affected_resources.map(res => `
                <div class="bg-gray-50 p-2 rounded-md text-sm font-mono break-all">
                    Resource: ${res.resource} <span class="text-gray-500">(${res.region})</span>
                </div>
            `).join('');

            html += `
                <div class="border-b border-gray-100 pb-4">
                    <div class="flex items-center mb-2">
                        <span class="text-sm font-bold text-gray-700 mr-2">${finding.name}</span>
                        <span class="text-xs font-medium px-2 py-0.5 rounded-full ${severityClass}">${finding.severity}</span>
                    </div>
                    <p class="text-sm text-gray-600 mb-2">${finding.description}</p>
                    <p class="text-xs text-gray-500 font-semibold mb-1">Affected Resources:</p>
                    <div class="space-y-1">${resourcesHtml}</div>
                </div>
            `;
        });

        html += '</div></div>';
    }

    container.innerHTML = html;
};

export const populateHealthyStatusFilter = (findings) => {
    const select = document.getElementById('healthy-status-region-filter');
    if (!select) return;

    const regions = new Set();
    regions.add('all');
    findings.forEach(finding => {
        finding.affected_resources.forEach(res => {
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

    select.addEventListener('change', (e) => {
        const selectedRegion = e.target.value;
        let filteredFindings = window.lastHealthyStatusFindings;
        if (selectedRegion !== 'all') {
            filteredFindings = window.lastHealthyStatusFindings.filter(finding =>
                finding.affected_resources.some(res => res.region === selectedRegion || res.region === 'Global')
            );
        }
        renderHealthyStatusFindings(filteredFindings);
    });
};