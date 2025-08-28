/**
 * 15_config_sh.js
 * Contains all logic for building and rendering the AWS Config & Security Hub view.
 */

// --- IMPORTS ---
import { handleTabClick, createStatusBadge, log, setupPagination } from '../utils.js';


// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildConfigSHView = () => {
    const container = document.getElementById('config-sh-view');
    const executionDate = (window.configSHApiData || window.configSHStatusApiData)?.metadata?.executionDate || 'Analysis not run.';

    if (window.configSHApiData) {
        const { service_status, findings, compliance_summary } = window.configSHApiData.results;
        container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">Config & Security Hub Status</h2>
                    <p class="text-sm text-gray-500">${executionDate}</p>
                </div>
            </header>
            <div id="config-sh-results-view">
                <div class="border-b border-gray-200 mb-6">
                    <nav class="-mb-px flex flex-wrap space-x-6" id="config-sh-tabs">
                        <a href="#" data-tab="config-sh-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                        <a href="#" data-tab="config-sh-status-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Service Status</a>
                        <a href="#" data-tab="config-sh-compliance-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Compliance Status</a>
                    </nav>
                </div>
                <div id="config-sh-tab-content-container">
                    <div id="config-sh-summary-content" class="config-sh-tab-content">${createConfigSHSummaryCardsHtml()}</div>
                    <div id="config-sh-status-content" class="config-sh-tab-content hidden">${renderConfigSHStatusTable(service_status)}</div>
                    <div id="config-sh-compliance-content" class="config-sh-tab-content hidden"></div>
                </div>
            </div>`;

        updateConfigSHSummaryCards(service_status, findings);
        renderComplianceStatus(compliance_summary, findings);
        
        const tabsNav = container.querySelector('#config-sh-tabs');
        if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.config-sh-tab-content'));

    } else if (window.configSHStatusApiData) {
        const { service_status } = window.configSHStatusApiData.results;
        container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">Config & Security Hub Status</h2>
                    <p class="text-sm text-gray-500">${executionDate}</p>
                </div>
            </header>
            <div class="border-b border-gray-200 mb-6">
                 <nav class="-mb-px flex flex-wrap space-x-6" id="config-sh-tabs">
                    <a href="#" data-tab="config-sh-status-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Service Status</a>
                    <a href="#" data-tab="config-sh-deep-scan-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Deep Dive Analysis</a>
                </nav>
            </div>
            <div id="config-sh-initial-view">
                <div id="config-sh-status-content" class="config-sh-tab-content">
                    ${renderConfigSHStatusTable(service_status)}
                </div>
                <div id="config-sh-deep-scan-content" class="config-sh-tab-content hidden">
                    <div class="bg-white mt-6 p-6 rounded-xl shadow-sm border border-gray-100 text-center">
                        <p class="text-gray-600 mb-4">Run the deep analysis to view all Security Hub findings and detailed compliance status. This process may take several minutes.</p>
                        <button id="run-deep-scan-btn" class="bg-[#eb3496] text-white px-5 py-2.5 rounded-lg font-bold text-md hover:bg-[#d42c86] transition flex items-center justify-center space-x-2 mx-auto">
                            <span id="deep-scan-btn-text">Run Deep Dive Analysis</span>
                            <div id="deep-scan-spinner" class="spinner hidden"></div>
                        </button>
                    </div>
                </div>
            </div>`;
        
        const tabsNav = container.querySelector('#config-sh-tabs');
        if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.config-sh-tab-content'));
        document.getElementById('run-deep-scan-btn').addEventListener('click', runDeepConfigSHAnalysis);

    } else {
         container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">Config & Security Hub Status</h2>
                    <p class="text-sm text-gray-500">Enter credentials to see the status.</p>
                </div>
            </header>
            <p class="text-center text-gray-500 py-8">Results will appear here after the analysis.</p>
        `;
    }
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const runDeepConfigSHAnalysis = async () => {
    const runBtn = document.getElementById('run-deep-scan-btn');
    const btnText = document.getElementById('deep-scan-btn-text');
    const spinner = document.getElementById('deep-scan-spinner');
    
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Analyzing… (this can take a few minutes)';
    log('Starting deep analysis of Config & Security Hub…', 'info');

    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');

    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
    };

    try {
        const response = await fetch('http://127.0.0.1:5001/api/run-config-sh-audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        window.configSHApiData = await response.json();
        
        if (!response.ok) {
            throw new Error(window.configSHApiData.error || 'Unknown server error.');
        }
        
        log('Deep analysis of Config & Security Hub completed.', 'success');
        buildConfigSHView();

        if (window.runAndDisplayHealthyStatus) {
            window.runAndDisplayHealthyStatus();
        }

    } catch (e) {
        log(`Error in deep analysis: ${e.message}`, 'error');
        const initialContainer = document.getElementById('config-sh-initial-view');
        if(initialContainer) {
            initialContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
        }
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Run Deep Dive Analysis';
    }
};

const createConfigSHSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Regions with Config</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-config-enabled" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-ui-checks w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M7 2.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zM2 1a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2zm0 8a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-2a2 2 0 0 0-2-2zm.854-3.646a.5.5 0 0 1-.708 0l-1-1a.5.5 0 1 1 .708-.708l.646.647 1.646-1.647a.5.5 0 1 1 .708.708zm0 8a.5.5 0 0 1-.708 0l-1-1a.5.5 0 0 1 .708-.708l.646.647 1.646-1.647a.5.5 0 0 1 .708.708zM7 10.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zm0-5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m0 8a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Regions with Security Hub</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-sh-enabled" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-ui-checks w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M7 2.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zM2 1a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2zm0 8a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-2a2 2 0 0 0-2-2zm.854-3.646a.5.5 0 0 1-.708 0l-1-1a.5.5 0 1 1 .708-.708l.646.647 1.646-1.647a.5.5 0 1 1 .708.708zm0 8a.5.5 0 0 1-.708 0l-1-1a.5.5 0 0 1 .708-.708l.646.647 1.646-1.647a.5.5 0 0 1 .708.708zM7 10.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zm0-5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m0 8a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Total Active Findings</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-total-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-exclamation w-6 h-6 text-orange-600" viewBox="0 0 16 16"><path d="M5.338 1.59a61 61 0 0 0-2.837.856.48.48 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.7 10.7 0 0 0 2.287 2.233c.346.244.652.42.893.533q.18.085.293.118a1 1 0 0 0 .101.025 1 1 0 0 0 .1-.025q.114-.034.294-.118c.24-.113.547-.29.893-.533a10.7 10.7 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.8 11.8 0 0 1-2.517 2.453 7 7 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7 7 0 0 1-1.048-.625 11.8 11.8 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 63 63 0 0 1 5.072.56"/><path d="M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Critical / High Findings</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-critical-findings" class="text-3xl font-bold text-red-600">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-exclamation w-6 h-6 text-red-600" viewBox="0 0 16 16"><path d="M5.338 1.59a61 61 0 0 0-2.837.856.48.48 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.7 10.7 0 0 0 2.287 2.233c.346.244.652.42.893.533q.18.085.293.118a1 1 0 0 0 .101.025 1 1 0 0 0 .1-.025q.114-.034.294-.118c.24-.113.547-.29.893-.533a10.7 10.7 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.8 11.8 0 0 1-2.517 2.453 7 7 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7 7 0 0 1-1.048-.625 11.8 11.8 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 63 63 0 0 1 5.072.56"/><path d="M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z"/></svg></div>
            </div>
        </div>
    </div>
`;

const updateConfigSHSummaryCards = (serviceStatus, findings) => {
    const totalRegions = serviceStatus.length;
    const configEnabledCount = serviceStatus.filter(s => s.ConfigEnabled).length;
    const shEnabledCount = serviceStatus.filter(s => s.SecurityHubEnabled).length;
    const criticalHighCount = findings.filter(f => ['CRITICAL', 'HIGH'].includes(f.Severity?.Label)).length;

    document.getElementById('config-sh-config-enabled').textContent = `${configEnabledCount} / ${totalRegions}`;
    document.getElementById('config-sh-sh-enabled').textContent = `${shEnabledCount} / ${totalRegions}`;
    document.getElementById('config-sh-total-findings').textContent = findings.length;
    document.getElementById('config-sh-critical-findings').textContent = criticalHighCount;
};

const renderConfigSHStatusTable = (serviceStatus) => {
    if (!serviceStatus || serviceStatus.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">Service status could not be retrieved by region.</p></div>';
    }

    const activeRegions = serviceStatus.filter(s => s.ConfigEnabled || s.SecurityHubEnabled);
    if (activeRegions.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No regions with AWS Config or Security Hub enabled.</p></div>';
    }
    
    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">AWS Config</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">AWS Security Hub</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Security Hub Standards</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Conformance Packs</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    activeRegions.forEach(s => {
        const configBadge = s.ConfigEnabled ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        const shBadge = s.SecurityHubEnabled ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        
        let standardsHtml = '-';
        if (s.EnabledStandards && s.EnabledStandards.length > 0) {
            standardsHtml = '<div class="flex flex-col items-start gap-1">' + 
                            s.EnabledStandards.map(arn => {
                                const shortName = arn.split(/[/:]standards\//).pop() || arn;
                                return `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">${shortName}</span>`
                            }).join('') +
                            '</div>';
        }
        
        let conformancePacksHtml = '-';
        if (s.EnabledConformancePacks && s.EnabledConformancePacks.length > 0) {
            conformancePacksHtml = '<div class="flex flex-col items-start gap-1">' +
                                s.EnabledConformancePacks.map(cp => `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-gray-200 text-gray-800">${cp}</span>`).join('') +
                                '</div>';
        }

        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm font-medium text-gray-800">${s.Region}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${configBadge}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${shBadge}</td>
                        <td class="px-4 py-4 align-top text-sm">${standardsHtml}</td>
                        <td class="px-4 py-4 align-top text-sm">${conformancePacksHtml}</td> 
                    </tr>`;
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
};

const renderComplianceStatus = (complianceSummary, allFindings) => {
    const container = document.getElementById('config-sh-compliance-content');
    if (!container) return;

    if (!complianceSummary || complianceSummary.length === 0) {
        container.innerHTML = `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No compliance data was found.</p></div>`;
        return;
    }

    const getPercentage = (count, total) => total > 0 ? ((count / total) * 100).toFixed(1) : 0;

    let contentHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="text-xl font-bold text-[#204071] mb-6">Controls Summary by Standard</h3><div class="space-y-8">`;

    complianceSummary.sort((a, b) => a.standardName.localeCompare(b.standardName)).forEach((standard, index) => {
        const totalControls = standard.totalControls || 0;
        const passedCount = standard.passedCount || 0;
        const failedCount = standard.failedCount || 0;
        const warningCount = standard.warningCount || 0;
        const detailContainerId = `detail-container-${index}`;
        
        contentHtml += `
            <div>
                <h4 class="text-md font-bold text-gray-800 mb-3 pb-2 border-b border-gray-200">${standard.standardName} <span class="text-sm font-normal text-gray-500">(${totalControls} controls)</span></h4>
                <div class="space-y-4">
                    <div id="row-passed-${index}" class="flex items-center p-2 rounded-md cursor-pointer hover:bg-gray-100 transition" onclick="showComplianceDetails('${standard.standardArn}', 'PASSED', 'row-passed-${index}', '${detailContainerId}')">
                        <span class="w-32"><span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">Passed</span></span>
                        <div class="flex-1 bg-gray-200 rounded-full h-4 mr-4"><div class="bg-green-500 h-4 rounded-full" style="width: ${getPercentage(passedCount, totalControls)}%"></div></div>
                        <span class="w-24 text-sm font-semibold text-gray-800 text-right">${passedCount.toLocaleString()} (${getPercentage(passedCount, totalControls)}%)</span>
                    </div>
                    <div id="row-failed-${index}" class="flex items-center p-2 rounded-md cursor-pointer hover:bg-gray-100 transition" onclick="showComplianceDetails('${standard.standardArn}', 'FAILED', 'row-failed-${index}', '${detailContainerId}')">
                        <span class="w-32"><span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">Failed</span></span>
                        <div class="flex-1 bg-gray-200 rounded-full h-4 mr-4"><div class="bg-red-500 h-4 rounded-full" style="width: ${getPercentage(failedCount, totalControls)}%"></div></div>
                        <span class="w-24 text-sm font-semibold text-gray-800 text-right">${failedCount.toLocaleString()} (${getPercentage(failedCount, totalControls)}%)</span>
                    </div>
                    <div id="row-warning-${index}" class="flex items-center p-2 rounded-md cursor-pointer hover:bg-gray-100 transition" onclick="showComplianceDetails('${standard.standardArn}', 'WARNING', 'row-warning-${index}', '${detailContainerId}')">
                        <span class="w-32"><span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-yellow-100 text-yellow-800">Warning</span></span>
                        <div class="flex-1 bg-gray-200 rounded-full h-4 mr-4"><div class="bg-yellow-500 h-4 rounded-full" style="width: ${getPercentage(warningCount, totalControls)}%"></div></div>
                        <span class="w-24 text-sm font-semibold text-gray-800 text-right">${warningCount.toLocaleString()} (${getPercentage(warningCount, totalControls)}%)</span>
                    </div>
                </div>
                <div id="${detailContainerId}" class="hidden mt-4 ml-6 border-l-2 pl-4"></div>
            </div>
        `;
    });

    contentHtml += `</div></div>`;
    container.innerHTML = contentHtml;
};

export const showComplianceDetails = (standardArn, status, rowId, containerId) => {
    const detailContainer = document.getElementById(containerId);
    const clickedRow = document.getElementById(rowId);

    if (!detailContainer.classList.contains('hidden') && clickedRow.classList.contains('bg-blue-50')) {
        detailContainer.classList.add('hidden');
        clickedRow.classList.remove('bg-blue-50', 'font-semibold');
        detailContainer.innerHTML = '';
        return;
    }

    clickedRow.parentElement.querySelectorAll('[id^="row-"]').forEach(row => {
        row.classList.remove('bg-blue-50', 'font-semibold');
    });
    
    clickedRow.classList.add('bg-blue-50', 'font-semibold');

    const getStandardIdentifier = (arn) => arn ? (arn.split('/standard/')[1] || arn) : null;
    const targetIdentifier = getStandardIdentifier(standardArn);

    const relevantFindings = window.configSHApiData.results.findings.filter(f => {
        const findingIdentifier = getStandardIdentifier(f.ProductFields?.StandardsArn);
        return findingIdentifier === targetIdentifier && f.Compliance?.Status === status;
    });
    
    let detailsHtml = '<ul class="space-y-3 text-sm">';
    if (relevantFindings.length > 0) {
        relevantFindings.sort((a, b) => a.Title.localeCompare(b.Title)).forEach(f => {
            detailsHtml += `
                <li class="p-3 bg-gray-50 rounded-md border border-gray-200">
                    <p class="font-bold text-gray-800">${f.Title}</p>
                    <p class="text-gray-600 mt-1">${f.Description}</p>
                    ${f.Remediation?.Recommendation?.Url ? `<a href="${f.Remediation.Recommendation.Url}" target="_blank" class="text-blue-600 hover:underline text-xs mt-1 inline-block">View recommendation ↗</a>` : ''}
                </li>
            `;
        });
    } else {
        detailsHtml += `<li class="text-gray-500">No detailed controls found for this status.</li>`;
    }
    detailsHtml += '</ul>';

    detailContainer.innerHTML = detailsHtml;
    detailContainer.classList.remove('hidden');
};