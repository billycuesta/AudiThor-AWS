/**
 * 05_waf.js
 * Contiene toda la lógica para construir y renderizar la vista de WAF & Shield.
 */

// Importamos las funciones de utilidad que vamos a necesitar desde el fichero utils.js
import { handleTabClick, renderSecurityHubFindings, createStatusBadge } from '../utils.js';

// La función principal que construye toda la vista. La exportamos para que otros ficheros puedan usarla.
export function buildWafView() {
    const container = document.getElementById('waf-view');
    if (!window.wafApiData || !window.securityHubApiData) {
        console.warn("WAF or Security Hub data not available for rendering.");
        return;
    }
    
    const { acls, ip_sets } = window.wafApiData.results;
    const wafFindings = window.securityHubApiData.results.findings.wafFindings;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">WAF & Shield</h2>
                <p class="text-sm text-gray-500">${window.wafApiData.metadata.executionDate}</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="waf-tabs">
                <a href="#" data-tab="waf-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="waf-acls-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Web ACLs (${acls.length})</a>
                <a href="#" data-tab="waf-ipsets-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">IP Sets (${ip_sets.length})</a>
                <a href="#" data-tab="waf-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${wafFindings.length})</a>
            </nav>
        </div>
        <div id="waf-tab-content-container">
            <div id="waf-summary-content" class="waf-tab-content">${createWafSummaryCardsHtml()}</div>
            <div id="waf-acls-content" class="waf-tab-content hidden">${renderWafAclsTable(acls)}</div>
            <div id="waf-ipsets-content" class="waf-tab-content hidden">${renderWafIpSetsTable(ip_sets)}</div>
            <div id="waf-sh-content" class="waf-tab-content hidden">${createWafSecurityHubHtml()}</div>
        </div>
    `;
    
    updateWafSummaryCards(acls, ip_sets, wafFindings);
    renderSecurityHubFindings(wafFindings, 'sh-waf-findings-container', 'No Security Hub findings related to WAF were found.');
    
    const tabsNav = container.querySelector('#waf-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.waf-tab-content'));
}

// --- Funciones internas de la vista WAF (no necesitan export porque solo se usan aquí) ---

function createWafSummaryCardsHtml() {
    return `
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
                <p class="text-sm text-gray-500">Total Web ACLs</p>
                <p id="waf-acl-count" class="text-3xl font-bold text-[#204071] mt-2">--</p>
            </div>
            <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
                <p class="text-sm text-gray-500">ACLs with Logging</p>
                <p id="waf-logging-enabled" class="text-3xl font-bold text-green-600 mt-2">--</p>
            </div>
            <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
                <p class="text-sm text-gray-500">Protected Resources</p>
                <p id="waf-protected-resources" class="text-3xl font-bold text-[#204071] mt-2">--</p>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm mb-8">
            <h3 class="font-bold text-lg text-[#204071] mb-2">Top 5 Blocked Rules (Last 30 Days)</h3>
            <div class="h-48"><canvas id="wafTopRulesChart"></canvas></div>
        </div>`;
}

function updateWafSummaryCards(acls, ipSets, wafFindings) {
    const aclCount = acls.length;
    const loggingEnabledCount = acls.filter(acl => acl.LoggingConfiguration && Object.keys(acl.LoggingConfiguration).length > 0).length;
    document.getElementById('waf-acl-count').textContent = aclCount;
    document.getElementById('waf-logging-enabled').textContent = `${loggingEnabledCount} / ${aclCount}`;
    const protectedResources = acls.reduce((sum, acl) => sum + (acl.AssociatedResourceArns?.length || 0), 0);
    document.getElementById('waf-protected-resources').textContent = protectedResources;
    updateWafTopRulesChart(acls);
}

function updateWafTopRulesChart(acls) {
    const ctx = document.getElementById('wafTopRulesChart');
    if (!ctx) return;
    const ruleCounts = {};
    acls.forEach(acl => {
        if (acl.TopRules) {
            acl.TopRules.forEach(rule => {
                ruleCounts[rule.RuleName] = (ruleCounts[rule.RuleName] || 0) + rule.BlockedRequests;
            });
        }
    });
    const sortedRules = Object.entries(ruleCounts).sort(([, a], [, b]) => b - a).slice(0, 5);
    if (sortedRules.length === 0) {
        ctx.parentElement.innerHTML = '<div class="flex items-center justify-center h-full text-center text-gray-500"><p>No blocked requests found in the last 30 days.</p></div>';
        return;
    }
    const labels = sortedRules.map(item => item[0]);
    const data = sortedRules.map(item => item[1]);
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Blocked Requests',
                data: data,
                backgroundColor: 'rgba(235, 52, 150, 0.6)',
                borderColor: 'rgba(235, 52, 150, 1)',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }
        }
    });
}

function createWafSecurityHubHtml() {
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (WAF)</h3><div id="sh-waf-findings-container" class="overflow-x-auto"></div></div>`;
}

function renderWafAclsTable(acls) {
    if (!acls || acls.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No Web ACLs were found in the account.</p></div>';
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Logging Destination</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Sampled Requests</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protected Resources</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    acls.sort((a,b) => a.Name.localeCompare(b.Name)).forEach(acl => {
        let resourcesHtml = '<span class="px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">No associated resources</span>';
        if (acl.AssociatedResourceArns && acl.AssociatedResourceArns.length > 0) {
            resourcesHtml = `<div class="flex flex-col space-y-1">` + acl.AssociatedResourceArns.map(arn => `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800 font-mono">${arn}</span>`).join('') + `</div>`;
        }
        let loggingHtml = '<span class="px-2 py-1 text-xs font-semibold rounded-full bg-gray-100 text-gray-700">Disabled</span>';
        if (acl.LoggingConfiguration && acl.LoggingConfiguration.LogDestinationConfigs && acl.LoggingConfiguration.LogDestinationConfigs.length > 0) {
            const firehoseArn = acl.LoggingConfiguration.LogDestinationConfigs[0];
            const firehoseName = firehoseArn.split('/').pop();
            loggingHtml = `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800 font-mono" title="${firehoseArn}">${firehoseName}</span>`;
        }
        const sampledEnabled = acl.VisibilityConfig ? acl.VisibilityConfig.SampledRequestsEnabled : false;
        const sampledBadge = sampledEnabled ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        table += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 align-top whitespace-nowrap text-sm font-medium text-gray-800">${acl.Name}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${acl.Scope}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${acl.Region}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm">${loggingHtml}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm">${sampledBadge}</td><td class="px-4 py-4 align-top text-sm">${resourcesHtml}</td></tr>`;
    });
    table += '</tbody></table></div>';
    return table;
}

function renderWafIpSetsTable(ipSets) { 
    if (!ipSets || ipSets.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No IP Sets were found in the account.</p></div>'; 
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Version</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase"># Addresses</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">'; 
    ipSets.sort((a,b) => a.Name.localeCompare(b.Name)).forEach(ipSet => { 
        table += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${ipSet.Name}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.Scope}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.Region}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.IPAddressVersion}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.AddressCount}</td></tr>`; 
    }); 
    table += '</tbody></table></div>'; 
    return table; 
}

