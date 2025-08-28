/**
 * 02_exposure.js
 * Contiene toda la lógica para construir y renderizar la vista de Internet Exposure.
 */

// --- IMPORTACIONES ---
// Importamos las funciones de utilidad que este módulo necesita.
import { handleTabClick, renderSecurityHubFindings, createStatusBadge } from '../utils.js';


// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
// Exportamos la función principal para que app.js pueda encontrarla y usarla.
export const buildExposureView = () => {
    const container = document.getElementById('exposure-view');
    if (!window.exposureApiData) return;

    const allExposureServices = [
        "S3 Public Buckets", "EC2 Public Instances", "Security Groups Open", 
        "ALB/NLB Public", "Lambda URLs", "API Gateway Public", "Assumable Roles"
    ];

    const details = window.exposureApiData.results.details;
    const networkPorts = window.exposureApiData.results.network_ports || [];
    const securityHubFindings = window.securityHubApiData.results.findings.exposureFindings;

    let tabsHtml = `<a href="#" data-tab="exposure-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>`;
    
    allExposureServices.forEach(service => {
        const count = Object.values(details[service] || {}).flat().length;
        const safeId = service.replace(/\s+/g, '-').replace(/\//g, '-');
        tabsHtml += `<a href="#" data-tab="exposure-${safeId}-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">${service} (${count})</a>`;
    });

    tabsHtml += `<a href="#" data-tab="exposure-network-ports-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Publicly Exposed Network Ports (${networkPorts.length})</a>`;
    tabsHtml += `<a href="#" data-tab="exposure-securityhub-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub Findings</a>`;

    let contentHtml = `<div id="exposure-summary-content" class="exposure-tab-content">${createExposureSummaryCardsHtml()}</div>`;
    
    allExposureServices.forEach(service => {
        const safeId = service.replace(/\s+/g, '-').replace(/\//g, '-');
        contentHtml += `<div id="exposure-${safeId}-content" class="exposure-tab-content hidden"></div>`;
    });

    contentHtml += `<div id="exposure-network-ports-content" class="exposure-tab-content hidden"></div>`;
    contentHtml += `<div id="exposure-securityhub-content" class="exposure-tab-content hidden">${createExposureSecurityHubHtml()}</div>`;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div><h2 class="text-2xl font-bold text-[#204071]">Internet Exposure</h2><p class="text-sm text-gray-500">${window.exposureApiData.metadata.executionDate}</p></div>
        </header>
        <div class="border-b border-gray-200 mb-6"><nav class="-mb-px flex flex-wrap space-x-6">${tabsHtml}</nav></div>
        <div>${contentHtml}</div>`;

    updateExposureSummaryCards(window.exposureApiData.results.summary, securityHubFindings);
    
    allExposureServices.forEach(service => {
        const safeId = service.replace(/\s+/g, '-').replace(/\//g, '-');
        const serviceContainer = container.querySelector(`#exposure-${safeId}-content`);

        if (service === 'EC2 Public Instances') {
            const allInstancesWithIndex = (window.computeApiData?.results?.ec2_instances || [])
                .map((instance, originalIndex) => ({ instance, originalIndex }))
                .filter(({ instance }) => instance.PublicIpAddress && instance.PublicIpAddress !== 'N/A');
            serviceContainer.innerHTML = renderPublicEc2InstancesTable(allInstancesWithIndex, window.allAvailableRegions, 'all', 'all');
        } else {
            serviceContainer.innerHTML = renderExposureDetails(service, details[service] || {});
        }
    });

    container.querySelector('#exposure-network-ports-content').innerHTML = renderNetworkPortsTable(networkPorts);
    renderSecurityHubFindings(securityHubFindings, 'sh-exposure-findings-container', 'No Security Hub findings related to internet exposure were found.');
    
    const ec2TabContent = container.querySelector('#exposure-EC2-Public-Instances-content');
    
    const handleFilterChange = () => {
        const selectedState = ec2TabContent.querySelector('.public-ec2-filter-btn.bg-\\[\\#eb3496\\]')?.dataset.state || 'all';
        const selectedRegion = ec2TabContent.querySelector('#public-ec2-region-filter').value;
        const allInstancesWithIndex = (window.computeApiData?.results?.ec2_instances || []).map((instance, originalIndex) => ({ instance, originalIndex }));

        let filteredInstances = allInstancesWithIndex
            .filter(({ instance }) => instance.PublicIpAddress && instance.PublicIpAddress !== 'N/A');

        if (selectedState !== 'all') {
            filteredInstances = filteredInstances.filter(({ instance }) => instance.State.toLowerCase() === selectedState);
        }
        if (selectedRegion !== 'all') {
            filteredInstances = filteredInstances.filter(({ instance }) => instance.Region === selectedRegion);
        }
        
        ec2TabContent.innerHTML = renderPublicEc2InstancesTable(filteredInstances, window.allAvailableRegions, selectedState, selectedRegion);
    };
    
    ec2TabContent.addEventListener('click', (e) => {
        const filterBtn = e.target.closest('.public-ec2-filter-btn');
        if (!filterBtn) return;
        
        ec2TabContent.querySelectorAll('.public-ec2-filter-btn').forEach(btn => {
            btn.classList.remove('bg-[#eb3496]', 'text-white');
            btn.classList.add('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        });
        filterBtn.classList.add('bg-[#eb3496]', 'text-white');
        filterBtn.classList.remove('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        handleFilterChange();
    });

    ec2TabContent.addEventListener('change', (e) => {
        if (e.target.id === 'public-ec2-region-filter') {
            handleFilterChange();
        }
    });
    
    const tabsNav = container.querySelector('nav');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.exposure-tab-content'));
};


// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const createExposureSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">ALB/NLB Public</p></div><div class="flex justify-between items-end pt-4"><p id="exp-total-albs" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path fill-rule="evenodd" d="M6 3.5a.5.5 0 0 1 .5-.5h8a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-8a.5.5 0 0 1-.5-.5v-2a.5.5 0 0 0-1 0v2A1.5 1.5 0 0 0 6.5 14h8a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2h-8A1.5 1.5 0 0 0 5 3.5v2a.5.5 0 0 0 1 0z"/> <path fill-rule="evenodd" d="M11.854 8.354a.5.5 0 0 0 0-.708l-3-3a.5.5 0 1 0-.708.708L10.293 7.5H1.5a.5.5 0 0 0 0 1h8.793l-2.147 2.146a.5.5 0 0 0 .708.708z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">EC2 Public Instances</p></div><div class="flex justify-between items-end pt-4"><p id="exp-total-ec2s" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path d="M5 0a.5.5 0 0 1 .5.5V2h1V.5a.5.5 0 0 1 1 0V2h1V.5a.5.5 0 0 1 1 0V2h1V.5a.5.5 0 0 1 1 0V2A2.5 2.5 0 0 1 14 4.5h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14a2.5 2.5 0 0 1-2.5 2.5v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14A2.5 2.5 0 0 1 2 11.5H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2A2.5 2.5 0 0 1 4.5 2V.5A.5.5 0 0 1 5 0m-.5 3A1.5 1.5 0 0 0 3 4.5v7A1.5 1.5 0 0 0 4.5 13h7a1.5 1.5 0 0 0 1.5-1.5v-7A1.5 1.5 0 0 0 11.5 3zM5 6.5A1.5 1.5 0 0 1 6.5 5h3A1.5 1.5 0 0 1 11 6.5v3A1.5 1.5 0 0 1 9.5 11h-3A1.5 1.5 0 0 1 5 9.5zM6.5 6a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Security Groups Open</p></div><div class="flex justify-between items-end pt-4"><p id="exp-total-sgs" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path fill-rule="evenodd" d="M12 0a4 4 0 0 1 4 4v2.5h-1V4a3 3 0 1 0-6 0v2h.5A2.5 2.5 0 0 1 12 8.5v5A2.5 2.5 0 0 1 9.5 16h-7A2.5 2.5 0 0 1 0 13.5v-5A2.5 2.5 0 0 1 2.5 6H8V4a4 4 0 0 1 4-4M2.5 7A1.5 1.5 0 0 0 1 8.5v5A1.5 1.5 0 0 0 2.5 15h7a1.5 1.5 0 0 0 1.5-1.5v-5A1.5 1.5 0 0 0 9.5 7z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">S3 Buckets Public</p></div><div class="flex justify-between items-end pt-4"><p id="exp-total-s3" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path d="M2.522 5H2a.5.5 0 0 0-.494.574l1.372 9.149A1.5 1.5 0 0 0 4.36 16h7.278a1.5 1.5 0 0 0 1.483-1.277l1.373-9.149A.5.5 0 0 0 14 5h-.522A5.5 5.5 0 0 0 2.522 5m1.005 0a4.5 4.5 0 0 1 8.945 0zm9.892 1-1.286 8.574a.5.5 0 0 1-.494.426H4.36a.5.5 0 0 1-.494-.426L2.58 6h10.838z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Findings (Crit/High)</p></div><div class="flex justify-between items-end pt-4"><p id="exp-critical-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"> <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/></svg></div></div></div>
    </div>`;

const createExposureSecurityHubHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (Exposed to the Internet)</h3><div id="sh-exposure-findings-container" class="overflow-x-auto"></div></div>`;

const updateExposureSummaryCards = (summaryData, findingsData) => { 
    const sumValues = (serviceName) => { 
        if (!summaryData[serviceName]) return 0; 
        return Object.values(summaryData[serviceName]).reduce((total, count) => total + count, 0); 
    }; 
    document.getElementById('exp-total-albs').textContent = sumValues('ALB/NLB Public'); 
    document.getElementById('exp-total-ec2s').textContent = sumValues('EC2 Public Instances'); 
    document.getElementById('exp-total-sgs').textContent = sumValues('Security Groups Open'); 
    document.getElementById('exp-total-s3').textContent = sumValues('S3 Public Buckets'); 
    const criticalHighFindings = findingsData.filter(f => f.Severity?.Label === 'CRITICAL' || f.Severity?.Label === 'HIGH').length; 
    document.getElementById('exp-critical-findings').textContent = criticalHighFindings; 
};

const renderPublicEc2InstancesTable = (instances, allRegions, selectedState = 'all', selectedRegion = 'all') => {
    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');

    const filterControlsHtml = `
        <div class="mb-4 flex flex-wrap gap-4 items-center">
            <div class="flex items-center space-x-2">
                <span class="text-sm font-medium text-gray-700">Status:</span>
                <div class="flex space-x-2">
                    <button data-state="all" class="public-ec2-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm ${selectedState === 'all' ? 'bg-[#eb3496] text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'}">All</button>
                    <button data-state="running" class="public-ec2-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm ${selectedState === 'running' ? 'bg-[#eb3496] text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'}">Running</button>
                    <button data-state="stopped" class="public-ec2-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm ${selectedState === 'stopped' ? 'bg-[#eb3496] text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'}">Stopped</button>
                </div>
            </div>
            <div class="flex items-center space-x-2">
                <label for="public-ec2-region-filter" class="text-sm font-medium text-gray-700">Region:</label>
                <select id="public-ec2-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5">
                    <option value="all">All Regions</option>
                    ${regionOptions}
                </select>
            </div>
        </div>`;

    if (!instances || instances.length === 0) {
        return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControlsHtml}<p class="text-center text-gray-500 py-4">No EC2 instances with public IPs match the selected filters.</p></div>`;
    }

    let tableHtml = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Instance ID</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public IP</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Operating System</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Security Groups</th>' +
                    '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tags</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    instances.forEach((instanceData) => {
        const { instance, originalIndex } = instanceData;
        const tagCount = Object.keys(instance.Tags).length;
        let tagsHtml = '-';
        if (tagCount > 0) {
            tagsHtml = `<button 
                            onclick="openModalWithEc2Tags(${originalIndex})" 
                            class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                            View (${tagCount})
                        </button>`;
        }

        const sgHtml = instance.SecurityGroups && instance.SecurityGroups.length > 0
            ? instance.SecurityGroups.map(sg => `<span class="inline-block bg-gray-100 text-gray-800 text-xs font-medium mr-2 mb-1 px-2.5 py-0.5 rounded-full">${sg}</span>`).join('')
            : '-';

        tableHtml += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${instance.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${instance.InstanceId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${instance.InstanceType}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(instance.State)}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${instance.PublicIpAddress}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 break-words">${instance.OperatingSystem}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 break-words">${sgHtml}</td>
                    <td class="px-4 py-4 text-center">
                        <button onclick="copyToClipboard(this, '${instance.ARN}')" title="${instance.ARN}" class="p-1 rounded-md hover:bg-gray-200 transition">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
                        </button>
                    </td>
                    <td class="px-4 py-4 text-sm text-gray-600">${tagsHtml}</td>
                </tr>`;
    });
    tableHtml += '</tbody></table></div>';
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControlsHtml}${tableHtml}</div>`;
};

export const openModalWithTlsDetails = (lbIndex, listenerIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    const allLbs = Object.values(window.exposureApiData.results.details['ALB/NLB Public'] || {}).flat();
    const lb = allLbs[lbIndex];
    const listener = lb.listeners[listenerIndex];

    if (!modal || !listener) return;

    modalTitle.textContent = `TLS Details for ${lb.name}:${listener.port}`;
    
    const tlsVersionsHtml = listener.tlsVersions.map(v => {
        const isOutdated = ['TLSv1.0', 'TLSv1.1', 'SSLv3'].includes(v);
        return `<li class="${isOutdated ? 'text-red-600 font-bold' : 'text-green-700'}">${v}</li>`;
    }).join('');

    const ciphersHtml = listener.ciphers.map(c => `<li class="font-mono text-xs">${c}</li>`).join('');

    modalContent.innerHTML = `
        <div class="space-y-4 text-left text-sm">
            <div>
                <h4 class="font-semibold text-gray-800">TLS Versions Supported</h4>
                <ul class="list-disc list-inside pl-2 mt-1">${tlsVersionsHtml}</ul>
            </div>
            <div>
                <h4 class="font-semibold text-gray-800">Cipher Suites Enabled</h4>
                <ul class="list-disc list-inside pl-2 mt-1 text-gray-600">${ciphersHtml}</ul>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
};

const renderPublicLoadBalancersTable = (loadBalancersByRegion) => {
    const allLbs = Object.values(loadBalancersByRegion || {}).flat();
    if (allLbs.length === 0) {
         return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No public Load Balancers were found.</p></div>';
    }

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Load Balancer Name</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Listener Port</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">TLS Policy</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">TLS Status</th>' +
                    '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Details</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    allLbs.forEach((lb, lbIndex) => {
        if (lb.listeners.length > 0) {
            lb.listeners.forEach((listener, listenerIndex) => {
                const statusBadge = listener.isOutdated
                    ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Outdated</span>'
                    : '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Secure</span>';

                tableHtml += `<tr class="hover:bg-gray-50">
                                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${lb.region}</td>
                                <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${lb.name}</td>
                                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${listener.port} (${listener.protocol})</td>
                                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${listener.policyName}</td>
                                <td class="px-4 py-4 whitespace-nowrap text-sm">${statusBadge}</td>
                                <td class="px-4 py-4 text-center">
                                    <button onclick="openModalWithTlsDetails(${lbIndex}, ${listenerIndex})" class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">View Details</button>
                                </td>
                            </tr>`;
            });
        } else {
            tableHtml += `<tr class="hover:bg-gray-50">
                            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${lb.region}</td>
                            <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${lb.name}</td>
                            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-500 italic" colspan="4">No HTTPS/TLS listeners</td>
                        </tr>`;
        }
    });

    tableHtml += '</tbody></table></div>';
    return tableHtml;
};

const renderOpenSecurityGroupsTable = (openSgs) => {
    if (!openSgs || openSgs.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No open security groups were found.</p></div>';
    }
    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Group ID</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Group Name</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Port Range</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    openSgs.forEach(sg => {
        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${sg.Region}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${sg.GroupId}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${sg.GroupName}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${sg.Protocol}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-red-600 font-semibold">${sg.PortRange}</td>
                    </tr>`;
    });

    tableHtml += '</tbody></table></div>';
    return tableHtml;
};

const renderExposureDetails = (service, regions) => {
    const flattenedData = Object.values(regions).flat();

    if (flattenedData.length === 0) {
        return `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No exposed resources of type "${service}" were found.</p></div>`;
    }

    if (service === "EC2 Public Instances") {
        return renderPublicEc2InstancesTable();
    }

    if (service === "Security Groups Open") {
        return renderOpenSecurityGroupsTable(flattenedData);
    }

    if (service === "ALB/NLB Public") {
        return renderPublicLoadBalancersTable(regions);
    }

    let html = '<div class="space-y-6">';
    Object.entries(regions).sort(([keyA], [keyB]) => keyA.localeCompare(keyB)).forEach(([region, items]) => {
        html += `<div class="bg-white p-4 rounded-xl shadow-sm border border-gray-100"><h4 class="font-semibold text-md text-[#204071] mb-2">${region}</h4><ul class="space-y-2 font-mono text-sm">`;
        items.forEach(item => { html += `<li class="text-gray-600 list-disc list-inside">${item}</li>`; });
        html += '</ul></div>';
    });
    html += '</div>';
    return html;
};

const renderNetworkPortsTable = (ports) => {
    if (!ports || ports.length === 0) {
        return `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">Excellent! No publicly exposed network ports were found.</p></div>`;
    }

    let tableHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type of Resource</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Resource ID</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Port Range</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">`;

    ports.sort((a,b) => a.Region.localeCompare(b.Region)).forEach(p => {
        const protocol = p.Protocol === "-1" ? "All" : p.Protocol;
        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${p.Region}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${p.ResourceType}</td>
                        <td class="px-4 py-4 text-sm text-gray-600 break-all font-mono">${p.ResourceId}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${protocol.toString().toUpperCase()}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${p.PortRange}</td>
                        <td class="px-4 py-4 text-sm text-gray-600 break-words">${p.Description}</td>
                      </tr>`;
    });

    tableHtml += `</tbody></table></div>`;
    return tableHtml;
};