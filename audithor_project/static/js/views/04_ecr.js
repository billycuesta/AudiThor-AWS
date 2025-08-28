/**
 * 04_ecr.js
 * Contiene toda la lógica para construir y renderizar la vista de Elastic Container Registry (ECR).
 */

// --- IMPORTACIONES ---
import { handleTabClick, renderSecurityHubFindings, createStatusBadge } from '../utils.js';

// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
export const buildEcrView = () => {
    const container = document.getElementById('ecr-view');
    if (!container || !window.ecrApiData) return;

    const { repositories } = window.ecrApiData.results;
    const executionDate = window.ecrApiData.metadata.executionDate;
    const ecrSecurityHubFindings = window.securityHubApiData?.results?.findings?.ecrFindings || [];

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Elastic Container Registry (ECR)</h2>
                <p class="text-sm text-gray-500">${executionDate}</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="ecr-tabs">
                <a href="#" data-tab="ecr-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="ecr-repos-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Repositories (${repositories.length})</a>
                <a href="#" data-tab="ecr-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${ecrSecurityHubFindings.length})</a>
            </nav>
        </div>
        <div id="ecr-tab-content-container">
            <div id="ecr-summary-content" class="ecr-tab-content">${createEcrSummaryCardsHtml()}</div>
            <div id="ecr-repos-content" class="ecr-tab-content hidden">${renderEcrRepositoriesTable(repositories)}</div>
            <div id="ecr-sh-content" class="ecr-tab-content hidden">${createEcrSecurityHubHtml()}</div>
        </div>
    `;

    updateEcrSummaryCards(repositories);
    renderSecurityHubFindings(ecrSecurityHubFindings, 'sh-ecr-findings-container', 'No Security Hub findings related to ECR were found.');
    
    const tabsNav = container.querySelector('#ecr-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.ecr-tab-content'));
};


// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const createEcrSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Total Repositories</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="ecr-total-repos" class="text-3xl font-bold text-[#204071]">--</p>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Scan on Push Disabled</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="ecr-scan-disabled" class="text-3xl font-bold text-red-600">--</p>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Mutable Tags</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="ecr-mutable-tags" class="text-3xl font-bold text-yellow-600">--</p>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Public Repositories</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="ecr-public-repos" class="text-3xl font-bold text-red-600">--</p>
            </div>
        </div>
    </div>
`;

const updateEcrSummaryCards = (repositories) => {
    document.getElementById('ecr-total-repos').textContent = repositories.length;
    document.getElementById('ecr-scan-disabled').textContent = repositories.filter(r => !r.ScanOnPush).length;
    document.getElementById('ecr-mutable-tags').textContent = repositories.filter(r => r.ImageTagMutability === 'MUTABLE').length;
    document.getElementById('ecr-public-repos').textContent = repositories.filter(r => r.IsPublic).length;
};

export const openModalWithEcrPolicy = (repoIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const repo = window.ecrApiData.results.repositories[repoIndex];
    if (!modal || !repo || !repo.Policy) return;

    modalTitle.textContent = `Repository Policy for: ${repo.RepositoryName}`;
    const formattedPolicy = JSON.stringify(repo.Policy, null, 2);
    modalContent.innerHTML = `<div class="text-left"><pre class="bg-[#204071] text-white text-xs font-mono rounded-md p-3 overflow-x-auto"><code>${formattedPolicy}</code></pre></div>`;
    modal.classList.remove('hidden');
};

const renderEcrRepositoriesTable = (repositories) => {
    if (!repositories || repositories.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No ECR repositories were found.</p></div>';
    }

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Repository Name</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tag Immutability</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scan on Push</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public Access</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encryption</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Policy</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    repositories.sort((a,b) => a.Region.localeCompare(b.Region) || a.RepositoryName.localeCompare(b.RepositoryName)).forEach((repo, index) => {
        const immutabilityBadge = repo.ImageTagMutability === 'IMMUTABLE' ? createStatusBadge('IMMUTABLE') : createStatusBadge('MUTABLE');
        const scanBadge = repo.ScanOnPush ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        const publicBadge = repo.IsPublic ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">YES</span>' : '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">NO</span>';
        const policyButton = repo.Policy ? `<button onclick="openModalWithEcrPolicy(${index})" class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">View Policy</button>` : '-';

        tableHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${repo.Region}</td>
                <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${repo.RepositoryName}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${immutabilityBadge}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${scanBadge}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${publicBadge}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm font-mono text-gray-600">${repo.EncryptionType}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${policyButton}</td>
            </tr>
        `;
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
};

const createEcrSecurityHubHtml = () => {
    return `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (ECR)</h3>
            <div id="sh-ecr-findings-container" class="overflow-x-auto"></div>
        </div>
    `;
};