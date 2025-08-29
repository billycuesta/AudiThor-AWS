/**
 * 01_iam.js
 * Contiene toda la lógica para construir y renderizar la vista de Identity & Access (IAM).
 */

// --- IMPORTACIONES ---
// Importamos las funciones de utilidad que vamos a necesitar desde el fichero utils.js
import { handleTabClick, renderSecurityHubFindings, log } from '../utils.js';


// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
// La función principal que construye toda la vista. La exportamos para que app.js pueda usarla.


export const buildIamView = () => {
    const container = document.getElementById('iam-view');
    if (!container) return;

    const accessAnalyzerFindingsCount = window.accessAnalyzerApiData?.results?.findings?.length || 0;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div><h2 class="text-2xl font-bold text-[#204071]">Identity & Access</h2><p class="text-sm text-gray-500 scan-info"></p></div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="iam-tabs">
                <a href="#" data-tab="resumen-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="usuarios-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Users</a>
                <a href="#" data-tab="grupos-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Groups</a>
                <a href="#" data-tab="roles-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Roles</a>
                <a href="#" data-tab="politicas-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Password Policies</a>
                <a href="#" data-tab="access-analyzer-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Access Analyzer (${accessAnalyzerFindingsCount})</a>
                <a href="#" data-tab="detalle-permisos-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Permission Details</a>
                <a href="#" data-tab="critical-perms-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Users with Critical Permissions</a>
                <a href="#" data-tab="federation-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Federation</a>
                <a href="#" data-tab="securityhub-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub</a>
            </nav>
        </div>
        <div id="iam-tab-content-container">
            <div id="resumen-content" class="iam-tab-content">${createIamResumenHtml()}</div>
            <div id="usuarios-content" class="iam-tab-content hidden">${createIamUsuariosHtml()}</div>
            <div id="grupos-content" class="iam-tab-content hidden">${createIamGruposHtml()}</div>
            <div id="roles-content" class="iam-tab-content hidden">${createIamRolesHtml()}</div>
            <div id="politicas-content" class="iam-tab-content hidden">${createIamPoliticasHtml()}</div>
            <div id="access-analyzer-content" class="iam-tab-content hidden"></div>
            <div id="securityhub-content" class="iam-tab-content hidden">${createSecurityHubHtml()}</div>
            <div id="detalle-permisos-content" class="iam-tab-content hidden">${renderIamDetailsViewHtml()}</div>
            <div id="critical-perms-content" class="iam-tab-content hidden"></div>
            <div id="federation-content" class="iam-tab-content hidden"></div>
        </div>`;

    const tabsNav = container.querySelector('#iam-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.iam-tab-content'));

    const getDetailsBtn = document.getElementById('iam-get-details-btn');
    if (getDetailsBtn) getDetailsBtn.addEventListener('click', getIamPermissionDetails);

    if (window.iamApiData) updateIamDashboard();
    
    // CAMBIO AQUÍ: Llamar updateSecurityHubDashboard si hay CUALQUIER dato de Security Hub
    if (window.securityHubApiData || window.securityHubStatusApiData) {
        updateSecurityHubDashboard();
    }
    
    if (window.accessAnalyzerApiData) {
        renderAccessAnalyzerContent();
    }
    if (window.federationApiData) {
        renderFederationView();
    }
};


// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const renderAccessAnalyzerStatusTable = (summary) => {
    if (!summary || summary.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100 mb-6"><p class="text-center text-gray-500">No active Access Analyzers found in any region.</p></div>';
    }

    let tableHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto mb-6">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">Enabled Analyzers Summary</h3>
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Analyzer Name</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">`;

    summary.sort((a, b) => a.Region.localeCompare(b.Region)).forEach(analyzer => {
        tableHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${analyzer.Region}</td>
                <td class="px-4 py-4 text-sm text-gray-800 font-mono break-all">${analyzer.Name}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${analyzer.Type}</td>
            </tr>`;
    });

    tableHtml += `</tbody></table></div>`;
    return tableHtml;
};

const renderAccessAnalyzerContent = () => {
    const container = document.getElementById('access-analyzer-content');
    if (!container || !window.accessAnalyzerApiData) return;

    const { findings, summary } = window.accessAnalyzerApiData.results;

    let contentHtml = renderAccessAnalyzerStatusTable(summary);

    if (!findings || findings.length === 0) {
        contentHtml += `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">Good job! No external access findings were found.</p></div>`;
        container.innerHTML = contentHtml;
        return;
    }

    contentHtml += `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">External Access Findings</h3>
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-1/12">Region</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-4/12">Affected Resource</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-4/12">External Principal</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-1/12">Public</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-2/12">Allowed Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">`;

    const scannedAccountId = window.iamApiData?.metadata?.accountId;
    const rolesFromScan = window.iamApiData?.results?.roles;

    findings.forEach(f => {
        const publicBadge = f.IsPublic 
            ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">YES</span>`
            : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">No</span>`;
        
        const principalDisplay = f.Principal === 'Public' 
            ? `<span class="font-bold text-red-600">* (Anyone)</span>` 
            : f.Principal;

        let vipBadge = '';
        if (f.ResourceType === 'AWS::IAM::Role' && scannedAccountId && rolesFromScan) {
            try {
                const resourceArn = f.Resource;
                const resourceAccountId = resourceArn.split(':')[4];
                if (resourceAccountId === scannedAccountId) {
                    const roleNameParts = resourceArn.split('/');
                    const roleName = roleNameParts[roleNameParts.length - 1];
                    const roleDetails = rolesFromScan.find(r => r.RoleName === roleName);
                    if (roleDetails && roleDetails.IsPrivileged) {
                        vipBadge = '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>';
                    }
                }
            } catch (e) { /* silent fail */ }
        }

        contentHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-4 align-top whitespace-nowrap text-xs text-gray-600">${f.Region}</td>
                <td class="px-4 py-4 align-top text-xs text-gray-800 font-mono break-all whitespace-normal">
                    <div>
                        ${vipBadge}
                        <span class="font-semibold">${f.ResourceType}</span>
                    </div>
                    ${f.Resource}
                </td>
                <td class="px-4 py-4 align-top whitespace-normal text-xs text-gray-600 font-mono break-all">${principalDisplay}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-xs">${publicBadge}</td>
                <td class="px-4 py-4 align-top whitespace-normal text-xs text-gray-600 break-all">${f.Action}</td>
            </tr>`;
    });

    contentHtml += `</tbody></table></div>`;
    container.innerHTML = contentHtml;
};

const createIamResumenHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Total Users</p></div><div class="flex justify-between items-end pt-4"><p id="iam-total-users" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6m2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0m4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4m-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10s-3.516.68-4.168 1.332c-.678.678-.83 1.418-.832 1.664z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Users with Elevated Privileges</p></div><div class="flex justify-between items-end pt-4"><p id="iam-privileged-users" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-yellow-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-yellow-600" viewBox="0 0 16 16"><path d="M12.5 16a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7m.5-5v1h1a.5.5 0 0 1 0 1h-1v1a.5.5 0 0 1-1 0v-1h-1a.5.5 0 0 1 0-1h1v-1a.5.5 0 0 1 1 0m-2-6a3 3 0 1 1-6 0 3 3 0 0 1 6 0M8 7a2 2 0 1 0 0-4 2 2 0 0 0 0 4"/><path d="M8.256 14a4.5 4.5 0 0 1-.229-1.004H3c.001-.246.154-.986.832-1.664C4.484 10.68 5.711 10 8 10q.39 0 .74.025c.226-.341.496-.65.804-.918Q8.844 9.002 8 9c-5 0-6 3-6 4s1 1 1 1z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Groups with Elevated Privileges</p></div><div class="flex justify-between items-end pt-4"><p id="iam-privileged-groups" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-yellow-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-yellow-600" viewBox="0 0 16 16"><path d="M5 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4m4-2.5a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1h-4a.5.5 0 0 1-.5-.5M9 8a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1h-4A.5.5 0 0 1 9 8m1 2.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3a.5.5 0 0 1-.5-.5"/><path d="M2 2a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zM1 4a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H8.96q.04-.245.04-.5C9 10.567 7.21 9 5 9c-2.086 0-3.8 1.398-3.984 3.181A1 1 0 0 1 1 12z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Users with Elevated Privileges</p></div><div class="flex justify-between items-end pt-4"><p id="iam-privileged-roles" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-yellow-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-yellow-600" viewBox="0 0 16 16"><path d="M0 4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2zm9 1.5a.5.5 0 0 0 .5.5h4a.5.5 0 0 0 0-1h-4a.5.5 0 0 0-.5.5M9 8a.5.5 0 0 0 .5.5h4a.5.5 0 0 0 0-1h-4A.5.5 0 0 0 9 8m1 2.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3a.5.5 0 0 1-.5-.5m-1 2C9 10.567 7.21 9 5 9c-2.086 0-3.8 1.398-3.984 3.181A1 1 0 0 1 1 12zM7 6a2 2 0 1 0-4 0 2 2 0 0 0 4 0"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">MFA Compliance</p></div><div class="flex justify-between items-end pt-4"><p id="iam-mfa-compliance" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"><path d="M6.5 2a.5.5 0 0 0 0 1h3a.5.5 0 0 0 0-1zM11 8a3 3 0 1 1-6 0 3 3 0 0 1 6 0"/><path d="M4.5 0A2.5 2.5 0 0 0 2 2.5V14a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V2.5A2.5 2.5 0 0 0 11.5 0zM3 2.5A1.5 1.5 0 0 1 4.5 1h7A1.5 1.5 0 0 1 13 2.5v10.795a4.2 4.2 0 0 0-.776-.492C11.392 12.387 10.063 12 8 12s-3.392.387-4.224.803a4.2 4.2 0 0 0-.776.492z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Password Policies</p></div><div class="flex justify-between items-end pt-4"><p id="iam-password-compliance" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M14.5 3a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-9a.5.5 0 0 1 .5-.5zm-13-1A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2z"/><path d="M7 5.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m-1.496-.854a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 1 1 .708-.708l.146.147 1.146-1.147a.5.5 0 0 1 .708 0M7 9.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m-1.496-.854a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 0 1 .708-.708l.146.147 1.146-1.147a.5.5 0 0 1 .708 0"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">IAM Findings (Crit/High)</p></div><div class="flex justify-between items-end pt-4"><p id="iam-critical-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"> <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/></svg></div></div></div>
    </div>`;

const createIamUsuariosHtml = () => `
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">IAM Users List</h3>
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Password</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Use of Password</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">MFA</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Groups</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attached Policies</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Inline Policies</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-3/12">Access Keys</th>
                    </tr>
                </thead>
                <tbody id="users-table-body" class="bg-white divide-y divide-gray-200"></tbody>
            </table>
        </div>
    </div>`;


const createIamGruposHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">IAM Groups List</h3><div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Group name</th><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Creation Date</th><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attached Policies</th></tr></thead><tbody id="groups-table-body" class="bg-white divide-y divide-gray-200"></tbody></table></div></div>`;
const createIamRolesHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">IAM Roles List</h3><div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role name</th><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Creation Date</th><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attached Policies</th></tr></thead><tbody id="roles-table-body" class="bg-white divide-y divide-gray-200"></tbody></table></div></div>`;
const createIamPoliticasHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Account password policy</h3><div id="password-policy-container"></div></div>`;   

const createSecurityHubHtml = () => `
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (IAM)</h3>
        
        <div id="iam-sh-filter-controls" class="flex flex-wrap items-center gap-2 mb-4">
            <span class="text-sm font-medium text-gray-700 mr-2">Filter by Severity:</span>
            <button data-severity="ALL" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-[#eb3496] text-white">All</button>
            <button data-severity="CRITICAL" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">Critical</button>
            <button data-severity="HIGH" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">High</button>
            <button data-severity="MEDIUM" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">Medium</button>
            <button data-severity="LOW" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">Low</button>
        </div>
        <div id="sh-iam-findings-container" class="overflow-x-auto"></div>
    </div>`;

const updateIamDashboard = () => { 
    const { users, roles, groups, password_policy } = window.iamApiData.results;
    const { accountId, executionDate } = window.iamApiData.metadata;
    const scanInfo = `Results for Account ${accountId} - ${executionDate}`;
    const infoElement = document.querySelector('#iam-view .scan-info');
    if (infoElement) infoElement.textContent = scanInfo;
    const totalUsers = users.length;
    const privilegedUsersCount = users.filter(u => u.IsPrivileged).length;
    const privilegedGroupsCount = groups.filter(g => g.IsPrivileged).length;
    const privilegedRolesCount = roles.filter(r => r.IsPrivileged).length;
    const mfaEnabledUsers = users.filter(u => u.MFADevices.length > 0).length;
    const mfaCompliance = totalUsers > 0 ? Math.round((mfaEnabledUsers / totalUsers) * 100) : 0;
    let passwordPolicyCompliance = 0;
    if (!password_policy.Error) {
        const checks = [ (password_policy.MinimumPasswordLength || 0) >= 12, password_policy.RequireUppercaseCharacters, password_policy.RequireLowercaseCharacters, password_policy.RequireNumbers, password_policy.RequireSymbols, password_policy.MaxPasswordAge && password_policy.MaxPasswordAge <= 90, (password_policy.PasswordReusePrevention || 0) >= 4, password_policy.HardExpiry ];
        const passedChecks = checks.filter(Boolean).length;
        passwordPolicyCompliance = Math.round((passedChecks / checks.length) * 100);
    }
    const criticalHighIamFindings = window.securityHubApiData.results.findings.iamFindings.filter(f => f.Severity?.Label === 'CRITICAL' || f.Severity?.Label === 'HIGH').length;
    document.getElementById('iam-total-users').textContent = totalUsers;
    document.getElementById('iam-privileged-users').textContent = privilegedUsersCount;
    document.getElementById('iam-privileged-groups').textContent = privilegedGroupsCount;
    document.getElementById('iam-privileged-roles').textContent = privilegedRolesCount;
    document.getElementById('iam-mfa-compliance').textContent = `${mfaCompliance}%`;
    document.getElementById('iam-password-compliance').textContent = `${passwordPolicyCompliance}%`;
    document.getElementById('iam-critical-findings').textContent = criticalHighIamFindings;
    renderUsersTable(users);
    renderGroupsTable(groups);
    renderRolesTable(roles);
    renderPasswordPolicy(password_policy);

    renderCriticalPermissionsTable(users);
};

const renderCriticalPermissionsTable = (users) => {
    const container = document.getElementById('critical-perms-content');
    if (!container) return;

    const permissionsByCategory = {
        network: [],
        cloudtrail: [],
        database: [],
        waf: []
    };

    users.forEach(user => {
        if (user.criticalPermissions) {
            for (const category in user.criticalPermissions) {
                if (user.criticalPermissions[category].length > 0) {
                    permissionsByCategory[category].push({
                        userName: user.UserName,
                        permissions: user.criticalPermissions[category]
                    });
                }
            }
        }
    });

    const categoryNames = {
        network: 'Red (VPC, SG, ACLs)',
        cloudtrail: 'CloudTrail',
        database: 'Bases de Datos (RDS, DynamoDB)',
        waf: 'WAF'
    };
    const categoryStyles = {
        network: 'bg-blue-100 text-blue-800',
        cloudtrail: 'bg-indigo-100 text-indigo-800',
        database: 'bg-purple-100 text-purple-800',
        waf: 'bg-pink-100 text-pink-800'
    };

    const hasAnyPrivilegedUser = Object.values(permissionsByCategory).some(userList => userList.length > 0);

    if (!hasAnyPrivilegedUser) {
        container.innerHTML = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><p class="text-center text-gray-500">Good job! No users with critical permissions were found in the analyzed categories.</p></div>`;
        return;
    }

    let tableHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                        <h3 class="font-bold text-lg mb-4 text-[#204071]">Critical Permissions by Service</h3>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-1/4">Critical Service</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Users and Assigned Permissions</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">`;

    for (const category in permissionsByCategory) {
        const userList = permissionsByCategory[category];
        if (userList.length > 0) {
            tableHtml += `<tr class="hover:bg-gray-50">
                            <td class="px-6 py-4 align-top">
                                <span class="inline-block ${categoryStyles[category]} text-sm font-semibold mr-2 px-4 py-1.5 rounded-full">${categoryNames[category]}</span>
                            </td>
                            <td class="px-6 py-4 text-sm align-top">
                                <div class="space-y-4">`;
            
            userList.forEach(user => {
                const permissionsBadges = user.permissions.map(perm => 
                    `<span class="inline-block bg-gray-100 text-gray-800 text-xs font-mono font-medium mr-2 mb-2 px-2.5 py-0.5 rounded-full">${perm}</span>`
                ).join('');

                tableHtml += `<div class="border-b border-gray-100 pb-3 last:border-b-0">
                                <p class="font-semibold text-gray-800">${user.userName}</p>
                                <div class="mt-1">${permissionsBadges}</div>
                            </div>`;
            });

            tableHtml += `</div></td></tr>`;
        }
    }

    tableHtml += `</tbody></table></div></div>`;
    container.innerHTML = tableHtml;
};

const renderFederationView = () => {
    const container = document.getElementById('federation-content');
    if (!container || !window.federationApiData || !window.federationApiData.results) {
        if(container) container.innerHTML = '<p class="text-center text-gray-500 py-4">Federation data is not available. Run a scan or check for API errors.</p>';
        return;
    }

    const { iam_federation = {}, identity_center = {} } = window.federationApiData.results;

    let aliasHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 mb-6">
                        <h3 class="font-bold text-lg mb-2 text-[#204071]">Account Alias</h3>`;
    if (iam_federation.account_alias) {
        const signInUrl = `https://${iam_federation.account_alias}.signin.aws.amazon.com/console`;
        aliasHtml += `<p class="text-sm text-gray-600">Alias: <strong class="font-mono bg-gray-100 p-1 rounded">${iam_federation.account_alias}</strong></p>
                    <p class="text-sm text-gray-600 mt-2">Sign-in URL:</p>
                    <a href="${signInUrl}" target="_blank" class="text-blue-600 hover:underline font-mono text-sm break-all">${signInUrl}</a>`;
    } else {
        aliasHtml += `<p class="text-sm text-gray-600">This account does not have a custom alias configured.</p>`;
    }
    aliasHtml += `</div>`;
    
    let identityCenterHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 mt-6">
                                <h3 class="font-bold text-lg mb-4 text-[#204071]">AWS Identity Center (SSO)</h3>`;

    if (identity_center.status === 'Found') {
        const { instance_arn, assignments } = identity_center;

        identityCenterHtml += `<div class="mb-6 space-y-2 text-sm">
                                    <p><strong class="text-gray-600">Instance ARN:</strong> <span class="font-mono bg-gray-100 p-1 rounded">${instance_arn}</span></p>
                                </div>`;

        if (assignments && assignments.length > 0) {
            identityCenterHtml += `<h4 class="font-semibold text-md mb-2">Permission Assignments</h4>
                                    <div class="overflow-x-auto">
                                    <table id="sso-assignments-table" class="min-w-full divide-y divide-gray-200">
                                        <thead class="bg-gray-50"><tr>
                                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Group</th>
                                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Permission Set (Role)</th>
                                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">AWS Account ID</th>
                                            <th class="px-4 py-2 text-center text-xs font-medium text-gray-500 uppercase">Details</th>
                                        </tr></thead>
                                        <tbody class="bg-white divide-y divide-gray-200">`;
            assignments.forEach(a => {
                const vipBadge = a.IsPrivileged ? '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>' : '';
                
                identityCenterHtml += `<tr class="hover:bg-gray-50">
                                        <td class="px-4 py-3 text-sm font-medium text-gray-800">${a.GroupName}</td>
                                        <td class="px-4 py-3 text-sm text-gray-600">${vipBadge}${a.PermissionSetName}</td>
                                        <td class="px-4 py-3 text-sm text-gray-600 font-mono">${a.AccountId}</td>
                                        <td class="px-4 py-3 text-center">
                                            <button onclick="openModalWithSsoDetails('${a.GroupId}', '${a.GroupName}')" class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">View</button>
                                        </td>
                                    </tr>`;
            });
            identityCenterHtml += `</tbody></table></div>`;
        } else {
            identityCenterHtml += `<p class="text-center text-gray-500 py-4">Identity Center is enabled, but no group permission assignments were found.</p>`;
        }
    } else {
        const message = identity_center.message || "Could not retrieve Identity Center information. Necessary permissions (sso-admin, identitystore) may be missing or the service is not configured.";
        identityCenterHtml += `<p class="text-center text-gray-500 py-4">${message}</p>`;
    }
    
    identityCenterHtml += `</div>`;
    
    container.innerHTML = aliasHtml + identityCenterHtml;
};

export const openModalWithSsoDetails = async (groupId, groupName) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    if (!modal || !modalTitle || !modalContent) return;

    modalTitle.textContent = `Members of Group: ${groupName}`;
    modalContent.innerHTML = `
        <div class="space-y-3 animate-pulse p-2">
            <div class="h-8 bg-slate-200 rounded-md w-full"></div>
            <div class="h-8 bg-slate-200 rounded-md w-5/6"></div>
            <div class="h-8 bg-slate-200 rounded-md w-2/3"></div>
        </div>`;
    modal.classList.remove('hidden');

    log(`Fetching members for SSO Group ID: ${groupId}`, 'info');
    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
        group_id: groupId
    };

    try {
        const response = await fetch('http://127.0.0.1:5001/api/get-sso-group-members', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        const memberCount = data.members ? data.members.length : 0;
        let membersListHtml = '';
        if (memberCount > 0) {
            membersListHtml = '<div class="space-y-2 text-left">';
            data.members.forEach(member => {
                membersListHtml += `<div class="bg-slate-100 text-slate-800 text-sm font-mono p-2 rounded-md">${member}</div>`;
            });
            membersListHtml += '</div>';
        } else {
            membersListHtml = '<p class="text-sm text-gray-500 text-center py-4">This group has no members.</p>';
        }
        modalContent.innerHTML = membersListHtml;
        log(`Successfully fetched ${memberCount} members for group ${groupName}.`, 'success');

    } catch (e) {
        modalContent.innerHTML = `<div class="bg-red-50 text-red-700 p-3 rounded-lg text-left"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
        log(`Error fetching group members: ${e.message}`, 'error');
    }
};

export const openModalWithAccessKeyDetails = (userIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const user = window.iamApiData.results.users[userIndex];
    if (!modal || !user || !user.AccessKeys || user.AccessKeys.length === 0) return;

    modalTitle.textContent = `Access Keys for User: ${user.UserName}`;
    const keysDetailsHtml = user.AccessKeys.map(k => {
        const createDate = new Date(k.CreateDate);
        const now = new Date();
        const ageDays = Math.floor((now - createDate) / (1000 * 60 * 60 * 24));
        const ageClass = ageDays > 90 ? 'text-red-600 font-bold' : 'text-gray-600';
        const statusClass = k.Status === 'Active' ? 'text-green-600' : 'text-gray-500';
        const lastUsed = k.LastUsedDate !== 'N/A' ? new Date(k.LastUsedDate).toLocaleDateString() : 'Never';

        return `
            <div class="p-3 bg-gray-100 rounded-md border border-gray-200 text-xs text-left">
                <div class="font-mono font-semibold text-gray-800">${k.AccessKeyId}</div>
                <div class="mt-1"><span class="font-semibold">Status:</span> <span class="${statusClass}">${k.Status}</span></div>
                <div><span class="font-semibold">Age:</span> <span class="${ageClass}">${ageDays} days</span></div>
                <div><span class="font-semibold">Last Used:</span> ${lastUsed}</div>
            </div>`;
    }).join('');
    modalContent.innerHTML = `<div class="space-y-3">${keysDetailsHtml}</div>`;
    modal.classList.remove('hidden');
};

export const openModalWithUserGroups = (userIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const user = window.iamApiData.results.users[userIndex];
    if (!modal || !user || !user.Groups || user.Groups.length === 0) return;

    modalTitle.textContent = `Groups for User: ${user.UserName}`;
    const groupsListHtml = user.Groups.map(groupName => {
        return `<div class="p-3 bg-gray-100 rounded-md border border-gray-200 text-sm text-left font-semibold text-gray-800">
                    ${groupName}
                </div>`;
    }).join('');
    modalContent.innerHTML = `<div class="space-y-3">${groupsListHtml}</div>`;
    modal.classList.remove('hidden');
};

export const updateSecurityHubDashboard = () => {
    const securityHubData = window.securityHubApiData || window.securityHubStatusApiData;
    const containerElement = document.getElementById('sh-iam-findings-container');
    
    if (!securityHubData || !securityHubData.results || !securityHubData.results.findings) {
        // Si no hay findings, mostrar mensaje vacío
        const container = document.getElementById('sh-iam-findings-container');
        if (container) {
            container.innerHTML = '<p class="text-center text-gray-500 py-4">No Security Hub data available. Run an analysis first.</p>';
        }
        return;
    }

    const allIamFindings = securityHubData.results.findings.iamFindings || [];
    const filterControlsContainer = document.getElementById('iam-sh-filter-controls');

    const renderFilteredFindings = (severity) => {
        let filteredFindings = allIamFindings;
        if (severity !== 'ALL') {
            filteredFindings = allIamFindings.filter(f => f.Severity?.Label === severity);
        }
        renderSecurityHubFindings(filteredFindings, 'sh-iam-findings-container', `No IAM findings with severity '${severity}' were found.`);
    };

    if (filterControlsContainer) {
        // Aseguramos que el listener solo se añade una vez
        if (!filterControlsContainer.dataset.listenerAttached) {
            filterControlsContainer.addEventListener('click', (e) => {
                const filterBtn = e.target.closest('.iam-sh-filter-btn');
                if (!filterBtn) return;
                filterControlsContainer.querySelectorAll('.iam-sh-filter-btn').forEach(btn => {
                    btn.classList.remove('bg-[#eb3496]', 'text-white');
                    btn.classList.add('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
                });
                filterBtn.classList.add('bg-[#eb3496]', 'text-white');
                filterBtn.classList.remove('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
                const selectedSeverity = filterBtn.dataset.severity;
                renderFilteredFindings(selectedSeverity);
            });
            filterControlsContainer.dataset.listenerAttached = 'true';
        }
    }

    renderFilteredFindings('ALL');
};


const renderUsersTable = (users) => {
    const tableBody = document.getElementById('users-table-body');
    tableBody.innerHTML = '';
    if (!users || users.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-gray-500 py-4">No users were found.</td></tr>`;
        return;
    }
    
    users.forEach((user, index) => {
        const vipBadge = user.IsPrivileged ? '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>' : '';
        const passwordEnabled = user.PasswordEnabled ? 'YES' : 'NO';
        const mfaEnabled = user.MFADevices.length > 0 ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">YES</span>' : '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">NO</span>';
        
        let groupsHtml = '-';
        if (user.Groups && user.Groups.length > 0) {
            groupsHtml = `<button 
                              onclick="openModalWithUserGroups(${index})" 
                              class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                              View (${user.Groups.length})
                          </button>`;
        }

        const attachedPolicies = user.AttachedPolicies.join(', ') || '-';
        const inlinePolicies = user.InlinePolicies.join(', ') || '-';
        
        let accessKeysHtml = '-';
        if (user.AccessKeys && user.AccessKeys.length > 0) {
            accessKeysHtml = `<button 
                                onclick="openModalWithAccessKeyDetails(${index})" 
                                class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                                View (${user.AccessKeys.length})
                              </button>`;
        }
        
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50';
        
        row.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap text-xs font-medium text-[#204071] flex items-center">${vipBadge}${user.UserName}</td> 
            <td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${passwordEnabled}</td> 
            <td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${user.PasswordLastUsed}</td> 
            <td class="px-6 py-4 whitespace-nowrap text-xs">${mfaEnabled}</td> 
            <td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${groupsHtml}</td> 
            <td class="px-6 py-4 text-xs text-gray-500 break-words">${attachedPolicies}</td> 
            <td class="px-6 py-4 text-xs text-gray-500 break-words">${inlinePolicies}</td> 
            <td class="px-6 py-4 text-xs text-gray-500 align-top">${accessKeysHtml}</td>`;
        tableBody.appendChild(row);
    });
};

const renderGroupsTable = (groups) => {
    const tableBody = document.getElementById('groups-table-body');
    tableBody.innerHTML = '';
    if (!groups || groups.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="3" class="text-center text-gray-500 py-4">No groups were found.</td></tr>`;
        return;
    }
    groups.forEach(group => {
        const vipBadge = group.IsPrivileged ? '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>' : '';
        const attachedPolicies = group.AttachedPolicies.join(', ') || '-';
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50';
        row.innerHTML = `<td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-[#204071] flex items-center">${vipBadge}${group.GroupName}</td> <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${new Date(group.CreateDate).toLocaleDateString()}</td> <td class="px-6 py-4 text-sm text-gray-500 break-words">${attachedPolicies}</td>`;
        tableBody.appendChild(row);
    });
};

const renderRolesTable = (roles) => {
    const tableBody = document.getElementById('roles-table-body');
    tableBody.innerHTML = '';
    if (!roles || roles.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="3" class="text-center text-gray-500 py-4">No roles were found.</td></tr>`;
        return;
    }
    roles.forEach(role => {
        const vipBadge = role.IsPrivileged ? '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>' : '';
        const attachedPolicies = role.AttachedPolicies.join(', ') || '-';
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50';
        row.innerHTML = `<td class="px-6 py-4 text-sm font-medium text-[#204071] break-words flex items-center">${vipBadge}${role.RoleName}</td> <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${new Date(role.CreateDate).toLocaleDateString()}</td> <td class="px-6 py-4 text-sm text-gray-500 break-words">${attachedPolicies}</td>`;
        tableBody.appendChild(row);
    });
};

const renderPasswordPolicy = (policy) => {
    const container = document.getElementById('password-policy-container');
    container.innerHTML = '';
    if (policy.Error) {
        container.innerHTML = `<p class="text-red-600 font-medium">There is no password policy configured for this account.</p>`;
        return;
    }
    const checks = [
        { desc: "Minimum length >= 12", ok: (policy.MinimumPasswordLength || 0) >= 12, val: policy.MinimumPasswordLength },
        { desc: "Requires uppercase", ok: policy.RequireUppercaseCharacters, val: policy.RequireUppercaseCharacters },
        { desc: "Requires lowercase letters", ok: policy.RequireLowercaseCharacters, val: policy.RequireLowercaseCharacters },
        { desc: "Requires numbers", ok: policy.RequireNumbers, val: policy.RequireNumbers },
        { desc: "Requires symbols", ok: policy.RequireSymbols, val: policy.RequireSymbols },
        { desc: "Expiration ≤ 90 days", ok: policy.MaxPasswordAge && policy.MaxPasswordAge <= 90, val: policy.MaxPasswordAge },
        { desc: "Reuse ≥ 4 passwords", ok: (policy.PasswordReusePrevention || 0) >= 4, val: policy.PasswordReusePrevention },
        { desc: "Forced expiration after failure", ok: policy.HardExpiry, val: policy.HardExpiry },
    ];
    let checksHtml = `<h4 class="font-semibold text-md mb-2">Compliance Checks</h4><div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200 mb-6"><thead class="bg-gray-50"><tr><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Check</th><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Configured Value</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">`;
    checks.forEach(({ desc, ok, val }) => {
        const statusIcon = ok ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">OK</span>' : '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">KO</span>';
        checksHtml += `<tr><td class="px-4 py-2 whitespace-nowrap text-sm text-gray-700">${desc}</td><td class="px-4 py-2 whitespace-nowrap text-sm">${statusIcon}</td><td class="px-4 py-2 whitespace-nowrap text-sm text-gray-500">${val === undefined ? 'Not defined' : val}</td></tr>`;
    });
    checksHtml += `</tbody></table></div>`;
    const rawJsonHtml = `<h4 class="font-semibold text-md mb-2 mt-6">API Raw Response</h4><pre class="bg-[#204071] text-white p-4 rounded-lg text-sm overflow-x-auto"><code>${JSON.stringify(policy, null, 2)}</code></pre>`;
    container.innerHTML = checksHtml + rawJsonHtml;
};

const renderIamDetailsViewHtml = () => {
    return `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-4 text-[#204071]">View Detailed Permissions of an IAM Principal</h3>
            <p class="text-sm text-gray-600 mb-4">Enter the exact name of a user, group, or role to view all of its associated permission policies.</p>
            <div class="flex flex-col sm:flex-row gap-4 items-end">
                <div class="flex-grow">
                    <label for="iam-principal-name" class="block text-sm font-medium text-gray-700 mb-1">Name of User, Group, or Role</label>
                    <input type="text" id="iam-principal-name" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="E.g.: admin-user, DevelopersGroup, EC2AdminRole">
                </div>
                <button id="iam-get-details-btn" class="w-full sm:w-auto bg-[#204071] text-white px-5 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition">View details</button>
            </div>
        </div>
        <div id="iam-details-result-container" class="mt-6"></div>
    `;
};

const getIamPermissionDetails = () => {
    log('Fetching IAM permission details...', 'info');
    const rawInput = document.getElementById('iam-principal-name').value.trim();
    const resultsContainer = document.getElementById('iam-details-result-container');
    let principalNameToSearch = rawInput;

    if (!rawInput) {
        resultsContainer.innerHTML = `<p class="text-yellow-600 font-medium">Please provide a name or ARN to search.</p>`;
        return;
    }

    if (rawInput.toLowerCase().startsWith('arn:aws:iam::')) {
        try {
            const parts = rawInput.split('/');
            principalNameToSearch = parts[parts.length - 1];
            log(`ARN detected. Searching for extracted name: '${principalNameToSearch}'`, 'info');
        } catch (e) {
            log('Error parsing ARN. Using full value.', 'error');
        }
    }

    if (!window.iamApiData || !window.iamApiData.results) {
        resultsContainer.innerHTML = `<p class="text-red-600 font-medium">No IAM data loaded. Please run an analysis first.</p>`;
        log('Attempted permission search without IAM data.', 'error');
        return;
    }

    const { users, groups, roles } = window.iamApiData.results;
    let foundPrincipal = null;
    let principalType = '';

    const user = users.find(u => u.UserName.toLowerCase() === principalNameToSearch.toLowerCase());
    if (user) {
        foundPrincipal = user;
        principalType = 'User';
    } else {
        const group = groups.find(g => g.GroupName.toLowerCase() === principalNameToSearch.toLowerCase());
        if (group) {
            foundPrincipal = group;
            principalType = 'Group';
        } else {
            const role = roles.find(r => r.RoleName.toLowerCase() === principalNameToSearch.toLowerCase());
            if (role) {
                foundPrincipal = role;
                principalType = 'Role';
            }
        }
    }
    
    renderIamPermissionDetails(foundPrincipal, principalType, rawInput);
};

const renderIamPermissionDetails = (principal, type, searchedTerm) => {
    const resultsContainer = document.getElementById('iam-details-result-container');
    if (!principal) {
        resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Not Found</h4><p>Could not find any user, group, or role with the name or ARN '${searchedTerm}'.</p></div>`;
        log(`IAM Principal '${searchedTerm}' not found.`, 'error');
        return;
    }

    let detailsToShow = {};
    const name = type === 'User' ? principal.UserName : (type === 'Group' ? principal.GroupName : principal.RoleName);

    if (type === 'User') {
        detailsToShow = {
            Type: 'User',
            Name: principal.UserName,
            DirectPermissions: {
                AttachedPolicies: principal.AttachedPolicies,
                InlinePolicies: principal.InlinePolicies,
            },
            InheritedPermissions: {
                 Groups: principal.Groups,
                 AssumableRoles_by_Tag: principal.Roles,
            }
        };
    } else if (type === 'Group') {
         detailsToShow = {
            Type: 'Group',
            Name: principal.GroupName,
            Permissions: {
                AttachedPolicies: principal.AttachedPolicies,
            }
        };
    } else if (type === 'Role') {
         detailsToShow = {
            Type: 'Role',
            Name: principal.RoleName,
            Permissions: {
                AttachedPolicies: principal.AttachedPolicies,
                InlinePolicies: principal.InlinePolicies
            }
        };
    }
    
    const formattedJson = JSON.stringify(detailsToShow, null, 2);
    log(`Showing details for ${type}: ${name}`, 'success');

    resultsContainer.innerHTML = `
        <h3 class="text-xl font-bold text-[#204071] mb-4">Showing details for ${type}: ${name}</h3>
        <pre class="bg-[#204071] text-white p-4 rounded-lg text-xs font-mono overflow-x-auto">${formattedJson}</pre>
    `;
};