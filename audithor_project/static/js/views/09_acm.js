/**
 * 09_acm.js
 * Contains all logic for building and rendering the AWS Certificate Manager (ACM) view.
 */

// --- IMPORTS ---
import { handleTabClick, renderSecurityHubFindings } from '../utils.js';


// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildAcmView = () => {
    const container = document.getElementById('acm-view');
    if (!window.acmApiData || !window.securityHubApiData) return;

    const { certificates } = window.acmApiData.results;
    const acmSecurityHubFindings = window.securityHubApiData.results.findings.cloudwatchFindings.filter(f => f.Title.includes('Certificate') || f.Title.includes('SSL') || f.Title.includes('TLS'));

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">AWS Certificate Manager (ACM)</h2>
                <p class="text-sm text-gray-500">${window.acmApiData.metadata.executionDate}</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="acm-tabs">
                <a href="#" data-tab="acm-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="acm-certificates-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Digital Certificates (${certificates.length})</a>
                <a href="#" data-tab="acm-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${acmSecurityHubFindings.length})</a>
            </nav>
        </div>
        <div id="acm-tab-content-container">
            <div id="acm-summary-content" class="acm-tab-content">${createAcmSummaryCardsHtml()}</div>
            <div id="acm-certificates-content" class="acm-tab-content hidden">${renderAcmCertificatesTable(certificates)}</div>
            <div id="acm-sh-content" class="acm-tab-content hidden">${createAcmSecurityHubHtml()}</div>
        </div>
    `;
    
    updateAcmSummaryCards(certificates, acmSecurityHubFindings);
    renderSecurityHubFindings(acmSecurityHubFindings, 'sh-acm-findings-container', 'No Security Hub findings related to ACM were found.');

    const tabsNav = container.querySelector('#acm-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.acm-tab-content'));
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const createAcmSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Total Certificates</p></div><div class="flex justify-between items-end pt-4"><p id="acm-total-certs" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-card-heading w-6 h-6 text-blue-600" viewBox="0 0 16 16">  <path d="M14.5 3a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-9a.5.5 0 0 1 .5-.5zm-13-1A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2z"/>  <path d="M3 8.5a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5m0 2a.5.5 0 0 1 .5-.5h6a.5.5 0 0 1 0 1h-6a.5.5 0 0 1-.5-.5m0-5a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-9a.5.5 0 0 1-.5-.5z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Issued Certificates</p></div><div class="flex justify-between items-end pt-4"><p id="acm-issued-certs" class="text-3xl font-bold text-green-600">--</p><div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-patch-check w-6 h-6 text-green-600" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M10.354 6.146a.5.5 0 0 1 0 .708l-3 3a.5.5 0 0 1-.708 0l-1.5-1.5a.5.5 0 1 1 .708-.708L7 8.793l2.646-2.647a.5.5 0 0 1 .708 0z"/><path d="m10.273 2.513-.921-.944.715-.698.622.637.89-.011a2.89 2.89 0 0 1 2.924 2.924l-.01.89.636.622a2.89 2.89 0 0 1 0 4.134l-.637.622.011.89a2.89 2.89 0 0 1-2.924 2.924l-.89-.01-.622.636a2.89 2.89 0 0 1-4.134 0l-.622-.637-.89.01a2.89 2.89 0 0 1-2.924-2.924l.01-.89-.636-.622a2.89 2.89 0 0 1 0-4.134l.637-.622-.011-.89a2.89 2.89 0 0 1 2.924-2.924l.89.01.622-.636a2.89 2.89 0 0 1 4.134 0l-.715.698a1.89 1.89 0 0 0-2.704 0l-.92.944-1.32-.016a1.89 1.89 0 0 0-1.911 1.912l.016 1.318-.944.921a1.89 1.89 0 0 0 0 2.704l.944.92-.016 1.32a1.89 1.89 0 0 0 1.912 1.911l1.318-.016.921.944a1.89 1.89 0 0 0 2.704 0l.92-.944 1.32.016a1.89 1.89 0 0 0 1.911-1.912l-.016-1.318.944-.921a1.89 1.89 0 0 0 0-2.704l-.944-.92.016-1.32a1.89 1.89 0 0 0-1.912-1.911z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Pending Certificates</p></div><div class="flex justify-between items-end pt-4"><p id="acm-pending-certs" class="text-3xl font-bold text-yellow-600">--</p><div class="bg-yellow-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clock w-6 h-6 text-yellow-600" viewBox="0 0 16 16"><path d="M8 3.5a.5.5 0 0 0-1 0V9a.5.5 0 0 0 .252.434l3.5 2a.5.5 0 0 0 .496-.868L8 8.71z"/><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16m7-8A7 7 0 1 1 1 8a7 7 0 0 1 14 0"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Expired/Revoked</p></div><div class="flex justify-between items-end pt-4"><p id="acm-expired-revoked-certs" class="text-3xl font-bold text-red-600">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-triangle w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1-.054-.06.18.18 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/> <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Findings (Crit/High)</p></div><div class="flex justify-between items-end pt-4"><p id="acm-critical-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"> <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/></svg></div></div></div>
    </div>`;

const updateAcmSummaryCards = (certificates, securityHubFindings) => {
    document.getElementById('acm-total-certs').textContent = certificates.length;
    document.getElementById('acm-issued-certs').textContent = certificates.filter(c => c.Status === 'ISSUED').length;
    document.getElementById('acm-pending-certs').textContent = certificates.filter(c => c.Status === 'PENDING_VALIDATION').length;
    document.getElementById('acm-expired-revoked-certs').textContent = certificates.filter(c => c.Status === 'EXPIRED' || c.Status === 'REVOKED').length;
    document.getElementById('acm-critical-findings').textContent = securityHubFindings.filter(f => f.Severity?.Label === 'CRITICAL' || f.Severity?.Label === 'HIGH').length;
};

const createAcmSecurityHubHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (ACM via SH)</h3><div id="sh-acm-findings-container" class="overflow-x-auto"></div></div>`;

const renderAcmCertificatesTable = (certificates) => {
    if (!certificates || certificates.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No ACM certificates were found.</p></div>';
    }

    const statusColors = {
        'ISSUED': 'bg-green-100 text-green-800',
        'PENDING_VALIDATION': 'bg-yellow-100 text-yellow-800',
        'EXPIRED': 'bg-red-100 text-red-800',
        'REVOKED': 'bg-red-100 text-red-800',
        'INACTIVE': 'bg-gray-100 text-gray-800',
        'VALIDATION_TIMED_OUT': 'bg-red-100 text-red-800',
        'FAILED': 'bg-red-100 text-red-800',
    };

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Main Domain</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Issued By</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Issue Date</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Expiration Date</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">SANs</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    certificates.forEach(cert => {
        const domainName = cert.DomainName || 'N/A';
        const region = cert.Region || 'N/A';
        const status = cert.Status || 'N/A';
        const statusClass = statusColors[status] || 'bg-gray-100 text-gray-800';
        const issuer = cert.Issuer || 'N/A';
        const issuedAt = cert.IssuedAt ? new Date(cert.IssuedAt).toLocaleDateString() : 'N/A';
        const expiresAt = cert.NotAfter ? new Date(cert.NotAfter).toLocaleDateString() : 'N/A';
        const sans = cert.SubjectAlternativeNames && cert.SubjectAlternativeNames.length > 0 ? cert.SubjectAlternativeNames.join(', ') : '-';

        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${domainName}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${region}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap"><span class="px-2.5 py-0.5 text-xs font-semibold rounded-full ${statusClass}">${status}</span></td>
                        <td class="px-4 py-4 align-top text-sm text-gray-600 break-words">${issuer}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${issuedAt}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${expiresAt}</td>
                        <td class="px-4 py-4 align-top text-sm text-gray-600 break-words">${sans}</td>
                      </tr>`;
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
};