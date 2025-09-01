/**
 * 12_kms.js
 * Contains all logic for building and rendering the Key Management Service (KMS) view.
 */

// --- IMPORTS ---
import { handleTabClick, createStatusBadge } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
    overview: {
        title: "AWS Key Management Service (KMS)",
        description: "AWS KMS is a managed service that makes it easy to create and control cryptographic keys used to encrypt your data. It provides centralized key management integrated with other AWS services.",
        useCases: "Data encryption at rest and in transit, database encryption, S3 bucket encryption, EBS volume encryption, application-level encryption, compliance with regulatory requirements.",
        auditConsiderations: "Review key policies for least privilege access, verify automatic key rotation is enabled for customer-managed keys, ensure proper separation of duties for key administration, validate that sensitive workloads use customer-managed keys instead of AWS-managed keys."
    },
    customerManagedKeys: {
        title: "Customer Managed Keys (CMK)",
        description: "Customer Managed Keys are KMS keys that you create, own, and manage. You have full control over these keys including key policies, rotation, and deletion.",
        useCases: "High-security environments requiring full control, compliance requirements mandating customer key ownership, cross-account access scenarios, custom key rotation policies.",
        auditConsiderations: "Verify that sensitive data uses CMKs instead of AWS-managed keys, ensure key rotation is enabled and appropriate, review key policies for overly permissive access, validate key usage logging in CloudTrail."
    },
    awsManagedKeys: {
        title: "AWS Managed Keys",
        description: "AWS Managed Keys are created, managed, and used on your behalf by AWS services. You cannot manage these keys directly, but you can audit their usage.",
        useCases: "Default encryption for AWS services, simplified key management for non-sensitive workloads, services that require transparent encryption without additional configuration.",
        auditConsiderations: "Identify workloads using AWS-managed keys that should potentially use customer-managed keys for enhanced security, monitor usage patterns, ensure compliance policies allow AWS-managed key usage."
    },
    keyRotation: {
        title: "Key Rotation",
        description: "Key rotation is the practice of replacing cryptographic keys on a regular schedule. AWS KMS supports automatic annual rotation for customer-managed keys.",
        useCases: "Compliance requirements for regular key rotation, reducing cryptographic risk over time, maintaining security best practices for long-lived encryption keys.",
        auditConsiderations: "Verify automatic rotation is enabled for all customer-managed keys unless there's a valid business reason, review rotation schedules align with compliance requirements, ensure applications can handle key rotation transparently."
    }
};

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildKmsView = () => {
    const container = document.getElementById('kms-view');
    if (!container || !window.kmsApiData) return;

    const { keys } = window.kmsApiData.results;
    const executionDate = window.kmsApiData.metadata.executionDate;

    // Separate keys by type for tab counts
    const customerManagedKeys = keys.filter(k => k.KeyManager === 'CUSTOMER');
    const awsManagedKeys = keys.filter(k => k.KeyManager === 'AWS');

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Key Management Service (KMS)</h2>
                <p class="text-sm text-gray-500">${executionDate}</p>
            </div>
        </header>
        
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review KMS key management to ensure proper encryption controls, key rotation policies, and access management. Focus on customer-managed keys for sensitive workloads and verify compliance with organizational security requirements.</p>
        </div>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="kms-tabs">
                <a href="#" data-tab="kms-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="kms-overview-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">KMS Overview</a>
                <a href="#" data-tab="kms-customer-keys-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Customer Keys (${customerManagedKeys.length})</a>
                <a href="#" data-tab="kms-aws-keys-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">AWS Keys (${awsManagedKeys.length})</a>
                <a href="#" data-tab="kms-rotation-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Key Rotation</a>
            </nav>
        </div>
        <div id="kms-tab-content-container">
            <div id="kms-summary-content" class="kms-tab-content">${createKmsSummaryCardsHtml()}</div>
            <div id="kms-overview-content" class="kms-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.overview)}
                ${renderAllKeysTable(keys)}
            </div>
            <div id="kms-customer-keys-content" class="kms-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.customerManagedKeys)}
                ${renderCustomerManagedKeysTable(customerManagedKeys)}
            </div>
            <div id="kms-aws-keys-content" class="kms-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.awsManagedKeys)}
                ${renderAwsManagedKeysTable(awsManagedKeys)}
            </div>
            <div id="kms-rotation-content" class="kms-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.keyRotation)}
                ${renderKeyRotationTable(customerManagedKeys)}
            </div>
        </div>
    `;

    updateKmsSummaryCards(keys);
    
    const tabsNav = container.querySelector('#kms-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.kms-tab-content'));
};

// --- SERVICE DESCRIPTION RENDERER ---
const renderServiceDescription = (serviceInfo) => {
    return `
        <div class="bg-white border border-gray-200 rounded-lg p-6 mb-6">
            <h3 class="text-lg font-semibold text-gray-800 mb-3">${serviceInfo.title}</h3>
            <div class="space-y-3">
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Definition:</h4>
                    <p class="text-sm text-gray-600">${serviceInfo.description}</p>
                </div>
                <div>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Common Use Cases:</h4>
                    <p class="text-sm text-gray-600">${serviceInfo.useCases}</p>
                </div>
                <div class="bg-yellow-50 border border-yellow-200 rounded p-3">
                    <h4 class="text-sm font-medium text-yellow-800 mb-1">Audit Considerations:</h4>
                    <p class="text-sm text-yellow-700">${serviceInfo.auditConsiderations}</p>
                </div>
            </div>
        </div>
    `;
};

// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const createKmsSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Total KMS Keys</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="kms-total-keys" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-lock w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 0a4 4 0 0 1 4 4v2.05a2.5 2.5 0 0 1 2 2.45v5a2.5 2.5 0 0 1-2.5 2.5h-7A2.5 2.5 0 0 1 2 13.5v-5a2.5 2.5 0 0 1 2-2.45V4a4 4 0 0 1 4-4M4.5 7A1.5 1.5 0 0 0 3 8.5v5A1.5 1.5 0 0 0 4.5 15h7a1.5 1.5 0 0 0 1.5-1.5v-5A1.5 1.5 0 0 0 11.5 7zM8 1a3 3 0 0 0-3 3v2h6V4a3 3 0 0 0-3-3"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Customer Managed</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="kms-customer-managed" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-person-gear w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M11 5a3 3 0 1 1-6 0 3 3 0 0 1 6 0M8 7a2 2 0 1 0 0-4 2 2 0 0 0 0 4m.256 7a4.5 4.5 0 0 1-.229-1.004H3c.001-.246.154-.986.832-1.664C4.484 10.68 5.711 10 8 10q.39 0 .74.025c.226-.341.496-.65.804-.918Q8.844 9.002 8 9c-5 0-6 3-6 4s1 1 1 1zm3.63-4.54c.18-.613 1.048-.613 1.229 0l.043.148a.64.64 0 0 0 .921.382l.136-.074c.561-.306 1.175.308.87.869l-.075.136a.64.64 0 0 0 .382.92l.149.045c.612.18.612 1.048 0 1.229l-.15.043a.64.64 0 0 0-.38.921l.074.136c.305.561-.309 1.175-.87.87l-.136-.075a.64.64 0 0 0-.92.382l-.045.149c-.18.612-1.048.612-1.229 0l-.043-.15a.64.64 0 0 0-.921-.38l-.136.074c-.561.305-1.175-.309-.87-.87l.075-.136a.64.64 0 0 0-.382-.92l-.148-.045c-.613-.18-.613-1.048 0-1.229l.148-.043a.64.64 0 0 0 .382-.921l-.074-.136c-.306-.561.308-1.175.869-.87l.136.075a.64.64 0 0 0 .92-.382zM14 12.5a1.5 1.5 0 1 0-3 0 1.5 1.5 0 0 0 3 0"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">AWS Managed</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="kms-aws-managed" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-yellow-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-amazon w-6 h-6 text-yellow-600" viewBox="0 0 16 16"><path d="M10.813 11.968c.157.083.36.074.5-.05l.005.005a90 90 0 0 1 1.623-1.405c.173-.143.143-.372.006-.563l-.125-.17c-.345-.465-.673-.906-.673-1.791v-3.3l.001-.335c.008-1.265.014-2.421-.933-3.305C10.404.274 9.06 0 8.03 0 6.017 0 3.77.75 3.296 3.24c-.047.264.143.404.316.443l2.054.22c.19-.009.33-.196.366-.387.176-.857.896-1.271 1.703-1.271.435 0 .929.16 1.188.55.264.39.26.91.257 1.376v.432q-.3.033-.621.065c-1.113.114-2.397.246-3.36.67C3.873 5.91 2.94 7.08 2.94 8.798c0 2.2 1.387 3.298 3.168 3.298 1.506 0 2.328-.354 3.489-1.54l.167.246c.274.405.456.675 1.047 1.166ZM6.03 8.431C6.03 6.627 7.647 6.3 9.177 6.3v.57c.001.776.002 1.434-.396 2.133-.336.595-.87.961-1.465.961-.812 0-1.286-.619-1.286-1.533M.435 12.174c2.629 1.603 6.698 4.084 13.183.997.28-.116.475.078.199.431C13.538 13.96 11.312 16 7.57 16 3.832 16 .968 13.446.094 12.386c-.24-.275.036-.4.199-.299z"/><path d="M13.828 11.943c.567-.07 1.468-.027 1.645.204.135.176-.004.966-.233 1.533-.23.563-.572.961-.762 1.115s-.333.094-.23-.137c.105-.23.684-1.663.455-1.963-.213-.278-1.177-.177-1.625-.13l-.09.009q-.142.013-.233.024c-.193.021-.245.027-.274-.032-.074-.209.779-.556 1.347-.623"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Key Rotation Disabled (CMK)</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="kms-rotation-disabled" class="text-3xl font-bold text-red-600">--</p>
                <div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-arrow-clockwise w-6 h-6 text-red-600" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2z"/><path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466"/></svg></div>
            </div>
        </div>
    </div>
`;

const updateKmsSummaryCards = (keys) => {
    document.getElementById('kms-total-keys').textContent = keys.length;
    document.getElementById('kms-customer-managed').textContent = keys.filter(k => k.KeyManager === 'CUSTOMER').length;
    document.getElementById('kms-aws-managed').textContent = keys.filter(k => k.KeyManager === 'AWS').length;
    document.getElementById('kms-rotation-disabled').textContent = keys.filter(k => k.RotationEnabled === 'Disabled').length;
};

const renderAllKeysTable = (keys) => {
    if (!keys || keys.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No KMS keys found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have any KMS keys configured.</p>
                </div>
            </div>
        `;
    }

    return renderKmsKeysTable(keys, 'All KMS Keys');
};

const renderCustomerManagedKeysTable = (keys) => {
    if (!keys || keys.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No customer-managed keys found</h3>
                    <p class="mt-1 text-sm text-gray-500">Consider creating customer-managed keys for enhanced security control over sensitive workloads.</p>
                </div>
            </div>
        `;
    }

    return renderKmsKeysTable(keys, 'Customer Managed Keys');
};

const renderAwsManagedKeysTable = (keys) => {
    if (!keys || keys.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No AWS-managed keys found</h3>
                    <p class="mt-1 text-sm text-gray-500">AWS-managed keys are automatically created when AWS services require encryption.</p>
                </div>
            </div>
        `;
    }

    return renderKmsKeysTable(keys, 'AWS Managed Keys');
};

const renderKeyRotationTable = (keys) => {
    if (!keys || keys.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No customer-managed keys for rotation analysis</h3>
                    <p class="mt-1 text-sm text-gray-500">Key rotation only applies to customer-managed keys.</p>
                </div>
            </div>
        `;
    }

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Alias</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Key ID</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rotation Status</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk Level</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    keys.sort((a,b) => a.Region.localeCompare(b.Region) || a.Aliases.localeCompare(b.Aliases)).forEach((k) => {
        const rotationBadge = k.RotationEnabled === 'Enabled' ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        const riskLevel = k.RotationEnabled === 'Disabled' ? 
            '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">High Risk</span>' :
            '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">Low Risk</span>';
        
        tableHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${k.Region}</td>
                <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${k.Aliases}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600 font-mono">${k.KeyId}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${rotationBadge}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${riskLevel}</td>
            </tr>
        `;
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
};

const renderKmsKeysTable = (keys, title) => {
    if (!keys || keys.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No KMS keys were found.</p></div>';
    }

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Alias</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Key ID</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">State</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rotation</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Manager</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Key Policy</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    keys.sort((a,b) => a.Region.localeCompare(b.Region) || a.Aliases.localeCompare(b.Aliases)).forEach((k, index) => {
        const rotationBadge = k.RotationEnabled === 'Enabled' ? createStatusBadge('Enabled') : (k.RotationEnabled === 'Disabled' ? createStatusBadge('Disabled') : createStatusBadge(k.RotationEnabled));
        
        tableHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${k.Region}</td>
                <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${k.Aliases}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600 font-mono">${k.KeyId}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${createStatusBadge(k.Status)}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${rotationBadge}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${k.KeyManager}</td>                        
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">
                    <button 
                        onclick="openModalWithKmsPolicy(${index})" 
                        class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">
                        View Policy
                    </button>
                </td>
            </tr>
        `;
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
};

// --- MODAL FUNCTION (EXPORTED) ---
export const openModalWithKmsPolicy = (keyIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const key = window.kmsApiData.results.keys[keyIndex];

    if (!modal || !key || !key.Policy) return;

    modalTitle.textContent = `Key Policy for: ${key.Aliases || key.KeyId}`;
    
    const formattedPolicy = JSON.stringify(key.Policy, null, 2);

    modalContent.innerHTML = `
        <div class="text-left">
            <pre class="bg-[#204071] text-white text-xs font-mono rounded-md p-3 overflow-x-auto"><code>${formattedPolicy}</code></pre>
        </div>
    `;

    modal.classList.remove('hidden');
};