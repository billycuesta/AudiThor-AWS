/**
 * 11_databases.js
 * Contains all logic for building and rendering the Databases view.
 */

// --- IMPORTS ---
import { handleTabClick, createStatusBadge } from '../utils.js';


// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildDatabasesView = () => {
    const container = document.getElementById('databases-view');
    if (!container || !window.databasesApiData) return;

    const { rds_instances = [], aurora_clusters = [], dynamodb_tables = [], documentdb_clusters = [] } = window.databasesApiData.results || {};
    
    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Databases</h2>
                <p class="text-sm text-gray-500">${window.databasesApiData.metadata.executionDate}</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="databases-tabs">
                <a href="#" data-tab="db-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="db-rds-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">RDS Instances (${rds_instances.length})</a>
                <a href="#" data-tab="db-aurora-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Aurora Clusters (${aurora_clusters.length})</a>
                <a href="#" data-tab="db-dynamodb-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">DynamoDB Tables (${dynamodb_tables.length})</a>
                <a href="#" data-tab="db-docdb-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">DocumentDB (${documentdb_clusters.length})</a>
            </nav>
        </div>
        <div id="databases-tab-content-container">
            <div id="db-summary-content" class="databases-tab-content">${createDatabasesSummaryCardsHtml()}</div>
            <div id="db-rds-content" class="databases-tab-content hidden">${renderRdsTable(rds_instances)}</div>
            <div id="db-aurora-content" class="databases-tab-content hidden">${renderAuroraTable(aurora_clusters)}</div>
            <div id="db-dynamodb-content" class="databases-tab-content hidden">${renderDynamoDbTable(dynamodb_tables)}</div>
            <div id="db-docdb-content" class="databases-tab-content hidden">${renderDocumentDbTable(documentdb_clusters)}</div>
        </div>
    `;
    
    updateDatabasesSummaryCards(rds_instances, aurora_clusters, dynamodb_tables, documentdb_clusters);
    
    const tabsNav = container.querySelector('#databases-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.databases-tab-content'));
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const createDatabasesSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">RDS Instances (Standalone)</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="db-total-rds" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-database w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Aurora Clusters</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="db-total-aurora" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-database w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">DynamoDB Tables</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="db-total-dynamodb" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-purple-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-database w-6 h-6 text-purple-600" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">DocumentDB Clusters</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="db-total-docdb" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-teal-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-earmark-code w-6 h-6 text-teal-600" viewBox="0 0 16 16"><path d="M14 4.5V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2h5.5zm-3 0A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V4.5z"/><path d="M8.646 6.646a.5.5 0 0 1 .708 0l2 2a.5.5 0 0 1 0 .708l-2 2a.5.5 0 0 1-.708-.708L10.293 8 8.646 6.354a.5.5 0 0 1 0-.708m-1.292 0a.5.5 0 0 0-.708 0l-2 2a.5.5 0 0 0 0 .708l2 2a.5.5 0 0 0 .708-.708L5.707 8l1.647-1.646a.5.5 0 0 0 0-.708"/></svg></div>
            </div>
        </div>
    </div>
`;

const createEncryptionBadge = (isEncrypted) => {
    return isEncrypted
        ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">YES</span>`
        : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">NO</span>`;
};

const updateDatabasesSummaryCards = (rds, aurora, dynamodb, docdb) => {
    document.getElementById('db-total-rds').textContent = rds.length;
    document.getElementById('db-total-aurora').textContent = aurora.length;
    document.getElementById('db-total-dynamodb').textContent = dynamodb.length;
    document.getElementById('db-total-docdb').textContent = docdb.length;
};

const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
 
const renderRdsTable = (instances) => {
    if (!instances || instances.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No standalone RDS instances were found.</p></div>';
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public Access</th>' + 
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encrypted</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">KMS Key Alias/ID</th>' +
                '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    instances.forEach(i => {
        const publicBadge = i.PubliclyAccessible 
            ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">YES</span>`
            : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">NO</span>`;

        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${i.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${i.DBInstanceIdentifier}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(i.DBInstanceStatus)}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${publicBadge}</td> 
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createEncryptionBadge(i.Encrypted)}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 font-mono break-all">${i.KmsKeyAlias}</td>
                    <td class="px-4 py-4 text-center">
                        <button onclick="copyToClipboard(this, '${i.ARN}')" title="${i.ARN}" class="p-1 rounded-md hover:bg-gray-200 transition">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
                        </button>
                    </td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderAuroraTable = (clusters) => {
    if (!clusters || clusters.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No Aurora clusters were found.</p></div>';
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encrypted</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">KMS Key Alias/ID</th>' +
                '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    clusters.forEach(c => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${c.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${c.ClusterIdentifier}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(c.Status)}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createEncryptionBadge(c.Encrypted)}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 font-mono break-all">${c.KmsKeyAlias}</td>
                    <td class="px-4 py-4 text-center">
                        <button onclick="copyToClipboard(this, \'${c.ARN}\')" title="${c.ARN}" class="p-1 rounded-md hover:bg-gray-200 transition">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
                        </button>
                    </td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderDynamoDbTable = (tables) => {
    if (!tables || tables.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No DynamoDB tables were found.</p></div>';
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Table Name</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encrypted</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">KMS Key Alias/Type</th>' +
                '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    tables.forEach(t => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${t.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${t.TableName}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createEncryptionBadge(t.Encrypted)}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 font-mono break-all">${t.KmsKeyAlias}</td>
                    <td class="px-4 py-4 text-center">
                        <button onclick="copyToClipboard(this, '${t.ARN}')" title="${t.ARN}" class="p-1 rounded-md hover:bg-gray-200 transition">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
                        </button>
                    </td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderDocumentDbTable = (clusters) => {
    if (!clusters || clusters.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No DocumentDB clusters were found.</p></div>';
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encrypted</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">KMS Key Alias/ID</th>' +
                '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    clusters.forEach(c => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${c.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${c.ClusterIdentifier}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(c.Status)}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createEncryptionBadge(c.Encrypted)}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 font-mono break-all">${c.KmsKeyAlias}</td>
                    <td class="px-4 py-4 text-center">
                        <button onclick="copyToClipboard(this, '${c.ARN}')" title="${c.ARN}" class="p-1 rounded-md hover:bg-gray-200 transition">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
                        </button>
                    </td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};