/**
 * 14_connectivity.js
 * Contains all the logic for building and rendering the Network Connectivity view.
 */

// --- IMPORTS ---
// This module only needs the handleTabClick utility.
import { handleTabClick } from '../utils.js';


// --- MAIN VIEW FUNCTION (EXPORTED) ---
// We export the main function so app.js can find and use it.
export const buildConnectivityView = () => {
    const container = document.getElementById('connectivity-view');
    if (!container || !window.connectivityApiData) return;

    const { peering_connections, tgw_attachments, vpn_connections, vpc_endpoints } = window.connectivityApiData.results;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Network Connectivity</h2>
                <p class="text-sm text-gray-500">${window.connectivityApiData.metadata.executionDate}</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="connectivity-tabs">
                <a href="#" data-tab="conn-peering-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">VPC Peering (${peering_connections.length})</a>
                <a href="#" data-tab="conn-tgw-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Transit Gateway (${tgw_attachments.length})</a>
                <a href="#" data-tab="conn-vpn-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">VPN Connections (${vpn_connections.length})</a>
                <a href="#" data-tab="conn-endpoints-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">VPC Endpoints (${vpc_endpoints.length})</a>
            </nav>
        </div>
        <div id="connectivity-tab-content-container">
            <div id="conn-peering-content" class="connectivity-tab-content">${renderPeeringTable(peering_connections)}</div>
            <div id="conn-tgw-content" class="connectivity-tab-content hidden">${renderTgwAttachmentsTable(tgw_attachments)}</div>
            <div id="conn-vpn-content" class="connectivity-tab-content hidden">${renderVpnConnectionsTable(vpn_connections)}</div>
            <div id="conn-endpoints-content" class="connectivity-tab-content hidden">${renderVpcEndpointsTable(vpc_endpoints)}</div>
        </div>
    `;
    
    const tabsNav = container.querySelector('#connectivity-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.connectivity-tab-content'));
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const renderPeeringTable = (connections) => {
    if (!connections || connections.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No active VPC Peering connections were found.</p></div>';
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Connection ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Requester VPC</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Accepter VPC</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    connections.forEach(c => {
        const requesterInfo = `${c.RequesterVpc.VpcId} (${c.RequesterVpc.OwnerId})`;
        const accepterInfo = `${c.AccepterVpc.VpcId} (${c.AccepterVpc.OwnerId})`;
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${c.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${c.ConnectionId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${requesterInfo}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${accepterInfo}</td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderTgwAttachmentsTable = (attachments) => {
    if (!attachments || attachments.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No VPC attachments to Transit Gateways were found.</p></div>';
     let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Transit Gateway ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Attached VPC</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Attachment ID</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    attachments.forEach(a => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${a.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${a.TransitGatewayId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${a.VpcId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${a.AttachmentId}</td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderVpnConnectionsTable = (connections) => {
    if (!connections || connections.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No active VPN connections were found.</p></div>';
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPN Connection ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Customer Gateway ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Associated TGW</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    connections.forEach(c => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${c.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${c.VpnConnectionId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${c.CustomerGatewayId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${c.TransitGatewayId}</td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderVpcEndpointsTable = (endpoints) => {
    if (!endpoints || endpoints.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No VPC Endpoints were found.</p></div>';
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Service Name</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    endpoints.forEach(e => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${e.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${e.VpcId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${e.EndpointType}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 break-all font-mono">${e.ServiceName}</td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};