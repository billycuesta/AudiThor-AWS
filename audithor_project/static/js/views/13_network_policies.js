/**
 * 13_network_policies.js
 * Contiene toda la lógica para construir y renderizar la vista de Network Security Policies.
 */

// --- IMPORTACIONES ---
import { handleTabClick, log } from '../utils.js';


// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
export const buildNetworkPoliciesView = () => {
    const container = document.getElementById('network-policies-view');
    if (!window.networkPoliciesApiData || !window.computeApiData || !window.databasesApiData) {
        container.innerHTML = '<p class="text-center text-gray-500">Network Policies, Compute, or Databases data not available.</p>';
        return;
    }

    const { vpcs, acls, security_groups, subnets, all_regions } = window.networkPoliciesApiData.results;
    const { ec2_instances, lambda_functions } = window.computeApiData.results;
    const { rds_instances, aurora_clusters } = window.databasesApiData.results;

    const activeRegions = [...new Set(vpcs.map(v => v.Region))].sort();
    const regionOptionsHtml = activeRegions.map(r => `<option value="${r}">${r}</option>`).join('');

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Network Security Policies</h2>
                <p class="text-sm text-gray-500">${window.networkPoliciesApiData.metadata.executionDate}</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="network-policies-tabs">
                <a href="#" data-tab="np-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="np-vpcs-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">VPCs (${vpcs.length})</a>
                <a href="#" data-tab="np-acls-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Network ACLs (${acls.length})</a>
                <a href="#" data-tab="np-sgs-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Groups (${security_groups.length})</a>
                <a href="#" data-tab="np-detail-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Details</a>
            </nav>
        </div>
        <div id="network-policies-tab-content-container">
            <div id="np-summary-content" class="network-policies-tab-content">
                ${createNetworkPoliciesSummaryCardsHtml()}
                <div id="vpc-diagram-container" class="mt-8">
                    <div class="flex justify-between items-center mb-4 flex-wrap gap-4">
                        <h3 class="text-xl font-bold text-[#204071]">Network Diagram</h3>
                        <div class="flex items-center gap-x-6 gap-y-2 flex-wrap">
                            <div class="flex items-center gap-2">
                                <label for="vpc-diagram-region-filter" class="text-sm font-medium text-gray-700">Filter by Region:</label>
                                <select id="vpc-diagram-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5">
                                    <option value="all">All Regions</option>
                                    ${regionOptionsHtml}
                                </select>
                            </div>
                            <div class="flex items-center gap-2">
                                <input type="checkbox" id="vpc-diagram-hide-empty-filter" class="h-4 w-4 rounded border-gray-300 text-[#eb3496] focus:ring-[#eb3496]">
                                <label for="vpc-diagram-hide-empty-filter" class="text-sm font-medium text-gray-700">Hide empty VPCs</label>
                            </div>
                        </div>
                    </div>
                    <div id="diagram-content-wrapper"></div>
                </div>
            </div>
            <div id="np-vpcs-content" class="network-policies-tab-content hidden"></div>
            <div id="np-acls-content" class="network-policies-tab-content hidden"></div>
            <div id="np-sgs-content" class="network-policies-tab-content hidden"></div>
            <div id="np-detail-content" class="network-policies-tab-content hidden"></div>
        </div>
    `;

    updateNetworkPoliciesSummaryCards(vpcs, acls, security_groups);

    const diagramWrapper = document.getElementById('diagram-content-wrapper');
    const regionFilter = document.getElementById('vpc-diagram-region-filter');
    const hideEmptyFilter = document.getElementById('vpc-diagram-hide-empty-filter');

    const updateDiagram = () => {
        const selectedRegion = regionFilter.value;
        const hideEmpty = hideEmptyFilter.checked;
        let filteredVpcs = (selectedRegion === 'all') ? vpcs : vpcs.filter(v => v.Region === selectedRegion);

        if (hideEmpty) {
            filteredVpcs = filteredVpcs.filter(vpc => {
                const hasEc2 = ec2_instances.some(i => {
                    const subnet = subnets.find(s => s.SubnetId === i.SubnetId);
                    return subnet && subnet.VpcId === vpc.VpcId;
                });
                const hasLambda = lambda_functions.some(l => l.VpcConfig && l.VpcConfig.VpcId === vpc.VpcId);
                const hasRds = rds_instances.some(r => r.VpcId === vpc.VpcId);
                const hasAurora = aurora_clusters.some(a => a.VpcId === vpc.VpcId);
                return hasEc2 || hasLambda || hasRds || hasAurora;
            });
        }
        diagramWrapper.innerHTML = renderVpcDiagram(filteredVpcs, subnets, ec2_instances, lambda_functions, rds_instances, aurora_clusters);
    };

    if (regionFilter) regionFilter.addEventListener('change', updateDiagram);
    if (hideEmptyFilter) hideEmptyFilter.addEventListener('change', updateDiagram);
    
    updateDiagram();
    
    const vpcsContainer = document.getElementById('np-vpcs-content');
    const aclsContainer = document.getElementById('np-acls-content');
    const sgsContainer = document.getElementById('np-sgs-content');
    const detailContainer = document.getElementById('np-detail-content');
    
    vpcsContainer.innerHTML = renderVPCsTable(vpcs, all_regions, 'all');
    aclsContainer.innerHTML = renderACLsTable(acls, all_regions, 'all');
    sgsContainer.innerHTML = renderSGsTable(security_groups, all_regions, 'all');
    detailContainer.innerHTML = renderNetworkDetailView(all_regions || []);

    container.addEventListener('change', (e) => {
        const selectedRegion = e.target.value;
        switch (e.target.id) {
            case 'vpc-region-filter':
                vpcsContainer.innerHTML = renderVPCsTable(vpcs.filter(v => selectedRegion === 'all' || v.Region === selectedRegion), all_regions, selectedRegion);
                break;
            case 'acl-region-filter':
                aclsContainer.innerHTML = renderACLsTable(acls.filter(a => selectedRegion === 'all' || a.Region === selectedRegion), all_regions, selectedRegion);
                break;
            case 'sg-region-filter':
                sgsContainer.innerHTML = renderSGsTable(security_groups.filter(sg => selectedRegion === 'all' || sg.Region === selectedRegion), all_regions, selectedRegion);
                break;
        }
    });
    
    const detailRunBtn = detailContainer.querySelector('#np-run-detail-btn');
    if(detailRunBtn) detailRunBtn.addEventListener('click', runNetworkDetailAnalysis);

    const tabsNav = container.querySelector('#network-policies-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.network-policies-tab-content'));
};


// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const createNetworkPoliciesSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Total VPCs</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="np-total-vpcs" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v4h10V2a1 1 0 0 0-1-1zm9 6H6v2h7zm0 3H6v2h7zm0 3H6v2h6a1 1 0 0 0 1-1zm-8 2v-2H3v1a1 1 0 0 0 1 1zm-2-3h2v-2H3zm0-3h2V7H3z"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Default VPCs</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="np-default-vpcs" class="text-3xl font-bold text-yellow-600">--</p>
                <div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v4h10V2a1 1 0 0 0-1-1zm9 6H6v2h7zm0 3H6v2h7zm0 3H6v2h6a1 1 0 0 0 1-1zm-8 2v-2H3v1a1 1 0 0 0 1 1zm-2-3h2v-2H3zm0-3h2V7H3z"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Total Network ACLs</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="np-total-acls" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M12 0H4a2 2 0 0 0-2 2v4h12V2a2 2 0 0 0-2-2m2 7H6v2h8zm0 3H6v2h8zm0 3H6v3h6a2 2 0 0 0 2-2zm-9 3v-3H2v1a2 2 0 0 0 2 2zm-3-4h3v-2H2zm0-3h3V7H2z"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Total Security Groups</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="np-total-sgs" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M12 0H4a2 2 0 0 0-2 2v4h12V2a2 2 0 0 0-2-2m2 7H6v2h8zm0 3H6v2h8zm0 3H6v3h6a2 2 0 0 0 2-2zm-9 3v-3H2v1a2 2 0 0 0 2 2zm-3-4h3v-2H2zm0-3h3V7H2z"/></svg></div>
            </div>
        </div>
    </div>`;

const updateNetworkPoliciesSummaryCards = (vpcs, acls, sgs) => {
    document.getElementById('np-total-vpcs').textContent = vpcs.length;
    document.getElementById('np-default-vpcs').textContent = vpcs.filter(v => v.IsDefault).length;
    document.getElementById('np-total-acls').textContent = acls.length;
    document.getElementById('np-total-sgs').textContent = sgs.length;
};

const renderVPCsTable = (vpcs, allRegions, selectedRegion = 'all') => {
    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');
    const filterControl = `<div class="mb-4 flex items-center gap-2"><label for="vpc-region-filter" class="text-sm font-medium text-gray-700">Filter by Region:</label><select id="vpc-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5"><option value="all">All Regions</option>${regionOptions}</select></div>`;
    if (!vpcs || vpcs.length === 0) return `<div class="bg-white p-6 rounded-xl border border-gray-100">${filterControl}<p class="text-center text-gray-500 py-4">No VPCs matching the selected filters were found.</p></div>`;
    let table = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC ID</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">CIDR Block</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Is Default</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tags</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    vpcs.sort((a,b) => a.Region.localeCompare(b.Region)).forEach(v => {
        const tagsStr = Object.entries(v.Tags).map(([k, val]) => `${k}:${val}`).join(', ') || '-';
        const isDefault = v.IsDefault ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">YES</span>' : 'NO';
        table += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${v.Region}</td><td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${v.VpcId}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${v.CidrBlock}</td><td class="px-4 py-4 whitespace-nowrap text-sm">${isDefault}</td><td class="px-4 py-4 text-sm text-gray-600 break-all">${tagsStr}</td></tr>`;
    });
    table += '</tbody></table></div>';
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControl}${table}</div>`;
};

const renderACLsTable = (acls, allRegions, selectedRegion = 'all') => {
    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');
    const filterControl = `<div class="mb-4 flex items-center gap-2"><label for="acl-region-filter" class="text-sm font-medium text-gray-700">Filter by Region:</label><select id="acl-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5"><option value="all">All Regions</option>${regionOptions}</select></div>`;
    if (!acls || acls.length === 0) return `<div class="bg-white p-6 rounded-xl border border-gray-100">${filterControl}<p class="text-center text-gray-500 py-4">No Network ACLs matching the selected filters were found.</p></div>`;
    let table = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ACL ID</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC ID</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Is Default</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tags</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    acls.sort((a,b) => a.Region.localeCompare(b.Region)).forEach(a => {
        const tagsStr = Object.entries(a.Tags).map(([k, val]) => `${k}:${val}`).join(', ') || '-';
        const isDefault = a.IsDefault ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">YES</span>' : 'NO';
        table += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${a.Region}</td><td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${a.AclId}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${a.VpcId}</td><td class="px-4 py-4 whitespace-nowrap text-sm">${isDefault}</td><td class="px-4 py-4 text-sm text-gray-600 break-all">${tagsStr}</td></tr>`;
    });
    table += '</tbody></table></div>';
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControl}${table}</div>`;
};        

const renderSGsTable = (sgs, allRegions, selectedRegion = 'all') => {
    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');
    const filterControl = `<div class="mb-4 flex items-center gap-2"><label for="sg-region-filter" class="text-sm font-medium text-gray-700">Filter by Region:</label><select id="sg-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5"><option value="all">All Regions</option>${regionOptions}</select></div>`;
    if (!sgs || sgs.length === 0) return `<div class="bg-white p-6 rounded-xl border border-gray-100">${filterControl}<p class="text-center text-gray-500 py-4">No Security Groups matching the selected filters were found.</p></div>`;
    let table = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Group ID</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Group Name</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tags</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    sgs.sort((a,b) => a.Region.localeCompare(b.Region)).forEach(sg => {
        const tagsStr = Object.entries(sg.Tags).map(([k, val]) => `${k}:${val}`).join(', ') || '-';
        table += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${sg.Region}</td><td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${sg.GroupId}</td><td class="px-4 py-4 text-sm text-gray-600 break-all">${sg.GroupName}</td><td class="px-4 py-4 text-sm text-gray-600 break-all">${sg.Description}</td><td class="px-4 py-4 text-sm text-gray-600 break-all">${tagsStr}</td></tr>`;
    });
    table += '</tbody></table></div>';
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControl}${table}</div>`;
};        

const renderVpcDiagram = (vpcs, subnets, instances, lambdas, rdsInstances, auroraClusters) => {
    if (!vpcs || vpcs.length === 0) return '<p class="text-center text-gray-500">No VPCs were found to display in the diagram.</p>';
    let diagramHtml = '<div class="space-y-8">';
    vpcs.forEach(vpc => {
        const vpcSubnets = subnets.filter(s => s.VpcId === vpc.VpcId);
        const vpcInstances = instances.filter(i => vpcSubnets.some(s => s.SubnetId === i.SubnetId));
        const vpcLambdas = lambdas.filter(l => l.VpcConfig && l.VpcConfig.VpcId === vpc.VpcId);
        const vpcRds = rdsInstances.filter(r => r.VpcId === vpc.VpcId);
        const vpcAurora = auroraClusters.filter(a => a.VpcId === vpc.VpcId);
        const totalResources = vpcInstances.length + vpcLambdas.length + vpcRds.length + vpcAurora.length;

        diagramHtml += `<div class="bg-white border border-gray-200 rounded-xl shadow-md"><div class="bg-gray-50 p-3 border-b border-gray-200 rounded-t-xl"><h3 class="text-lg font-bold text-[#204071]">${vpc.Tags['Name'] || vpc.VpcId}</h3><p class="text-sm text-gray-500 font-mono">${vpc.Region} | ${vpc.VpcId} | ${vpc.CidrBlock} | ${vpcSubnets.length} subnets | ${totalResources} resources</p></div><div class="p-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">`;
        vpcSubnets.sort((a,b) => (a.Tags['Name'] || a.SubnetId).localeCompare(b.Tags['Name'] || b.SubnetId)).forEach(subnet => {
            diagramHtml += `<div class="bg-slate-50 border border-blue-200 rounded-lg p-3 flex flex-col"><div class="border-b border-blue-200 pb-2 mb-3"><p class="font-bold text-sm text-blue-800">${subnet.Tags['Name'] || subnet.SubnetId}</p><p class="text-xs text-gray-500 font-mono">${subnet.CidrBlock}</p></div><div class="space-y-2 flex-grow">`;
            const subnetInstances = instances.filter(i => i.SubnetId === subnet.SubnetId);
            if (subnetInstances.length > 0) {
                subnetInstances.sort((a,b) => (a.Tags['Name'] || a.InstanceId).localeCompare(b.Tags['Name'] || b.InstanceId)).forEach(instance => {
                    const state = instance.State.toLowerCase();
                    let bgColor = (state === 'running') ? 'bg-green-100 border border-green-300' : 'bg-red-100 border border-red-300';
                    const instanceName = instance.Tags['Name'] || instance.InstanceId;
                    diagramHtml += `<div class="${bgColor} p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${instanceName}">${instanceName}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${instance.InstanceType}</span><span>${instance.State}</span></div></div>`;
                });
            }
            const subnetLambdas = lambdas.filter(l => l.VpcConfig && l.VpcConfig.SubnetIds && l.VpcConfig.SubnetIds.includes(subnet.SubnetId));
            if (subnetLambdas.length > 0) {
                subnetLambdas.sort((a,b) => a.FunctionName.localeCompare(b.FunctionName)).forEach(lambda => {
                    diagramHtml += `<div class="bg-purple-100 border border-purple-300 p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${lambda.FunctionName}"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="inline-block mr-1" viewBox="0 0 16 16"><path d="M14 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1zM2 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2z"/><path d="M6.854 4.646a.5.5 0 0 1 0 .708L4.207 8l2.647 2.646a.5.5 0 0 1-.708.708l-3-3a.5.5 0 0 1 0-.708l3-3a.5.5 0 0 1 .708 0m2.292 0a.5.5 0 0 0 0 .708L11.793 8l-2.647 2.646a.5.5 0 0 0 .708.708l3-3a.5.5 0 0 0 0-.708l-3-3a.5.5 0 0 0-.708 0"/></svg>${lambda.FunctionName}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${lambda.Runtime}</span></div></div>`;
                });
            }
            const subnetRds = rdsInstances.filter(r => r.SubnetIds && r.SubnetIds.includes(subnet.SubnetId));
            if (subnetRds.length > 0) {
                subnetRds.forEach(rds => {
                    diagramHtml += `<div class="bg-blue-100 border border-blue-300 p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${rds.DBInstanceIdentifier}"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="inline-block mr-1" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg>${rds.DBInstanceIdentifier}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${rds.Engine}</span></div></div>`;
                });
            }
            const subnetAurora = auroraClusters.filter(c => c.SubnetIds && c.SubnetIds.includes(subnet.SubnetId));
            if (subnetAurora.length > 0) {
                subnetAurora.forEach(aurora => {
                    diagramHtml += `<div class="bg-teal-100 border border-teal-300 p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${aurora.ClusterIdentifier}"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="inline-block mr-1" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg>${aurora.ClusterIdentifier}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${aurora.Engine}</span></div></div>`;
                });
            }

            if (subnetInstances.length === 0 && subnetLambdas.length === 0 && subnetRds.length === 0 && subnetAurora.length === 0) {
                diagramHtml += '<p class="text-center text-xs text-gray-400 py-4">No resources</p>';
            }

            diagramHtml += `</div></div>`;
        });
        diagramHtml += `</div></div>`;
    });

    diagramHtml += '</div>';
    return diagramHtml;
};

const renderNetworkDetailView = (allRegions) => {
    const regionOptions = allRegions.map(r => `<option value="${r}">${r}</option>`).join('');
    
    return `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-4 text-[#204071]">Get Network Resource Details</h3>
            <p class="text-sm text-gray-600 mb-4">Enter the ID of a Security Group (e.g., sg-xxxx) or a Network ACL (e.g., acl-xxxx) and select its region to view its rules.</p>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4 items-end">
                <div class="lg:col-span-2">
                    <label for="np-resource-id" class="block text-sm font-medium text-gray-700 mb-1">Resource ID (SG or ACL)</label>
                    <input type="text" id="np-resource-id" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="sg-12345678 or acl-12345678">
                </div>
                <div>
                    <label for="np-resource-region" class="block text-sm font-medium text-gray-700 mb-1">Resource Region</label>
                    <select id="np-resource-region" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5">
                        <option value="">Select a Region</option>
                        ${regionOptions}
                    </select>
                </div>
            </div>
            <button id="np-run-detail-btn" class="bg-[#204071] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition flex items-center justify-center space-x-2">
                <span id="np-detail-btn-text">Analyze</span>
                <div id="np-detail-spinner" class="spinner hidden"></div>
            </button>
        </div>
        <div id="np-detail-results-container" class="mt-6"></div>
    `;
};

const runNetworkDetailAnalysis = async () => {
    log('Starting detailed network analysis…', 'info');
    const resourceId = document.getElementById('np-resource-id').value.trim();
    const region = document.getElementById('np-resource-region').value;
    const resultsContainer = document.getElementById('np-detail-results-container');
    resultsContainer.innerHTML = '';

    if (!resourceId || !region) {
        log('Resource ID and region are required.', 'error');
        resultsContainer.innerHTML = '<p class="text-red-600 font-medium">Error: Please enter an ID and select a region.</p>';
        return;
    }

    const runBtn = document.getElementById('np-run-detail-btn');
    const btnText = document.getElementById('np-detail-btn-text');
    const spinner = document.getElementById('np-detail-spinner');
    
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Analyzing...';
    
    // These need to be accessed from the global scope
    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');

    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
        resource_id: resourceId,
        region: region
    };

    try {
        const response = await fetch('http://127.0.0.1:5001/api/run-network-detail-audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Unknown server error.');
        }

        log('Detailed analysis completed.', 'success');
        renderNetworkDetailResult(data.results.details_table);

    } catch(e) {
        log(`Error during the detailed analysis: ${e.message}`, 'error');
        resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Analyze';
    }
};

const renderNetworkDetailResult = (tableString) => {
    const container = document.getElementById('np-detail-results-container');
    if (!tableString) {
        container.innerHTML = '<p class="text-gray-500">No results were found.</p>';
        return;
    }
    container.innerHTML = `
        <h3 class="text-xl font-bold text-[#204071] mb-4">Analysis Results</h3>
        <pre class="bg-[#204071] text-white p-4 rounded-lg text-xs font-mono overflow-x-auto">${tableString}</pre>
    `;
};