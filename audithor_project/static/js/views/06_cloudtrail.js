/**
 * 06_cloudtrail.js
 * Contiene toda la lógica para construir y renderizar la vista de CloudTrail.
 */

// --- IMPORTACIONES ---
import { handleTabClick, renderSecurityHubFindings, log } from '../utils.js';


// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
export const buildCloudtrailView = () => {
    const container = document.getElementById('cloudtrail-view');
    if (!window.cloudtrailApiData || !window.securityHubApiData) return;
    
    const { trails, events, trailguard_findings } = window.cloudtrailApiData.results;
    const cloudtrailFindings = window.securityHubApiData.results.findings.cloudtrailFindings;
    const allRegions = window.allAvailableRegions;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">CloudTrail Analysis</h2>
                <p class="text-sm text-gray-500">${window.cloudtrailApiData.metadata.executionDate}</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="cloudtrail-tabs">
                <a href="#" data-tab="ct-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="ct-trails-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Trails (${trails.length})</a>
                <a href="#" data-tab="ct-events-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Events (${events.length})</a>
                <a href="#" data-tab="ct-trailguard-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">TrailGuard</a>
                <a href="#" data-tab="ct-lookup-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Log Finder</a>
                <a href="#" data-tab="ct-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${cloudtrailFindings.length})</a>
            </nav>
        </div>
        <div id="cloudtrail-tab-content-container">
            <div id="ct-summary-content" class="cloudtrail-tab-content">${createCloudtrailSummaryCardsHtml()}</div>
            <div id="ct-trails-content" class="cloudtrail-tab-content hidden">${renderCloudtrailTrailsView(trails)}</div>
            <div id="ct-events-content" class="cloudtrail-tab-content hidden">${renderCloudtrailEventsTable(events)}</div>
            <div id="ct-trailguard-content" class="cloudtrail-tab-content hidden"></div>
            <div id="ct-lookup-content" class="cloudtrail-tab-content hidden"></div>
            <div id="ct-sh-content" class="cloudtrail-tab-content hidden">${createCloudtrailSecurityHubHtml()}</div>
        </div>`;
    
    updateCloudtrailSummaryCards(trails, events); 
    renderSecurityHubFindings(cloudtrailFindings, 'sh-cloudtrail-findings-container', 'No Security Hub findings for CloudTrail were found.');
    
    const flowContainer = document.getElementById('ct-trailguard-content');
    flowContainer.innerHTML = renderCloudtrailFlowDiagram(trailguard_findings);

    const lookupContainer = document.getElementById('ct-lookup-content');
    lookupContainer.innerHTML = renderCloudtrailLookUpView(allRegions);

    const lookupBtn = lookupContainer.querySelector('#ct-run-lookup-btn');
    if(lookupBtn) lookupBtn.addEventListener('click', runCloudtrailLookupAnalysis);

    const tabsNav = container.querySelector('#cloudtrail-tabs'); 
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.cloudtrail-tab-content'));
};


// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const renderCloudtrailFlowDiagram = (trailFlows) => {
    if (!trailFlows || trailFlows.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No CloudTrail configurations were found to display a data flow.</p></div>';
    }

    let diagramHtml = '<div class="space-y-8">';

    trailFlows.forEach(trail => {
        diagramHtml += `
        <div class="bg-white border border-gray-200 rounded-xl shadow-md">
            <div class="bg-gray-50 p-3 border-b border-gray-200 rounded-t-xl">
                <h3 class="text-lg font-bold text-[#204071]">${trail.TrailName}</h3>
                <p class="text-sm text-gray-500 font-mono">${trail.Region} | ${trail.TrailArn}</p>
            </div>
            <div class="p-4 grid grid-cols-1 lg:grid-cols-2 gap-4">
        `;

        if (trail.S3Destination) {
            const s3 = trail.S3Destination;
            diagramHtml += `
            <div class="bg-slate-50 border border-blue-200 rounded-lg p-3 flex flex-col">
                <div class="border-b border-blue-200 pb-2 mb-3">
                    <p class="font-bold text-sm text-blue-800">${ICONS.S3} S3 Bucket: ${s3.BucketName}</p>
                </div>
                <div class="space-y-2 flex-grow">
            `;
            if (s3.Notifications && s3.Notifications.length > 0) {
                s3.Notifications.forEach(notif => {
                    const icon = ICONS[notif.Type] || '';
                    diagramHtml += `<div class="bg-blue-100 border border-blue-300 p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${notif.Target}">${icon}${notif.Type}: ${notif.Target.split(':').pop()}</p></div>`;
                });
            } else {
                diagramHtml += '<p class="text-center text-xs text-gray-400 py-4">No notifications configured</p>';
            }
            diagramHtml += `</div></div>`;
        }

        if (trail.CloudWatchDestination) {
            const cw = trail.CloudWatchDestination;
            diagramHtml += `
            <div class="bg-slate-50 border border-purple-200 rounded-lg p-3 flex flex-col">
                <div class="border-b border-purple-200 pb-2 mb-3">
                    <p class="font-bold text-sm text-purple-800">${ICONS.CloudWatch} CloudWatch Log Group: ${cw.LogGroupName}</p>
                </div>
                <div class="space-y-2 flex-grow">
            `;
            if (cw.Subscriptions && cw.Subscriptions.length > 0) {
                cw.Subscriptions.forEach(sub => {
                    const icon = ICONS[sub.Type] || '';
                    diagramHtml += `<div class="bg-purple-100 border border-purple-300 p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${sub.Target}">${icon}${sub.Type}: ${sub.Target.split(':').pop()}</p></div>`;
                });
            } else {
                diagramHtml += '<p class="text-center text-xs text-gray-400">No subscriptions found</p>';
            }
            
            if (cw.MetricFilters && cw.MetricFilters.length > 0) {
                 diagramHtml += '<hr class="my-2 border-purple-200">';
                 cw.MetricFilters.forEach(mf => {
                    diagramHtml += `<div class="bg-purple-100 border border-purple-300 p-2 rounded-md text-xs">
                                        <p class="font-semibold text-gray-800 truncate" title="${mf.FilterName}">${ICONS.MetricFilter}${mf.FilterName}</p>`;
                    if (mf.Alarms && mf.Alarms.length > 0) {
                        mf.Alarms.forEach(alarm => {
                            diagramHtml += `<p class="pl-5 text-gray-600 truncate" title="${alarm}">${ICONS.Alarm}${alarm}</p>`;
                        });
                    }
                    diagramHtml += `</div>`;
                 });
            }
            diagramHtml += `</div></div>`;
        }

        if (!trail.S3Destination && !trail.CloudWatchDestination) {
             diagramHtml += `<div class="lg:col-span-2 text-center text-sm text-gray-500 py-4">This trail has no configured destinations (S3 or CloudWatch).</div>`;
        }

        diagramHtml += `</div></div>`;
    });

    diagramHtml += '</div>';

    const footerHtml = `
        <div class="mt-8 text-center text-xs text-gray-400">
            <p>Data Flow visualization inspired by the concepts in 
                <a href="https://github.com/adanalvarez/TrailGuard" target="_blank" class="text-blue-400 hover:underline">adanalvarez/TrailGuard</a>.
            </p>
        </div>
    `;
    diagramHtml += footerHtml;

    return diagramHtml;
};

const createCloudtrailSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Total Trails</p></div><div class="flex justify-between items-end pt-4"><p id="ct-total-trails" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M7.05 11.885c0 1.415-.548 2.206-1.524 2.206C4.548 14.09 4 13.3 4 11.885c0-1.412.548-2.203 1.526-2.203.976 0 1.524.79 1.524 2.203m-1.524-1.612c-.542 0-.832.563-.832 1.612q0 .133.006.252l1.559-1.143c-.126-.474-.375-.72-.733-.72zm-.732 2.508c.126.472.372.718.732.718.54 0 .83-.563.83-1.614q0-.129-.006-.25zm6.061.624V14h-3v-.595h1.181V10.5h-.05l-1.136.747v-.688l1.19-.786h.69v3.633z"/><path d="M14 14V4.5L9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2M9.5 3A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Active Trails</p></div><div class="flex justify-between items-end pt-4"><p id="ct-active-trails" class="text-3xl font-bold text-green-600">--</p><div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M7.05 11.885c0 1.415-.548 2.206-1.524 2.206C4.548 14.09 4 13.3 4 11.885c0-1.412.548-2.203 1.526-2.203.976 0 1.524.79 1.524 2.203m-1.524-1.612c-.542 0-.832.563-.832 1.612q0 .133.006.252l1.559-1.143c-.126-.474-.375-.72-.733-.72zm-.732 2.508c.126.472.372.718.732.718.54 0 .83-.563.83-1.614q0-.129-.006-.25zm6.061.624V14h-3v-.595h1.181V10.5h-.05l-1.136.747v-.688l1.19-.786h.69v3.633z"/><path d="M14 14V4.5L9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2M9.5 3A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Inactive Trails</p></div><div class="flex justify-between items-end pt-4"><p id="ct-inactive-trails" class="text-3xl font-bold text-red-600">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"><path d="M7.05 11.885c0 1.415-.548 2.206-1.524 2.206C4.548 14.09 4 13.3 4 11.885c0-1.412.548-2.203 1.526-2.203.976 0 1.524.79 1.524 2.203m-1.524-1.612c-.542 0-.832.563-.832 1.612q0 .133.006.252l1.559-1.143c-.126-.474-.375-.72-.733-.72zm-.732 2.508c.126.472.372.718.732.718.54 0 .83-.563.83-1.614q0-.129-.006-.25zm6.061.624V14h-3v-.595h1.181V10.5h-.05l-1.136.747v-.688l1.19-.786h.69v3.633z"/><path d="M14 14V4.5L9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2M9.5 3A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Found Events</p></div><div class="flex justify-between items-end pt-4"><p id="ct-total-events" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"> <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/></svg></div></div></div>
    </div>`;

const updateCloudtrailSummaryCards = (trails, events) => {
    const activeTrails = trails.filter(t => t.IsLogging).length;
    const inactiveTrails = trails.length - activeTrails;
    document.getElementById('ct-total-trails').textContent = trails.length;
    document.getElementById('ct-active-trails').textContent = activeTrails;
    document.getElementById('ct-inactive-trails').textContent = inactiveTrails;
    document.getElementById('ct-total-events').textContent = events.length;
};

const createCloudtrailSecurityHubHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (CloudTrail)</h3><div id="sh-cloudtrail-findings-container" class="overflow-x-auto"></div></div>`;

const renderCloudtrailTrailsView = (trails) => {
    if (!trails || trails.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No CloudTrail trails were found in the account.</p></div>';
    let summaryTable = '<h3 class="font-bold text-lg mb-4 text-[#204071]">Trails Summary</h3><div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto mb-8"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' + '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>' + '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Home Region</th>' + '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Multi-Region</th>' + '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Logging Status</th>' + '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    trails.forEach(t => {
        const loggingStatus = t.IsLogging ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Enabled</span>` : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Stopped</span>`;
        summaryTable += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 align-top whitespace-nowrap text-sm font-medium text-gray-800">${t.Name}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${t.HomeRegion}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${t.IsMultiRegionTrail ? 'YES' : 'NO'}</td><td class="px-4 py-4 align-top whitespace-nowrap text-sm">${loggingStatus}</td></tr>`;
    });
    summaryTable += '</tbody></table></div>';
    let detailsHtml = '<h3 class="font-bold text-lg mb-4 text-[#204071]">Trail configuration details</h3><div class="space-y-6">';
    trails.forEach(t => {
        const validationBadge = t.LogFileValidationEnabled ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Enabled</span>` : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Disabled</span>`;
        const kmsBadge = t.KmsKeyId ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">YES</span>` : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">NO</span>`;
        detailsHtml += `<div class="bg-white p-4 rounded-xl shadow-sm border border-gray-100"><h4 class="font-semibold text-md text-[#204071] mb-3 pb-2 border-b">${t.Name}</h4><ul class="space-y-2 text-sm"><li class="flex justify-between"><span class="font-medium text-gray-600">Integrity Validation:</span><span>${validationBadge}</span></li><li class="flex justify-between"><span class="font-medium text-gray-600">KMS Encryption:</span><span>${kmsBadge}</span></li><li class="flex justify-between items-center"><span class="font-medium text-gray-600">Bucket S3:</span><span class="font-mono text-gray-800">${t.S3BucketName || '-'}</span></li><li class="flex justify-between items-center"><span class="font-medium text-gray-600">CloudWatch Log Group:</span><span class="font-mono text-xs text-gray-800">${t.CloudWatchLogsLogGroupArn ? t.CloudWatchLogsLogGroupArn.split(':log-group:')[1] : '-'}</span></li></ul></div>`;
    });
    detailsHtml += '</div>';
    return summaryTable + detailsHtml;
};

const renderCloudtrailEventsTable = (events) => {
    if (!events || events.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No events of interest were found in the last 7 days.</p></div>';
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' + '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>' + '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Event Name</th>' + '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">User</th>' + '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' + '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source IP</th>' + '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    events.forEach(e => {
        const eventDate = new Date(e.EventTime).toLocaleString();
        table += `<tr class="hover:bg-gray-50"> <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${eventDate}</td> <td class="px-4 py-4 align-top whitespace-nowrap text-sm font-medium text-gray-800">${e.EventName}</td> <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${e.Username}</td> <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${e.EventRegion}</td> <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600 font-mono">${e.SourceIPAddress}</td> </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderCloudtrailLookUpView = (allRegions) => {
    const regionOptions = allRegions.map(r => `<option value="${r}">${r}</option>`).join('');

    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(endDate.getDate() - 7);

    const formatDate = (date) => {
        let d = date.getDate().toString().padStart(2, '0');
        let m = (date.getMonth() + 1).toString().padStart(2, '0');
        let y = date.getFullYear();
        return `${d}-${m}-${y}`;
    }

    return `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-4 text-[#204071]">Cloudtrail event searcher</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4 items-end">
                <div>
                    <label for="ct-event-name" class="block text-sm font-medium text-gray-700 mb-1">Event Name</label>
                    <input type="text" id="ct-event-name" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5" placeholder="E.g.: ConsoleLogin">
                </div>
                <div>
                    <label for="ct-start-date" class="block text-sm font-medium text-gray-700 mb-1">From</label>
                    <input type="text" id="ct-start-date" value="${formatDate(startDate)}" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5" placeholder="dd-mm-yyyy">
                </div>
                <div>
                    <label for="ct-end-date" class="block text-sm font-medium text-gray-700 mb-1">To</label>
                    <input type="text" id="ct-end-date" value="${formatDate(endDate)}" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5" placeholder="dd-mm-yyyy">
                </div>
                 <div>
                    <label for="ct-lookup-region" class="block text-sm font-medium text-gray-700 mb-1">Region</label>
                    <select id="ct-lookup-region" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5">
                        <option value="">Select a region</option>
                        ${regionOptions}
                    </select>
                </div>
            </div>
            <button id="ct-run-lookup-btn" class="bg-[#204071] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition flex items-center justify-center space-x-2">
                <span id="ct-lookup-btn-text">Search Event</span>
                <div id="ct-lookup-spinner" class="spinner hidden"></div>
            </button>
        </div>
        <div id="ct-lookup-results-container" class="mt-6"></div>
    `;
};

const runCloudtrailLookupAnalysis = async () => {
    log('Starting CloudTrail log search...', 'info');
    const accessKeyInput = document.getElementById("access-key-input");
    const secretKeyInput = document.getElementById("secret-key-input");
    const sessionTokenInput = document.getElementById("session-token-input");
    const eventName = document.getElementById('ct-event-name').value.trim();
    const startDate = document.getElementById('ct-start-date').value.trim();
    const endDate = document.getElementById('ct-end-date').value.trim();
    const region = document.getElementById('ct-lookup-region').value;
    const resultsContainer = document.getElementById('ct-lookup-results-container');
    resultsContainer.innerHTML = '';

    if (!startDate || !endDate || !region) {
        const msg = 'The date and region fields are required.';
        log(msg, 'error');
        resultsContainer.innerHTML = `<p class="text-red-600 font-medium">Error: ${msg}</p>`;
        return;
    }

    const runBtn = document.getElementById('ct-run-lookup-btn');
    const btnText = document.getElementById('ct-lookup-btn-text');
    const spinner = document.getElementById('ct-lookup-spinner');
    
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Searching...';

    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
        event_name: eventName,
        start_date: startDate,
        end_date: endDate,
        region: region
    };

    try {
        const response = await fetch('http://127.0.0.1:5001/api/run-cloudtrail-lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Unknown server error.');
        }
        
        window.lastCloudtrailLookupResults = data.results.events; 
        log(`Search complete. Found ${window.lastCloudtrailLookupResults.length} events.`, 'success');
        resultsContainer.innerHTML = renderCloudtrailLookupResult(window.lastCloudtrailLookupResults);

    } catch(e) {
        log(`Error in log search: ${e.message}`, 'error');
        resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Search Events';
    }
};        

const renderCloudtrailLookupResult = (events) => {
    if (!events) return '';
    if (events.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No events matching the search criteria were found.</p></div>';
    }
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table id="cloudtrail-lookup-table" class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Event Name</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">User</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source IP</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    events.forEach(e => {
        const eventDate = new Date(e.EventTime).toLocaleString();
        table += `<tr id="event-row-${e.EventId}" class="hover:bg-blue-50 cursor-pointer" onclick="showCloudtrailEventDetails('${e.EventId}')">
                    <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${eventDate}</td>
                    <td class="px-4 py-4 align-top whitespace-nowrap text-sm font-medium text-gray-800">${e.EventName}</td>
                    <td class="px-4 py-4 align-top text-sm text-gray-600 break-words">${e.Username}</td>
                    <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${e.EventRegion}</td>
                    <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600 font-mono">${e.SourceIPAddress}</td>
                  </tr>`;
    });
    table += '</tbody></table></div>';

    const detailContainer = '<div id="ct-event-detail-container" class="mt-6"></div>';
    return table + detailContainer;
};
    
export const showCloudtrailEventDetails = (eventId) => {
    if (!window.lastCloudtrailLookupResults) return;

    const eventData = window.lastCloudtrailLookupResults.find(e => e.EventId === eventId);
    if (!eventData) {
        log(`No details were found for event ${eventId}`, 'error');
        return;
    }

    const detailContainer = document.getElementById('ct-event-detail-container');
    const table = document.getElementById('cloudtrail-lookup-table');

    if (table) {
        table.querySelectorAll('tr.bg-blue-100').forEach(row => {
            row.classList.remove('bg-blue-100');
            row.classList.add('hover:bg-blue-50');
        });
    }

    const currentRow = document.getElementById(`event-row-${eventId}`);
    if (currentRow) {
        currentRow.classList.add('bg-blue-100');
        currentRow.classList.remove('hover:bg-blue-50');
    }
    
    try {
        const formattedJson = JSON.stringify(JSON.parse(eventData.CloudTrailEvent), null, 2);
        detailContainer.innerHTML = `
            <h3 class="text-xl font-bold text-[#204071] mb-4">Event Detail: ${eventId}</h3>
            <pre class="bg-[#204071] text-white p-4 rounded-lg text-xs font-mono overflow-x-auto">${formattedJson}</pre>
        `;
    } catch (e) {
        log('Error al parsear el JSON del evento.', 'error');
        detailContainer.innerHTML = `<p class="text-red-500">The event details could not be displayed.</p>`;
    }
};