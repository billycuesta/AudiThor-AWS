/**
 * 16_playground.js
 * Contains all logic for building and rendering the Playground view with interactive tools.
 */

// --- IMPORTS ---
import { handleTabClick, log } from '../utils.js';


// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildPlaygroundView = () => {
    const container = document.getElementById('playground-view');
    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Playground</h2>
                <p class="text-sm text-gray-500">Interactive Analysis Tools.</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="playground-tabs">
                <a href="#" data-tab="pg-tracer-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Traceroute</a>
                <a href="#" data-tab="pg-sslscan-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">SSL Scan</a>
            </nav>
        </div>
        <div id="pg-tracer-content" class="playground-tab-content">
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <h3 class="font-bold text-lg mb-4 text-[#204071]">Connectivity Analyzer Between Resources</h3>
                <p class="text-sm text-gray-600 mb-4">Enter the source and destination instance ARNs (you can copy them from the Compute -> EC2 tab) to verify if a network path is allowed between them.</p>
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label for="pg-source-arn" class="block text-sm font-medium text-gray-700 mb-1">Source ARN</label>
                        <input type="text" id="pg-source-arn" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="arn:aws:ec2:region:account:instance/i-...">
                    </div>
                    <div>
                        <label for="pg-target-arn" class="block text-sm font-medium text-gray-700 mb-1">Destination ARN</label>
                        <input type="text" id="pg-target-arn" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="arn:aws:ec2:region:account:instance/i-...">
                    </div>
                </div>
                <button id="pg-run-analysis-btn" class="bg-[#204071] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition flex items-center justify-center space-x-2">
                    <span id="pg-button-text">Analyze Path</span>
                    <div id="pg-loading-spinner" class="spinner hidden"></div>
                </button>
            </div>
            <div id="playground-results-container" class="mt-6"></div>
        </div>
        <div id="pg-sslscan-content" class="playground-tab-content hidden">
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <h3 class="font-bold text-lg mb-4 text-[#204071]">SSL/TLS Configuration Scanner</h3>
                <p class="text-sm text-gray-600 mb-4">Enter one or more comma-separated domains/IPs to analyze their configuration.</p>
                <div>
                    <label for="pg-sslscan-target" class="block text-sm font-medium text-gray-700 mb-1">Domain(s) or IP(s)</label>
                    <input type="text" id="pg-sslscan-target" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="e.g.: google.com, github.com, 1.1.1.1">
                </div>
                <button id="pg-run-sslscan-btn" class="bg-[#204071] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition flex items-center justify-center space-x-2 mt-4">
                    <span id="pg-sslscan-btn-text">Scan SSL/TLS</span>
                    <div id="pg-sslscan-spinner" class="spinner hidden"></div>
                </button>
            </div>
            <div id="sslscan-results-container" class="mt-6"></div>
        </div>
    `;

    const tabsNav = document.getElementById('playground-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.playground-tab-content'));
    
    const runAnalysisBtn = document.getElementById('pg-run-analysis-btn');
    if (runAnalysisBtn) runAnalysisBtn.addEventListener('click', runPlaygroundAnalysis);

    const runSslScanBtn = document.getElementById('pg-run-sslscan-btn');
    if (runSslScanBtn) runSslScanBtn.addEventListener('click', runSslScan);

    if (window.playgroundApiData?.results) {
        renderPlaygroundResults();
    }
    if (window.playgroundApiData?.sslscan) {
        renderSslScanResults(window.playgroundApiData.sslscan);
    }
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const runPlaygroundAnalysis = async () => {
    log('Starting network path analysis…', 'info');
    const sourceArn = document.getElementById('pg-source-arn').value.trim();
    const targetArn = document.getElementById('pg-target-arn').value.trim();
    const resultsContainer = document.getElementById('playground-results-container');
    resultsContainer.innerHTML = '';

    if (!sourceArn || !targetArn) {
        log('Source and destination ARNs are required.', 'error');
        resultsContainer.innerHTML = '<p class="text-red-600 font-medium">Error: Please enter both ARNs.</p>';
        return;
    }

    const runBtn = document.getElementById('pg-run-analysis-btn');
    const btnText = document.getElementById('pg-button-text');
    const spinner = document.getElementById('pg-loading-spinner');
    
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Analyzing...';
    
    // These need to be accessed from the global scope for credentials
    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');

    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
        source_arn: sourceArn,
        target_arn: targetArn
    };

    try {
        const response = await fetch('http://127.0.0.1:5001/api/run-playground-audit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        window.playgroundApiData = await response.json();
        
        if (!response.ok) {
            throw new Error(window.playgroundApiData.error || 'Unknown server error.');
        }

        log('Path analysis completed.', 'success');
        renderPlaygroundResults();

    } catch(e) {
        log(`Path analysis error: ${e.message}`, 'error');
        resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Analyze Path';
    }
};

const renderPlaygroundResults = () => {
    if (!window.playgroundApiData?.results) return;
    const container = document.getElementById('playground-results-container');
    const { status, reason, tables, detail_tables } = window.playgroundApiData.results;

    let resultHtml = '';
    if (status === 'REACHABLE') {
        resultHtml = `
            <div class="bg-green-50 text-green-800 p-4 rounded-lg">
                <h4 class="text-lg font-bold flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 mr-2" viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>
                    Status: REACHABLE
                </h4>
            </div>
        `;
        if(tables && tables.length > 0) {
            tables.forEach(table => {
                resultHtml += `<pre class="bg-[#204071] text-white p-4 rounded-lg text-xs font-mono overflow-x-auto mt-4">${table}</pre>`;
            });
        }
        
        if (detail_tables && Object.keys(detail_tables).length > 0) {
            resultHtml += '<h3 class="text-xl font-bold text-[#204071] mt-8 mb-4 border-b pb-2">Details of Involved Resources</h3>';
            for (const resourceId in detail_tables) {
                resultHtml += `<div class="mt-4"><pre class="bg-gray-800 text-gray-200 p-4 rounded-lg text-xs font-mono overflow-x-auto">${detail_tables[resourceId]}</pre></div>`;
            }
        }

    } else { // UNREACHABLE
        resultHtml = `
            <div class="bg-red-50 text-red-800 p-4 rounded-lg">
                <h4 class="text-lg font-bold flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 mr-2" viewBox="0 0 16 16"><path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/></svg>
                    Status: UNREACHABLE
                </h4>
                <p class="mt-2 font-mono text-sm"><b>Reason:</b> ${reason}</p>
            </div>
        `;
    }
    container.innerHTML = resultHtml;
};

const renderSslScanResults = (results) => {
    const resultsContainer = document.getElementById('sslscan-results-container');
    if (!results || results.length === 0) {
        resultsContainer.innerHTML = '';
        return;
    }

    let resultsHtml = '';
    results.forEach(result => {
        let resultOutput = '';
        if (result.error) {
            resultOutput = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${result.error}</p></div>`;
        } else if (result.output && result.output.trim() !== '') {
            resultOutput = `<pre class="bg-gray-900 text-white p-4 rounded-lg text-xs font-mono overflow-x-auto">${result.output}</pre>`;
        } else {
            resultOutput = `<div class="bg-yellow-50 text-yellow-700 p-4 rounded-lg"><h4 class="font-bold">Warning</h4><p>The scan finished without returning results for this target.</p></div>`;
        }
        
        resultsHtml += `
            <div class="mb-6">
                <h4 class="font-bold text-lg mb-2 text-[#204071]">Result for: ${result.target}</h4>
                ${resultOutput}
            </div>
        `;
    });
    resultsContainer.innerHTML = resultsHtml;
};

const runSslScan = async () => {
    const targetInput = document.getElementById('pg-sslscan-target');
    const resultsContainer = document.getElementById('sslscan-results-container');
    const runBtn = document.getElementById('pg-run-sslscan-btn');
    const btnText = document.getElementById('pg-sslscan-btn-text');
    const spinner = document.getElementById('pg-sslscan-spinner');
    const target = targetInput.value.trim();
    
    if (!target) {
        resultsContainer.innerHTML = '<p class="text-red-600 font-medium">Please enter one or more comma-separated domains/IPs.</p>';
        return;
    }

    log(`Starting sslscan for: ${target}...`, 'info');
    resultsContainer.innerHTML = '';
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Scanning...';

    try {
        const response = await fetch('http://127.0.0.1:5001/api/run-sslscan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target })
        });
        const data = await response.json();
        if (!response.ok && data.error) {
            throw new Error(data.error);
        }
        if (!window.playgroundApiData) window.playgroundApiData = {};
        window.playgroundApiData.sslscan = data.results;
        renderSslScanResults(data.results);
        log(`sslscan completed for: ${target}.`, 'success');
    } catch (e) {
        log(`sslscan error: ${e.message}`, 'error');
        resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Scan SSL/TLS';
    }
};