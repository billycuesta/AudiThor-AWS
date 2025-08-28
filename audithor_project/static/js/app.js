/**
 * app.js
 * Fichero principal (el "cerebro") de la lógica de la aplicación AudiThor.
 */

// 1. IMPORTACIONES
import { 
    log, 
    copyToClipboard, 
    handleTabClick, 
    createStatusBadge, 
    createAlarmStateBadge, 
    setupModalControls, 
    setupPagination, 
    renderSecurityHubFindings 
} from '/static/js/utils.js';

import { 
    buildIamView, 
    updateSecurityHubDashboard, 
    openModalWithSsoDetails, 
    openModalWithAccessKeyDetails, 
    openModalWithUserGroups 
} from '/static/js/views/01_iam.js';
import { buildExposureView } from '/static/js/views/02_exposure.js';
import { buildGuarddutyView } from '/static/js/views/03_guardduty.js';
import { buildEcrView } from '/static/js/views/04_ecr.js';
import { buildWafView } from '/static/js/views/05_waf.js';
import { buildCloudtrailView } from '/static/js/views/06_cloudtrail.js';
import { buildCloudwatchView } from '/static/js/views/07_cloudwatch.js';
import { buildInspectorView } from '/static/js/views/08_inspector.js';
import { buildAcmView } from '/static/js/views/09_acm.js';
import { buildComputeView } from '/static/js/views/10_compute.js';
import { buildDatabasesView } from '/static/js/views/11_databases.js';
import { buildKmsView } from '/static/js/views/12_kms.js';
import { buildNetworkPoliciesView } from '/static/js/views/13_network_policies.js';
import { buildConnectivityView } from '/static/js/views/14_connectivity.js';
import { buildConfigSHView } from '/static/js/views/15_config_sh.js';
import { buildPlaygroundView } from '/static/js/views/16_playground.js';
import { buildHealthyStatusView, buildGeminiReportView } from '/static/js/views/17_healthy_status.js';


// Importar las funciones que se usarán en onclick
import { openModalWithTlsDetails } from '/static/js/views/02_exposure.js';
import { openModalWithEcrPolicy } from '/static/js/views/04_ecr.js';
import { showCloudtrailEventDetails } from '/static/js/views/06_cloudtrail.js';
import { toggleAlarmDetails } from '/static/js/views/07_cloudwatch.js';
import { openModalWithEc2Tags, openModalWithLambdaTags, openModalWithLambdaRole } from '/static/js/views/10_compute.js';
import { openModalWithKmsPolicy } from '/static/js/views/12_kms.js';
import { showComplianceDetails } from '/static/js/views/15_config_sh.js';

// Importar iconos
import { SIDEBAR_ICONS } from '/static/js/icons.js';

// 2. ESTADO GLOBAL
window.iamApiData = null;
window.federationApiData = null;
window.accessAnalyzerApiData = null;
window.securityHubApiData = null;
window.exposureApiData = null;
window.guarddutyApiData = null;
window.wafApiData = null;
window.cloudtrailApiData = null;
window.cloudwatchApiData = null;
window.inspectorApiData = null;
window.acmApiData = null;
window.computeApiData = null;
window.ecrApiData = null;
window.databasesApiData = null;
window.networkPoliciesApiData = null;
window.connectivityApiData = null;
window.playgroundApiData = null;
window.configSHApiData = null;
window.configSHStatusApiData = null;
window.kmsApiData = null;
window.allAvailableRegions = [];
window.lastCloudtrailLookupResults = [];
window.lastHealthyStatusFindings = [];

// 3. SELECTORES
let views, mainNavLinks, runAnalysisBtn, accessKeyInput, secretKeyInput, sessionTokenInput, loadingSpinner, buttonText, errorMessageDiv, logContainer, clearLogBtn, toggleLogBtn, logPanel;

// 4. LÓGICA PRINCIPAL
const loadSidebarIcons = () => {
    const sidebarNav = document.getElementById('sidebar-nav');
    if (!sidebarNav) return;

    const navLinks = sidebarNav.querySelectorAll('a[data-view]');
    navLinks.forEach(link => {
        const viewName = link.dataset.view;
        const iconKey = viewName === 'healthy-status' ? 'healthy-status' : viewName;
        
        if (SIDEBAR_ICONS[iconKey]) {
            const span = link.querySelector('span');
            if (span) {
                const currentText = span.textContent.trim();
                
                // Crear nueva estructura: icono + texto en contenedores separados
                span.innerHTML = '';
                
                // Crear contenedor para el icono
                const iconDiv = document.createElement('div');
                iconDiv.innerHTML = SIDEBAR_ICONS[iconKey];
                iconDiv.className = 'flex-shrink-0';
                
                // Crear contenedor para el texto
                const textDiv = document.createElement('div');
                textDiv.textContent = currentText;
                textDiv.className = 'ml-3';
                
                // Añadir ambos al span
                span.appendChild(iconDiv);
                span.appendChild(textDiv);
                
                // Asegurar que el span tenga flex
                span.className = 'flex items-center';
            }
        }
    });
};

const handleMainNavClick = (e) => {
    e.preventDefault();
    const link = e.target.closest('a.main-nav-link');
    if (!link) return;
    
    const targetView = link.dataset.view;
    if (!targetView) return;
    
    // Actualizar navegación activa
    mainNavLinks.forEach(l => {
        l.classList.remove('bg-[#eb3496]');
        l.classList.add('hover:bg-[#1a335a]');
    });
    link.classList.add('bg-[#eb3496]');
    link.classList.remove('hover:bg-[#1a335a]');
    
    // Mostrar vista correspondiente
    views.forEach(v => v.classList.add('hidden'));
    const targetViewElement = document.getElementById(`${targetView}-view`);
    if (targetViewElement) {
        targetViewElement.classList.remove('hidden');
    }
};

const runAnalysisFromInputs = async () => {
    // Resetear estado
    window.iamApiData = null; window.securityHubApiData = null; window.exposureApiData = null; window.guarddutyApiData = null; window.wafApiData = null; window.cloudtrailApiData = null; window.cloudwatchApiData = null; window.inspectorApiData = null; window.acmApiData = null; window.computeApiData = null; window.databasesApiData = null; window.networkPoliciesApiData = null; window.connectivityApiData = null; window.playgroundApiData = null; window.allAvailableRegions = []; window.lastCloudtrailLookupResults = []; window.federationApiData = null; window.configSHApiData = null; window.configSHStatusApiData = null; window.kmsApiData = null; window.ecrApiData = null;
    document.querySelectorAll('.view').forEach(v => v.innerHTML = '');
    document.getElementById('iam-view').innerHTML = createInitialEmptyState();
    
    log('Starting full analysis...', 'info');
    const accessKey = accessKeyInput.value.trim(); 
    const secretKey = secretKeyInput.value.trim(); 
    const sessionToken = sessionTokenInput.value.trim();
    if (!accessKey || !secretKey) { 
        const msg = 'Please enter the Access Key ID and Secret Access Key.'; 
        errorMessageDiv.textContent = msg; 
        errorMessageDiv.classList.remove('hidden'); 
        log(msg, 'error'); 
        return; 
    }
    const payload = { access_key: accessKey, secret_key: secretKey };
    if (sessionToken) { payload.session_token = sessionToken; }
    
    runAnalysisBtn.disabled = true; 
    loadingSpinner.classList.remove('hidden'); 
    buttonText.textContent = 'Scanning...'; 
    errorMessageDiv.classList.add('hidden');
    
    try {
        log('Calling all AWS APIs...', 'info');
        const apiCalls = {
            iam: fetch('http://127.0.0.1:5001/api/run-iam-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            accessAnalyzer: fetch('http://127.0.0.1:5001/api/run-access-analyzer-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            securityhub: fetch('http://127.0.0.1:5001/api/run-securityhub-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            exposure: fetch('http://127.0.0.1:5001/api/run-exposure-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            guardduty: fetch('http://127.0.0.1:5001/api/run-guardduty-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            waf: fetch('http://127.0.0.1:5001/api/run-waf-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            cloudtrail: fetch('http://127.0.0.1:5001/api/run-cloudtrail-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            cloudwatch: fetch('http://127.0.0.1:5001/api/run-cloudwatch-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            inspector: fetch('http://127.0.0.1:5001/api/run-inspector-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            acm: fetch('http://127.0.0.1:5001/api/run-acm-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            compute: fetch('http://127.0.0.1:5001/api/run-compute-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            ecr: fetch('http://127.0.0.1:5001/api/run-ecr-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            databases: fetch('http://127.0.0.1:5001/api/run-databases-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            network_policies: fetch('http://127.0.0.1:5001/api/run-network-policies-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            federation: fetch('http://127.0.0.1:5001/api/run-federation-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            config_sh_status: fetch('http://127.0.0.1:5001/api/run-config-sh-status-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            kms: fetch('http://127.0.0.1:5001/api/run-kms-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
            connectivity: fetch('http://127.0.0.1:5001/api/run-connectivity-audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
        };
        
        const promises = Object.entries(apiCalls).map(async ([key, promise]) => {
            try { 
                const response = await promise; 
                if (!response.ok) { 
                    const errorData = await response.json(); 
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`); 
                } 
                return [key, await response.json()]; 
            } catch (error) { 
                log(`Error for API '${key}': ${error.message}`, 'error'); 
                return [key, null]; 
            }
        });

        const resolvedPromises = await Promise.all(promises);
        const results = Object.fromEntries(resolvedPromises);

        window.iamApiData = results.iam; 
        window.accessAnalyzerApiData = results.accessAnalyzer; 
        window.securityHubApiData = results.securityhub; 
        window.exposureApiData = results.exposure; 
        window.guarddutyApiData = results.guardduty; 
        window.wafApiData = results.waf; 
        window.cloudtrailApiData = results.cloudtrail; 
        window.cloudwatchApiData = results.cloudwatch; 
        window.inspectorApiData = results.inspector; 
        window.acmApiData = results.acm; 
        window.computeApiData = results.compute;
        window.ecrApiData = results.ecr;
        window.databasesApiData = results.databases; 
        window.networkPoliciesApiData = results.network_policies; 
        window.federationApiData = results.federation;
        window.configSHStatusApiData = results.config_sh_status; 
        window.kmsApiData = results.kms; 
        window.connectivityApiData = results.connectivity;
        
        if (!window.iamApiData || !window.networkPoliciesApiData) { 
            throw new Error("One or more critical API calls failed. Cannot continue."); 
        }
        
        window.allAvailableRegions = window.networkPoliciesApiData?.results?.all_regions || [];
        log('All data has been received.', 'success');
        
        buildAndRenderAllViews();
        await runAndDisplayHealthyStatus();

        // INICIA LA CORRECCIÓN
        log('Activating the Identity & Access view post-scan...', 'info');

        // Ocultar todas las vistas
        document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
        
        // Mostrar la vista de IAM
        const iamViewToShow = document.getElementById('iam-view');
        if (iamViewToShow) {
            iamViewToShow.classList.remove('hidden');
        }

        // Actualizar el estilo "activo" en la barra lateral
        const sidebarLinks = document.querySelectorAll('#sidebar-nav a.main-nav-link');
        sidebarLinks.forEach(link => {
            link.classList.remove('bg-[#eb3496]');
            link.classList.add('hover:bg-[#1a335a]');
        });
        const activeIamLink = document.querySelector('#sidebar-nav a[data-view="iam"]');
        if (activeIamLink) {
            activeIamLink.classList.add('bg-[#eb3496]');
            activeIamLink.classList.remove('hover:bg-[#1a335a]');
        }
        // TERMINA LA CORRECCIÓN
    } catch (error) {
        const errorMsg = `Error: ${error.message || 'An unknown error occurred.'}`;
        console.error('Detailed Error:', error);
        errorMessageDiv.textContent = errorMsg;
        errorMessageDiv.classList.remove('hidden');
        log(`${errorMsg}`, 'error');
    } finally {
        runAnalysisBtn.disabled = false;
        loadingSpinner.classList.add('hidden');
        buttonText.textContent = 'Scan Account';
    }
};


const buildAndRenderAllViews = () => {
    try {
        log('Rendering all views…', 'info');
        buildHealthyStatusView();
        buildGeminiReportView();
        buildIamView();
        buildExposureView();
        buildGuarddutyView();
        buildWafView();
        buildCloudtrailView();
        buildCloudwatchView();
        buildInspectorView();
        buildAcmView();
        buildComputeView();
        buildEcrView();
        buildDatabasesView();
        buildNetworkPoliciesView();
        buildConfigSHView();
        buildPlaygroundView();
        buildKmsView();
        buildConnectivityView();
        log('Views rendered.', 'success');
    } catch (e) { log(`Error rendering: ${e.message}`, 'error'); console.error(e); }
};

const createInitialEmptyState = () => `<div class="text-center py-16 bg-white rounded-lg"><svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" /></svg><h3 class="mt-2 text-lg font-medium text-[#204071]">Welcome to AudiThor</h3><p class="mt-1 text-sm text-gray-500">Enter your credentials and click "Scan Account"</p></div>`;

const exportResultsToJson = () => {
    if (!window.iamApiData) {
        alert("Aviso: Debes ejecutar un análisis primero antes de exportar los resultados.");
        return;
    }

    let scanType = "fast";
    if (window.configSHApiData || (window.inspectorApiData && window.inspectorApiData.results.findings && window.inspectorApiData.results.findings.length > 0)) {
        scanType = "deep";
    }
    
    const accountId = window.iamApiData.metadata.accountId;
    const accountAlias = window.federationApiData?.results?.iam_federation?.account_alias || "NoAlias";
    const timestamp = window.iamApiData.metadata.executionDate;

    const exportData = {
        metadata: {
            accountId: accountId,
            accountAlias: accountAlias,
            analysisTimestamp: timestamp,
            analysisType: scanType,
            exportTimestamp: new Date().toISOString()
        },
        results: {
            iam: window.iamApiData?.results || null,
            federation: window.federationApiData?.results || null,
            accessAnalyzer: window.accessAnalyzerApiData?.results || null,
            securityhub: window.securityHubApiData?.results || null,
            exposure: window.exposureApiData?.results || null,
            guardduty: window.guarddutyApiData?.results || null,
            waf: window.wafApiData?.results || null,
            cloudtrail: window.cloudtrailApiData?.results || null,
            cloudwatch: window.cloudwatchApiData?.results || null,
            inspector: window.inspectorApiData?.results || null,
            acm: window.acmApiData?.results || null,
            compute: window.computeApiData?.results || null,
            ecr: window.ecrApiData?.results || null,
            databases: window.databasesApiData?.results || null,
            networkPolicies: window.networkPoliciesApiData?.results || null,
            configAndSecurityHubStatus: window.configSHStatusApiData?.results || null,
            configAndSecurityHubDeepScan: window.configSHApiData?.results || null,
            kms: window.kmsApiData?.results || null, 
            playground: {
                traceroute: window.playgroundApiData?.results || null,
                sslscan: window.playgroundApiData?.sslscan || null
            },
            connectivity: window.connectivityApiData?.results || null
        }
    };
    
    const filename = `${accountId}_${accountAlias}_${scanType}.json`;
    const jsonString = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    log(`Results successfully exported to the file: ${filename}`, 'success');
};


const handleJsonImport = (event) => {
    const file = event.target.files[0];
    if (!file) {
        log('No file selected.', 'info');
        return;
    }

    log(`Loading file: ${file.name}...`, 'info');
    const reader = new FileReader();

    reader.onload = (e) => {
        try {
            const importedData = JSON.parse(e.target.result);

            if (!importedData.metadata || !importedData.results) {
                throw new Error("The JSON file does not have the expected structure. (metadata/results).");
            }

            log(`JSON file parsed successfully. Account: ${importedData.metadata.accountId}`, 'info');

            const results = importedData.results;
            const metadata = { accountId: importedData.metadata.accountId, executionDate: importedData.metadata.analysisTimestamp };

            // Asignar todos los datos globales
            window.iamApiData = results.iam ? { metadata: metadata, results: results.iam } : null;
            window.federationApiData = results.federation ? { metadata: metadata, results: results.federation } : null;
            window.accessAnalyzerApiData = results.accessAnalyzer ? { metadata: metadata, results: results.accessAnalyzer } : null;
            window.securityHubApiData = results.securityhub ? { metadata: metadata, results: results.securityhub } : null;
            window.exposureApiData = results.exposure ? { metadata: metadata, results: results.exposure } : null;
            window.guarddutyApiData = results.guardduty ? { metadata: metadata, results: results.guardduty } : null;
            window.wafApiData = results.waf ? { metadata: metadata, results: results.waf } : null;
            window.cloudtrailApiData = results.cloudtrail ? { metadata: metadata, results: results.cloudtrail } : null;
            window.cloudwatchApiData = results.cloudwatch ? { metadata: metadata, results: results.cloudwatch } : null;
            window.inspectorApiData = results.inspector ? { metadata: metadata, results: results.inspector } : null;
            window.acmApiData = results.acm ? { metadata: metadata, results: results.acm } : null;
            window.computeApiData = results.compute ? { metadata: metadata, results: results.compute } : null;
            window.ecrApiData = results.ecr ? { metadata: metadata, results: results.ecr } : null;
            window.databasesApiData = results.databases ? { metadata: metadata, results: results.databases } : null;
            window.networkPoliciesApiData = results.networkPolicies ? { metadata: metadata, results: results.networkPolicies } : null;
            window.configSHStatusApiData = results.configAndSecurityHubStatus ? { metadata: metadata, results: results.configAndSecurityHubStatus } : null;
            window.configSHApiData = results.configAndSecurityHubDeepScan ? { metadata: metadata, results: results.configAndSecurityHubDeepScan } : null;
            window.kmsApiData = results.kms ? { metadata: metadata, results: results.kms } : null;
            window.connectivityApiData = results.connectivity ? { metadata: metadata, results: results.connectivity } : null;
            
            const playgroundImportData = results.playground || {};
            window.playgroundApiData = {
                metadata: metadata,
                results: playgroundImportData.traceroute || null,
                sslscan: playgroundImportData.sslscan || null
            };

            window.allAvailableRegions = window.networkPoliciesApiData?.results?.all_regions || [];

            log('Data imported into the application state.', 'success');
            
            // 1. Construir el contenido de todas las vistas en segundo plano
            buildAndRenderAllViews();
            
            // 2. Ejecutar lógicas adicionales que puedan ser necesarias
            runAndDisplayHealthyStatus();

            // 3. (LA CORRECCIÓN FINAL) - Asegurarse de que se muestra la vista correcta
            log('Activating the Identity & Access view post-import...', 'info');

            // Ocultar todas las vistas
            document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
            
            // Mostrar la vista de IAM
            const iamViewToShow = document.getElementById('iam-view');
            if (iamViewToShow) {
                iamViewToShow.classList.remove('hidden');
            }

            // Actualizar el estilo "activo" en la barra lateral para que sea coherente
            const sidebarLinks = document.querySelectorAll('#sidebar-nav a.main-nav-link');
            sidebarLinks.forEach(link => {
                link.classList.remove('bg-[#eb3496]');
                link.classList.add('hover:bg-[#1a335a]');
            });
            const activeIamLink = document.querySelector('#sidebar-nav a[data-view="iam"]');
            if (activeIamLink) {
                activeIamLink.classList.add('bg-[#eb3496]');
                activeIamLink.classList.remove('hover:bg-[#1a335a]');
            }

        } catch (error) {
            log(`Error importing the JSON file: ${error.message}`, 'error');
            console.error(error);
            errorMessageDiv.textContent = 'Error: El fichero seleccionado no es un JSON válido o tiene un formato incorrecto.';
            errorMessageDiv.classList.remove('hidden');
        }
    };

    reader.onerror = () => {
        log('Error reading the file.', 'error');
        errorMessageDiv.textContent = 'Error: No se pudo leer el fichero seleccionado.';
        errorMessageDiv.classList.remove('hidden');
    };

    reader.readAsText(file);
    event.target.value = '';
};

const displayHealthyStatus = (selectedRegion) => {
    // Placeholder - necesitarías implementar esta función
    log('Displaying healthy status...', 'info');
};

const runAndDisplayHealthyStatus = async () => {
    if (!window.iamApiData) {
        log('No audit data available for healthy status analysis.', 'info');
        return;
    }

    log('Running healthy status analysis...', 'info');
    
    try {
        // Prepare audit data structure
        const auditData = {
            iam: window.iamApiData,
            federation: window.federationApiData,
            accessAnalyzer: window.accessAnalyzerApiData,
            securityhub: window.securityHubApiData,
            exposure: window.exposureApiData,
            guardduty: window.guarddutyApiData,
            waf: window.wafApiData,
            cloudtrail: window.cloudtrailApiData,
            cloudwatch: window.cloudwatchApiData,
            inspector: window.inspectorApiData,
            acm: window.acmApiData,
            compute: window.computeApiData,
            ecr: window.ecrApiData,
            databases: window.databasesApiData,
            networkPolicies: window.networkPoliciesApiData,
            configSH: window.configSHApiData,
            configSHStatus: window.configSHStatusApiData,
            kms: window.kmsApiData,
            connectivity: window.connectivityApiData
        };

        // Call the backend API to check rules
        const response = await fetch('http://127.0.0.1:5001/api/check-healthy-status-rules', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(auditData)
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const findings = await response.json();
        
        // Store findings globally
        window.lastHealthyStatusFindings = findings;
        
        log(`Healthy status analysis completed. Found ${findings.length} findings.`, 'success');
        
        // Import the functions dynamically to avoid circular imports
        const { renderHealthyStatusFindings, populateHealthyStatusFilter } = await import('/static/js/views/17_healthy_status.js');
        
        // Render the findings
        renderHealthyStatusFindings(findings);
        populateHealthyStatusFilter(findings);
        
        // Also populate the Gemini region filter
        populateGeminiRegionFilter(findings);
        
    } catch (error) {
        log(`Error in healthy status analysis: ${error.message}`, 'error');
        console.error('Healthy status error:', error);
    }
};

const populateHealthyStatusFilter = () => {
    // Placeholder - necesitarías implementar esta función
    log('Populating healthy status filters...', 'info');
};

const populateGeminiRegionFilter = (findings) => {
    const select = document.getElementById('gemini-region-filter');
    if (!select) return;

    const regions = new Set();
    regions.add('all');
    findings.forEach(finding => {
        finding.affected_resources.forEach(res => {
            if (res.region) {
                regions.add(res.region);
            }
        });
    });

    // Clear existing options except "All Regions"
    select.innerHTML = '<option value="all">All Regions</option>';
    
    const sortedRegions = Array.from(regions).sort();
    sortedRegions.forEach(region => {
        if (region !== 'all') {
            const option = document.createElement('option');
            option.value = region;
            option.textContent = region;
            select.appendChild(option);
        }
    });
};

// 5. PUNTO DE ENTRADA
document.addEventListener('DOMContentLoaded', () => {
    // Inicializar selectores
    views = document.querySelectorAll('.view');
    mainNavLinks = document.querySelectorAll('.main-nav-link');
    runAnalysisBtn = document.getElementById('run-analysis-button');
    accessKeyInput = document.getElementById('access-key-input');
    secretKeyInput = document.getElementById('secret-key-input');
    sessionTokenInput = document.getElementById('session-token-input');
    loadingSpinner = document.getElementById('loading-spinner');
    buttonText = document.getElementById('button-text');
    errorMessageDiv = document.getElementById('error-message');
    logContainer = document.getElementById('log-container');
    clearLogBtn = document.getElementById('clear-log-btn');
    toggleLogBtn = document.getElementById('toggle-log-btn');
    logPanel = document.getElementById('log-panel');

    // Cargar iconos de la barra lateral
    loadSidebarIcons();

    // Configurar navegación principal
    const sidebarNav = document.getElementById('sidebar-nav');
    if (sidebarNav) {
        sidebarNav.addEventListener('click', handleMainNavClick);
    }

    // Configurar botón de análisis
    if (runAnalysisBtn) {
        runAnalysisBtn.addEventListener('click', runAnalysisFromInputs);
    }

    // Configurar botones de importación/exportación
    const exportBtn = document.getElementById('export-results-button');
    const importBtn = document.getElementById('import-results-button');
    const fileInput = document.getElementById('json-file-input');

    if (exportBtn) {
        exportBtn.addEventListener('click', exportResultsToJson);
    }

    if (importBtn && fileInput) {
        importBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', handleJsonImport);
    }

    // Configurar controles del log
    if (clearLogBtn) {
        clearLogBtn.addEventListener('click', () => {
            if (logContainer) logContainer.innerHTML = '';
        });
    }

    if (toggleLogBtn && logPanel) {
        toggleLogBtn.addEventListener('click', () => {
            const isMinimized = logPanel.classList.contains('minimized');
            
            if (isMinimized) {
                // Show the full panel
                logPanel.classList.remove('minimized');
                toggleLogBtn.textContent = 'Minimize';
            } else {
                // Minimize the panel (slide down, keeping only 48px visible)
                logPanel.classList.add('minimized');
                toggleLogBtn.textContent = 'Show Log';
            }
        });
    }

    // Configurar modal
    setupModalControls();

    // Inicializar vistas vacías
    views.forEach(view => {
        if (view.id !== 'iam-view') {
            view.innerHTML = createInitialEmptyState();
        }
    });

    // Mostrar vista inicial (iam)
    const initialView = document.getElementById('iam-view');
    if (initialView) {
        initialView.classList.remove('hidden');
        buildIamView();
    }

    log('Application initialized successfully.', 'success');
});

// 6. EXPOSICIÓN DE FUNCIONES GLOBALES
window.openModalWithSsoDetails = openModalWithSsoDetails;
window.openModalWithAccessKeyDetails = openModalWithAccessKeyDetails;
window.openModalWithUserGroups = openModalWithUserGroups;
window.openModalWithEc2Tags = openModalWithEc2Tags;
window.openModalWithLambdaTags = openModalWithLambdaTags;
window.openModalWithTlsDetails = openModalWithTlsDetails;
window.toggleAlarmDetails = toggleAlarmDetails;
window.showCloudtrailEventDetails = showCloudtrailEventDetails;
window.openModalWithKmsPolicy = openModalWithKmsPolicy;
window.openModalWithLambdaRole = openModalWithLambdaRole;
window.openModalWithEcrPolicy = openModalWithEcrPolicy;
window.showComplianceDetails = showComplianceDetails;
window.copyToClipboard = copyToClipboard;