/**
 * 17_healthy_status.js
 * Contains all logic for building and rendering the Healthy Status / Executive Summary view.
 */

// --- IMPORTS ---
import { handleTabClick, log } from '../utils.js';

// Initialize global variable
if (!window.lastHealthyStatusFindings) {
    window.lastHealthyStatusFindings = [];
    
}

if (!window.reportCheckboxStates) {
    window.reportCheckboxStates = new Set(); // Guarda los índices de findings seleccionados
}

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildHealthyStatusView = () => {
    const container = document.getElementById('healthy-status-view');
    if (!container) return;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Healthy Status</h2>
                <p class="text-sm text-gray-500">Summary of Findings and Report Generation.</p>
            </div>
        </header>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex space-x-6" id="healthy-status-tabs">
                <a href="#" data-tab="hs-findings-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Findings</a>
                <a href="#" data-tab="hs-report-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Executive Summary AI</a>
                <a href="#" data-tab="hs-findings-report-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Generate Findings Report</a>
                <a href="#" data-tab="hs-inventory-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Scoped Inventory</a>
                <a href="#" data-tab="hs-notes-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Auditor's Notes</a>
            </nav>
        </div>
        <div id="healthy-status-tab-content-container">
            <div id="hs-findings-content" class="healthy-status-tab-content">
                <div class="bg-gradient-to-r from-white to-gray-50 p-6 rounded-2xl border border-gray-200 shadow-sm mb-6">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center space-x-2">
                            <svg class="w-5 h-5 text-[#eb3496]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293.707L3.293 7.707A1 1 0 013 7V4z"></path>
                            </svg>
                            <h3 class="text-lg font-bold text-gray-800">Filter Options</h3>
                        </div>
                        <div id="findings-count-display" class="bg-[#eb3496] text-white px-3 py-1 rounded-full text-sm font-semibold"></div>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-4">
                        <div class="group">
                            <label for="healthy-status-region-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-blue-500" viewBox="0 0 16 16">
                                    <path d="M12.166 8.94c-.524 1.062-1.234 2.12-1.96 3.07A32 32 0 0 1 8 14.58a32 32 0 0 1-2.206-2.57c-.726-.95-1.436-2.008-1.96-3.07C3.304 7.867 3 6.862 3 6a5 5 0 0 1 10 0c0 .862-.305 1.867-.834 2.94M8 16s6-5.686 6-10A6 6 0 0 0 2 6c0 4.314 6 10 6 10"/>
                                    <path d="M8 8a2 2 0 1 1 0-4 2 2 0 0 1 0 4m0 1a3 3 0 1 0 0-6 3 3 0 0 0 0 6"/>
                                </svg>
                                Region
                            </label>
                            <select id="healthy-status-region-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-blue-300">
                                <option value="all">All Regions</option>
                            </select>
                        </div>
                        
                        <div class="group">
                            <label for="healthy-status-severity-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-red-500" viewBox="0 0 16 16">
                                    <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1-.054-.06.18.18 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/>
                                    <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/>
                                </svg>
                                Severity
                            </label>
                            <select id="healthy-status-severity-filter" class="severity-select w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-red-300">
                                <option value="all">All Severities</option>
                                <option value="Crítico" data-color="critical">Critical</option>
                                <option value="Alto" data-color="high">High</option>
                                <option value="Medio" data-color="medium">Medium</option>
                                <option value="Bajo" data-color="low">Low</option>
                                <option value="Informativo" data-color="info">Info</option>
                            </select>
                        </div>
                        
                        <div class="group">
                            <label for="healthy-status-section-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-green-500" viewBox="0 0 16 16">
                                    <path d="M8.186 1.113a.5.5 0 0 0-.372 0L1.846 3.5 8 5.961 14.154 3.5zM15 4.239l-6.5 2.6v7.922l6.5-2.6V4.24zM7.5 14.762V6.838L1 4.239v7.923zM7.443.184a1.5 1.5 0 0 1 1.114 0l7.129 2.852A.5.5 0 0 1 16 3.5v8.662a1 1 0 0 1-.629.928l-7.185 2.874a.5.5 0 0 1-.372 0L.63 13.09a1 1 0 0 1-.63-.928V3.5a.5.5 0 0 1 .314-.464z"/>
                                </svg>
                                Section
                            </label>
                            <select id="healthy-status-section-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-green-300">
                                <option value="all">All Sections</option>
                            </select>
                        </div>
                        
                        <div class="group">
                            <label for="healthy-status-impact-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-purple-500" viewBox="0 0 16 16">
                                    <path d="M8 16c3.314 0 6-2 6-5.5 0-1.5-.5-4-2.5-6 .25 1.5-1.25 2-1.25 2C11 4 9 .5 6 0c.357 2 .5 4-2 6-1.25 1-2 2.729-2 4.5C2 14 4.686 16 8 16m0-1c-1.657 0-3-1-3-2.75 0-.75.25-2 1.25-3C6.125 10 7 10.5 7 10.5c-.375-1.25.5-3.25 2-3.5-.179 1-.25 2 1 3 .625.5 1 1.364 1 2.25C11 14 9.657 15 8 15"/>
                                </svg>
                                Impact Type
                            </label>
                            <select id="healthy-status-impact-filter" class="impact-select w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-purple-300">
                                <option value="all">All Impact Types</option>
                                <option value="compliance" data-color="compliance">Compliance Risk</option>
                                <option value="data_breach" data-color="data-breach">Data Breach Risk</option>
                                <option value="operational" data-color="operational">Operational Risk</option>
                                <option value="access_control" data-color="access-control">Access Control Risk</option>
                                <option value="monitoring" data-color="monitoring">Monitoring Gap</option>
                                <option value="encryption" data-color="encryption">Encryption Issue</option>
                            </select>
                        </div>
                    </div>
                    
                    <div id="active-filters-display" class="hidden mb-4">
                        <div class="flex flex-wrap items-center gap-2">
                            <span class="text-sm font-medium text-gray-600">Active filters:</span>
                            <div id="active-filters-container" class="flex flex-wrap gap-2"></div>
                        </div>
                    </div>
                    
                    <div class="flex justify-between items-center pt-4 border-t border-gray-200">
                        <button id="reset-filters-btn" class="inline-flex items-center px-4 py-2 text-sm font-medium text-[#eb3496] bg-pink-50 border border-pink-200 rounded-xl hover:bg-pink-100 hover:border-[#eb3496] transition-all duration-200 group">
                            <svg class="w-4 h-4 mr-2 group-hover:rotate-180 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                            </svg>
                            Reset All Filters
                        </button>
                        
                        <div class="flex items-center space-x-2 text-sm text-gray-600">
                            <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path>
                            </svg>
                            <span>Active filters will update results instantly</span>
                        </div>
                    </div>
                </div>

                <div id="healthy-status-container">
                    <div class="text-center py-16 bg-white rounded-lg">
                        <h3 class="mt-2 text-lg font-medium text-[#204071]">Waiting for analysis</h3>
                        <p class="mt-1 text-sm text-gray-500">Status findings will appear here after analyzing an account.</p>
                    </div>
                </div>
            </div>

            <div id="hs-report-content" class="healthy-status-tab-content hidden"></div>
            <div id="hs-findings-report-content" class="healthy-status-tab-content hidden"></div>
            <div id="hs-inventory-content" class="healthy-status-tab-content hidden"></div>
            <div id="hs-notes-content" class="healthy-status-tab-content hidden"></div>
        </div>
        
        <style>
        .severity-pill-critical { background-color: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; }
        .severity-pill-high { background-color: #fef3c7; color: #92400e; border: 1px solid #fbbf24; }
        .severity-pill-medium { background-color: #fef3c7; color: #d97706; border: 1px solid #f59e0b; }
        .severity-pill-low { background-color: #dbeafe; color: #1e40af; border: 1px solid #60a5fa; }
        .severity-pill-info { background-color: #f3f4f6; color: #374151; border: 1px solid #d1d5db; }

        .impact-pill-compliance { background-color: #f0f9ff; color: #0c4a6e; border: 1px solid #7dd3fc; }
        .impact-pill-data-breach { background-color: #fef2f2; color: #7f1d1d; border: 1px solid #fca5a5; }
        .impact-pill-operational { background-color: #f0fdf4; color: #14532d; border: 1px solid #86efac; }
        .impact-pill-access-control { background-color: #faf5ff; color: #581c87; border: 1px solid #c084fc; }
        .impact-pill-monitoring { background-color: #fff7ed; color: #9a3412; border: 1px solid #fdba74; }
        .impact-pill-encryption { background-color: #ecfdf5; color: #065f46; border: 1px solid #6ee7b7; }

        .filter-pill {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 500;
            gap: 0.375rem;
        }
        </style>
    `;

    const tabsNav = container.querySelector('#healthy-status-tabs');
    if (tabsNav) {
        tabsNav.addEventListener('click', handleTabClick(tabsNav, '.healthy-status-tab-content'));
    }
    
    setupFilterEventListeners();
    buildGeminiReportView();
    buildScopedInventoryView();
    buildFindingsReportView();
};

// --- FILTER SETUP ---
const setupFilterEventListeners = () => {
    const regionFilter = document.getElementById('healthy-status-region-filter');
    const severityFilter = document.getElementById('healthy-status-severity-filter');
    const sectionFilter = document.getElementById('healthy-status-section-filter');
    const impactFilter = document.getElementById('healthy-status-impact-filter');
    const resetBtn = document.getElementById('reset-filters-btn');

    let filterTimeout;
    const debouncedApplyFilters = () => {
        clearTimeout(filterTimeout);
        filterTimeout = setTimeout(applyFilters, 100);
    };

    [regionFilter, severityFilter, sectionFilter, impactFilter].forEach(filter => {
        if (filter) {
            filter.removeEventListener('change', debouncedApplyFilters);
            filter.addEventListener('change', debouncedApplyFilters);
        }
    });

    if (resetBtn) {
        resetBtn.removeEventListener('click', resetAllFilters);
        resetBtn.addEventListener('click', resetAllFilters);
    }
};

const resetAllFilters = () => {
    const filters = [
        'healthy-status-region-filter', 
        'healthy-status-severity-filter', 
        'healthy-status-section-filter', 
        'healthy-status-impact-filter'
    ];
    
    filters.forEach(filterId => {
        const filter = document.getElementById(filterId);
        if (filter) {
            filter.value = 'all';
        }
    });
    
    setTimeout(applyFilters, 50);
};

const applyFilters = () => {
    const regionValue = document.getElementById('healthy-status-region-filter')?.value || 'all';
    const severityValue = document.getElementById('healthy-status-severity-filter')?.value || 'all';
    const sectionValue = document.getElementById('healthy-status-section-filter')?.value || 'all';
    const impactValue = document.getElementById('healthy-status-impact-filter')?.value || 'all';

    let filteredFindings = [...(window.lastHealthyStatusFindings || [])];
    
    if (regionValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => {
            const resources = finding.affected_resources || [];
            if (resources.length === 0) return false;
            
            return resources.some(res => {
                if (typeof res === 'object' && res !== null) {
                    const region = res.region || 'Global';
                    return region === regionValue || region === 'Global';
                } else if (typeof res === 'string') {
                    return regionValue === 'Global';
                }
                return false;
            });
        });
    }
    
    if (severityValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            finding.severity === severityValue
        );
    }
    
    if (sectionValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            finding.section === sectionValue
        );
    }
    
    if (impactValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            classifyFindingImpact(finding) === impactValue
        );
    }
    
    updateFindingsCount(filteredFindings.length, (window.lastHealthyStatusFindings || []).length);
    
    updateActiveFiltersDisplay();
    
    renderHealthyStatusFindings(filteredFindings);
};

const updateFindingsCount = (filtered, total, countDisplayId = 'findings-count-display') => {
    const countDisplay = document.getElementById(countDisplayId);
    if (!countDisplay) return;

    if (filtered === total) {
        countDisplay.innerHTML = `
            <div class="flex items-center space-x-1">
                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
                </svg>
                <span>${total} finding${total !== 1 ? 's' : ''}</span>
            </div>
        `;
        countDisplay.className = "bg-[#eb3496] text-white px-3 py-1 rounded-full text-sm font-semibold flex items-center";
    } else {
        countDisplay.innerHTML = `
            <div class="flex items-center space-x-1">
                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M3 3a1 1 0 011-1h12a1 1 0 011 1v3a1 1 0 01-.293.707L12 11.414V15a1 1 0 01-.293.707l-2 2A1 1 0 018 17v-5.586L3.293 6.707A1 1 0 013 6V3z" clip-rule="evenodd"></path>
                </svg>
                <span>${filtered}/${total}</span>
            </div>
        `;
        countDisplay.className = "bg-blue-500 text-white px-3 py-1 rounded-full text-sm font-semibold flex items-center animate-pulse";
    }
};



const updateActiveFiltersDisplay = () => {
    const activeFiltersContainer = document.getElementById('active-filters-container');
    const activeFiltersDisplay = document.getElementById('active-filters-display');
    
    if (!activeFiltersContainer || !activeFiltersDisplay) return;
    
    activeFiltersContainer.innerHTML = '';
    let hasActiveFilters = false;
    
    const severityConfig = {
        'Crítico': { label: 'Critical', class: 'severity-pill-critical' },
        'Alto': { label: 'High', class: 'severity-pill-high' },
        'Medio': { label: 'Medium', class: 'severity-pill-medium' },
        'Bajo': { label: 'Low', class: 'severity-pill-low' },
        'Informativo': { label: 'Info', class: 'severity-pill-info' }
    };
    
    const impactConfig = {
        'compliance': { label: 'Compliance Risk', class: 'impact-pill-compliance' },
        'data_breach': { label: 'Data Breach Risk', class: 'impact-pill-data-breach' },
        'operational': { label: 'Operational Risk', class: 'impact-pill-operational' },
        'access_control': { label: 'Access Control Risk', class: 'impact-pill-access-control' },
        'monitoring': { label: 'Monitoring Gap', class: 'impact-pill-monitoring' },
        'encryption': { label: 'Encryption Issue', class: 'impact-pill-encryption' }
    };
    
    const regionValue = document.getElementById('healthy-status-region-filter')?.value;
    const severityValue = document.getElementById('healthy-status-severity-filter')?.value;
    const sectionValue = document.getElementById('healthy-status-section-filter')?.value;
    const impactValue = document.getElementById('healthy-status-impact-filter')?.value;
    
    if (regionValue && regionValue !== 'all') {
        const pill = createFilterPill('Region', regionValue, 'region', 'bg-blue-100 text-blue-800 border-blue-200');
        activeFiltersContainer.appendChild(pill);
        hasActiveFilters = true;
    }
    
    if (severityValue && severityValue !== 'all') {
        const config = severityConfig[severityValue];
        const pill = createFilterPill('Severity', config?.label || severityValue, 'severity', config?.class || 'bg-gray-100 text-gray-800 border-gray-200');
        activeFiltersContainer.appendChild(pill);
        hasActiveFilters = true;
    }
    
    if (sectionValue && sectionValue !== 'all') {
        const pill = createFilterPill('Section', sectionValue, 'section', 'bg-green-100 text-green-800 border-green-200');
        activeFiltersContainer.appendChild(pill);
        hasActiveFilters = true;
    }
    
    if (impactValue && impactValue !== 'all') {
        const config = impactConfig[impactValue];
        const pill = createFilterPill('Impact', config?.label || impactValue, 'impact', config?.class || 'bg-gray-100 text-gray-800 border-gray-200');
        activeFiltersContainer.appendChild(pill);
        hasActiveFilters = true;
    }
    
    if (hasActiveFilters) {
        activeFiltersDisplay.classList.remove('hidden');
    } else {
        activeFiltersDisplay.classList.add('hidden');
    }
};

const createFilterPill = (type, label, filterType, cssClass) => {
    const pill = document.createElement('div');
    pill.className = `filter-pill ${cssClass}`;
    pill.innerHTML = `
        <span class="text-xs font-medium opacity-75">${type}:</span>
        <span class="text-xs font-semibold">${label}</span>
        <button class="ml-1 hover:bg-black hover:bg-opacity-10 rounded-full p-0.5 transition-colors" onclick="removeFilter('${filterType}')">
            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
        </button>
    `;
    return pill;
};

const removeFilter = (filterType) => {
    const filterMap = {
        'region': 'healthy-status-region-filter',
        'severity': 'healthy-status-severity-filter',
        'section': 'healthy-status-section-filter',
        'impact': 'healthy-status-impact-filter'
    };
    
    const filterId = filterMap[filterType];
    const filter = document.getElementById(filterId);
    
    if (filter) {
        filter.value = 'all';
        applyFilters();
    }
};

const setupFindingsReportEvents = () => {
    // Eventos para los botones
    document.getElementById('select-all-findings')?.addEventListener('click', selectAllFindings);
    document.getElementById('deselect-all-findings')?.addEventListener('click', deselectAllFindings);
    document.getElementById('generate-custom-pdf')?.addEventListener('click', generateCustomPDF);
    document.getElementById('reset-finding-edits')?.addEventListener('click', resetFindingEdits);


    // Pasa los findings iniciales a la función de renderizado
    populateFindingsReportData();

    // Configura los event listeners para los nuevos filtros
    const regionFilter = document.getElementById('report-region-filter');
    const severityFilter = document.getElementById('report-severity-filter');
    const sectionFilter = document.getElementById('report-section-filter');
    const impactFilter = document.getElementById('report-impact-filter');
    const resetBtn = document.getElementById('report-reset-filters-btn');

    let filterTimeout;
    const debouncedApplyFilters = () => {
        clearTimeout(filterTimeout);
        filterTimeout = setTimeout(applyReportFilters, 100);
    };

    [regionFilter, severityFilter, sectionFilter, impactFilter].forEach(filter => {
        if (filter) {
            filter.removeEventListener('change', debouncedApplyFilters);
            filter.addEventListener('change', debouncedApplyFilters);
        }
    });

    if (resetBtn) {
        resetBtn.removeEventListener('click', resetReportFilters);
        resetBtn.addEventListener('click', resetReportFilters);
    }

    // Observa la pestaña para refrescar los filtros cuando se haga visible
    const container = document.getElementById('hs-findings-report-content');
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'attributes' && 
                mutation.attributeName === 'class' && 
                !container.classList.contains('hidden')) {
                // La pestaña se hizo visible, refrescar datos
                populateFindingsReportData();
            }
        });
    });
    observer.observe(container, { attributes: true });
};

// REEMPLAZA LA FUNCIÓN ENTERA
const populateFindingsReportData = () => {
    const regionFilter = document.getElementById('report-region-filter');
    const severityFilter = document.getElementById('report-severity-filter');
    const sectionFilter = document.getElementById('report-section-filter');
    const impactFilter = document.getElementById('report-impact-filter');
    const findingsList = document.getElementById('findings-selection-list');

    if (!regionFilter || !severityFilter || !sectionFilter || !impactFilter || !findingsList) return;

    // ¡CAMBIO CLAVE! Creamos aquí la copia editable para trabajar sobre ella.
    window.editableFindings = JSON.parse(JSON.stringify(window.lastHealthyStatusFindings || []));

    if (window.editableFindings.length === 0) {
        findingsList.innerHTML = '<p class="text-gray-500 text-center py-8">No findings available yet. Please run an analysis from another section first.</p>';
        regionFilter.innerHTML = '<option value="all">All Regions</option>';
        severityFilter.innerHTML = '<option value="all">All Severities</option>';
        sectionFilter.innerHTML = '<option value="all">All Sections</option>';
        impactFilter.innerHTML = '<option value="all">All Impact Types</option>';
        return;
    }

    const findings = window.editableFindings; // Usamos la copia

    // Poblar filtros de región
    const regions = new Set();
    findings.forEach(finding => {
        (finding.affected_resources || []).forEach(res => {
            const region = res.region || 'Global';
            regions.add(region);
        });
    });
    regionFilter.innerHTML = '<option value="all">All Regions</option>';
    Array.from(regions).sort().forEach(region => {
        const option = document.createElement('option');
        option.value = region;
        option.textContent = region;
        regionFilter.appendChild(option);
    });

    // Poblar filtros de severidad
    const severities = ['Crítico', 'Alto', 'Medio', 'Bajo', 'Informativo'];
    const severityLabels = { 'Crítico': 'Critical', 'Alto': 'High', 'Medio': 'Medium', 'Bajo': 'Low', 'Informativo': 'Info' };
    severityFilter.innerHTML = '<option value="all">All Severities</option>';
    severities.forEach(severity => {
        const option = document.createElement('option');
        option.value = severity;
        option.textContent = severityLabels[severity] || severity;
        severityFilter.appendChild(option);
    });

    // Poblar filtros de sección
    const sections = new Set(findings.map(f => f.section).filter(Boolean));
    sectionFilter.innerHTML = '<option value="all">All Sections</option>';
    Array.from(sections).sort().forEach(section => {
        const option = document.createElement('option');
        option.value = section;
        option.textContent = section;
        sectionFilter.appendChild(option);
    });

    // Poblar filtros de impacto
    const impacts = new Set(findings.map(classifyFindingImpact).filter(Boolean));
    const impactLabels = {
        'compliance': 'Compliance Risk',
        'data_breach': 'Data Breach Risk',
        'operational': 'Operational Risk',
        'access_control': 'Access Control Risk',
        'monitoring': 'Monitoring Gap',
        'encryption': 'Encryption Issue'
    };
    impactFilter.innerHTML = '<option value="all">All Impact Types</option>';
    Array.from(impacts).sort().forEach(impact => {
        const option = document.createElement('option');
        option.value = impact;
        option.textContent = impactLabels[impact] || impact;
        impactFilter.appendChild(option);
    });

    // Renderizar hallazgos iniciales sin filtros
    renderFindingsSelectionList(findings);

    // Actualizar el conteo de hallazgos
    updateFindingsCount(findings.length, findings.length, 'report-findings-count-display');
    
    if (window.reportCheckboxStates.size === 0) {
        for (let i = 0; i < findings.length; i++) {
            window.reportCheckboxStates.add(i);
        }
    }
};

const renderFindingsSelectionList = (findings) => {
    const container = document.getElementById('findings-selection-list');
    if (!container) return;
    
    if (findings.length === 0) {
        container.innerHTML = '<p class="text-gray-500 text-center py-4">No findings available for the selected filters.</p>';
        return;
    }
    
    const severityOrder = { 'Crítico': 1, 'Alto': 2, 'Medio': 3, 'Bajo': 4, 'Informativo': 5 };
    const sortedFindings = [...findings].sort((a, b) => 
        (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99)
    );
    
    container.innerHTML = sortedFindings.map((finding, index) => {
        const severityClass = getSeverityClass(finding.severity);
        const resourceCount = (finding.affected_resources || []).length;
        
        return `
            <div class="finding-item border border-gray-200 rounded-lg p-4 hover:bg-gray-50" data-finding-index="${index}">
                <div class="flex items-start space-x-3">
                    <input type="checkbox" id="finding-${index}" class="finding-checkbox mt-1" ${window.reportCheckboxStates.has(index) ? 'checked' : ''}>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center space-x-2 mb-2">
                            <h5 class="font-semibold text-gray-900 truncate">${finding.name || 'Unknown Finding'}</h5>
                            <span class="px-2 py-1 text-xs font-medium rounded-full ${severityClass}">${getSeverityLabel(finding.severity)}</span>
                        </div>
                        <p class="text-sm text-gray-600 mb-2">${finding.description || 'No description'}</p>
                        <div class="text-xs text-gray-500">
                            Section: ${finding.section || 'N/A'} | Resources: ${resourceCount}
                        </div>
                    </div>
                    <button class="edit-finding-btn text-blue-600 hover:text-blue-800 p-1" data-finding-index="${index}" title="Edit Finding">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                        </svg>
                    </button>
                </div>
            </div>
        `;
    }).join('');
    
    // Agregar event listeners para los botones de editar
    container.querySelectorAll('.edit-finding-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const findingIndex = parseInt(e.currentTarget.getAttribute('data-finding-index'));
            openEditFindingModal(findingIndex, sortedFindings); // Pasar los findings filtrados
        });
    });

    // Agregar event listeners para los checkboxes
    container.querySelectorAll('.finding-checkbox').forEach((checkbox, idx) => {
        checkbox.addEventListener('change', (e) => {
            const index = parseInt(e.target.id.replace('finding-', ''));
            if (e.target.checked) {
                window.reportCheckboxStates.add(index);
            } else {
                window.reportCheckboxStates.delete(index);
            }
        });
    });
};

const getSeverityClass = (severity) => {
    const classes = {
        'Crítico': 'bg-red-100 text-red-800',
        'Alto': 'bg-red-100 text-red-700',
        'Medio': 'bg-yellow-100 text-yellow-800',
        'Bajo': 'bg-blue-100 text-blue-800',
        'Informativo': 'bg-gray-100 text-gray-700'
    };
    return classes[severity] || 'bg-gray-100 text-gray-700';
};

const getSeverityLabel = (severity) => {
    const labels = {
        'Crítico': 'Critical',
        'Alto': 'High',
        'Medio': 'Medium',
        'Bajo': 'Low',
        'Informativo': 'Info'
    };
    return labels[severity] || severity;
};


const selectAllFindings = () => {
    // Marcar todos los checkboxes visibles
    const checkboxes = document.querySelectorAll('.finding-checkbox');
    checkboxes.forEach((checkbox, idx) => {
        checkbox.checked = true;
        const index = parseInt(checkbox.id.replace('finding-', ''));
        window.reportCheckboxStates.add(index);
    });
};

const deselectAllFindings = () => {
    // Desmarcar todos los checkboxes visibles
    const checkboxes = document.querySelectorAll('.finding-checkbox');
    checkboxes.forEach((checkbox, idx) => {
        checkbox.checked = false;
        const index = parseInt(checkbox.id.replace('finding-', ''));
        window.reportCheckboxStates.delete(index);
    });
};

const getSelectedFindings = () => {
    const selectedFindings = [];
    const currentlyDisplayedFindings = getCurrentlyDisplayedFindings();
    
    document.querySelectorAll('.finding-checkbox:checked').forEach(checkbox => {
        const findingItem = checkbox.closest('.finding-item');
        const findingIndex = parseInt(findingItem.getAttribute('data-finding-index'));
        
        if (currentlyDisplayedFindings[findingIndex]) {
            selectedFindings.push(currentlyDisplayedFindings[findingIndex]);
        }
    });
    return selectedFindings;
};

const generateCustomPDF = () => {
    const auditedCompany = document.getElementById('audited-company')?.value.trim();
    
    if (!auditedCompany) {
        alert('Please fill in the client company name.');
        return;
    }
    
    // CORRECCIÓN: Primero obtener los findings filtrados actuales
const selectedFindings = getSelectedFindings();
    
    if (selectedFindings.length === 0) {
        alert('Please select at least one finding to include in the report.');
        return;
    }
    
    // Llamar a la función de generación de PDF con los findings seleccionados
    generateCustomPDFReport({
        clientName: auditedCompany,
        findings: selectedFindings
    });
};

// REEMPLAZA LA FUNCIÓN ENTERA
const getCurrentlyDisplayedFindings = () => {
    const regionValue = document.getElementById('report-region-filter')?.value || 'all';
    const severityValue = document.getElementById('report-severity-filter')?.value || 'all';
    const sectionValue = document.getElementById('report-section-filter')?.value || 'all';
    const impactValue = document.getElementById('report-impact-filter')?.value || 'all';

    let displayedFindings = [...(window.editableFindings || [])];

    if (regionValue !== 'all') {
        // PASO 1: Filtrar los findings que tienen AL MENOS UN recurso en la región seleccionada.
        const relevantFindings = displayedFindings.filter(finding => {
            const resources = finding.affected_resources || [];
            if (resources.length === 0) return false;

            return resources.some(res => {
                const region = (typeof res === 'object' && res.region) ? res.region : 'Global';
                return region === regionValue || region === 'Global';
            });
        });

        // PASO 2: Mapear sobre los findings relevantes para filtrar SU PROPIA lista de recursos.
        displayedFindings = relevantFindings.map(finding => {
            // Se crea una copia profunda para no modificar el dato original (window.editableFindings).
            const newFinding = JSON.parse(JSON.stringify(finding));

            // Filtramos la lista de recursos INTERNA del finding.
            newFinding.affected_resources = (finding.affected_resources || []).filter(res => {
                const region = (typeof res === 'object' && res.region) ? res.region : 'Global';
                // La condición es la misma: mantener solo los de la región seleccionada o los globales.
                return region === regionValue || region === 'Global';
            });

            return newFinding; // Devolvemos la copia del finding con los recursos ya filtrados.
        });

    } else {
        // Si no hay filtro de región, simplemente clonamos para evitar mutaciones no deseadas.
        displayedFindings = displayedFindings.map(f => JSON.parse(JSON.stringify(f)));
    }


    // El resto de los filtros no necesitan esta lógica de mapeo, ya que operan sobre el finding en general.
    if (severityValue !== 'all') {
        displayedFindings = displayedFindings.filter(finding =>
            finding.severity === severityValue
        );
    }

    if (sectionValue !== 'all') {
        displayedFindings = displayedFindings.filter(finding =>
            finding.section === sectionValue
        );
    }

    if (impactValue !== 'all') {
        displayedFindings = displayedFindings.filter(finding =>
            classifyFindingImpact(finding) === impactValue
        );
    }

    // Finalmente, se ordena como siempre.
    const severityOrder = { 'Crítico': 1, 'Alto': 2, 'Medio': 3, 'Bajo': 4, 'Informativo': 5 };
    return displayedFindings.sort((a, b) =>
        (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99)
    );
};




const openEditFindingModal = (findingIndex, findings) => {
    const finding = findings[findingIndex];
    if (!finding) return;
    
    const modal = document.createElement('div');
    modal.id = 'edit-finding-modal';
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50';
    
    // Preparar recursos afectados para mostrar
    const affectedResources = finding.affected_resources || [];
    const resourcesHtml = affectedResources.map((resource, resourceIndex) => {
        let resourceName, regionName;
        
        if (typeof resource === 'object' && resource.resource && resource.region) {
            resourceName = resource.resource;
            regionName = resource.region;
        } else if (typeof resource === 'string') {
            resourceName = resource;
            regionName = 'Global';
        } else {
            resourceName = 'Unknown Resource';
            regionName = 'Global';
        }
        
        return `
            <div class="resource-item flex items-center justify-between p-2 bg-gray-50 rounded border" data-resource-index="${resourceIndex}">
                <div class="flex-1 min-w-0">
                    <div class="text-sm font-medium text-gray-900 truncate">${resourceName}</div>
                    <div class="text-xs text-gray-500">${regionName}</div>
                </div>
                <button class="remove-resource-btn ml-2 text-red-600 hover:text-red-800 p-1" data-resource-index="${resourceIndex}" title="Remove Resource">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
        `;
    }).join('');
    
    modal.innerHTML = `
        <div class="bg-white rounded-lg p-6 max-w-4xl w-full mx-4 max-h-[90vh] overflow-y-auto">
            <h3 class="text-xl font-bold text-[#204071] mb-4">Edit Finding</h3>
            
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- Columna izquierda: Información básica -->
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Finding Name</label>
                        <input type="text" id="edit-finding-name" class="w-full p-2 border border-gray-300 rounded-lg" 
                               value="${finding.name || ''}">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Description</label>
                        <textarea id="edit-finding-description" rows="4" 
                                  class="w-full p-2 border border-gray-300 rounded-lg">${finding.description || ''}</textarea>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Remediation</label>
                        <textarea id="edit-finding-remediation" rows="3" 
                                  class="w-full p-2 border border-gray-300 rounded-lg">${finding.remediation || ''}</textarea>
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Severity</label>
                        <select id="edit-finding-severity" class="w-full p-2 border border-gray-300 rounded-lg">
                            <option value="Crítico" ${finding.severity === 'Crítico' ? 'selected' : ''}>Critical</option>
                            <option value="Alto" ${finding.severity === 'Alto' ? 'selected' : ''}>High</option>
                            <option value="Medio" ${finding.severity === 'Medio' ? 'selected' : ''}>Medium</option>
                            <option value="Bajo" ${finding.severity === 'Bajo' ? 'selected' : ''}>Low</option>
                            <option value="Informativo" ${finding.severity === 'Informativo' ? 'selected' : ''}>Info</option>
                        </select>
                    </div>
                </div>
                
                <!-- Columna derecha: Recursos afectados -->
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">
                            Affected Resources (${affectedResources.length})
                        </label>
                        <div id="affected-resources-list" class="space-y-2 max-h-64 overflow-y-auto border border-gray-200 rounded-lg p-3">
                            ${resourcesHtml || '<p class="text-gray-500 text-sm">No resources available</p>'}
                        </div>
                    </div>
                    
                    <div class="bg-blue-50 p-3 rounded-lg">
                        <p class="text-sm text-blue-800">
                            <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                            </svg>
                            Click the X button to remove resources that don't apply to this finding.
                        </p>
                    </div>
                </div>
            </div>
            
            <div class="flex space-x-3 mt-6">
                <button onclick="closeEditFindingModal()" class="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50">Cancel</button>
                <button onclick="saveFindingChanges(${findingIndex})" class="flex-1 px-4 py-2 bg-[#204071] text-white rounded-lg hover:bg-[#1a365d]">Save Changes</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Agregar event listeners para los botones de eliminar recursos
    modal.querySelectorAll('.remove-resource-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const resourceIndex = parseInt(e.currentTarget.getAttribute('data-resource-index'));
            removeResourceFromFinding(findingIndex, resourceIndex);
        });
    });
};

window.closeEditFindingModal = () => {
    const modal = document.getElementById('edit-finding-modal');
    if (modal) modal.remove();
};

// REEMPLAZA LA FUNCIÓN ENTERA
window.saveFindingChanges = (findingIndex) => {
    const name = document.getElementById('edit-finding-name')?.value.trim();
    const description = document.getElementById('edit-finding-description')?.value.trim();
    const remediation = document.getElementById('edit-finding-remediation')?.value.trim();
    const severity = document.getElementById('edit-finding-severity')?.value;
    
    const currentlyDisplayedFindings = getCurrentlyDisplayedFindings();
    const findingToEdit = currentlyDisplayedFindings[findingIndex];
    
    if (!findingToEdit) return;
    
    // ¡CAMBIO CLAVE! Buscamos el hallazgo en la lista editable para modificarlo.
    const editableIndex = window.editableFindings.findIndex(f => 
        f.rule_id === findingToEdit.rule_id && 
        f.name === findingToEdit.name && 
        f.section === findingToEdit.section
    );
    
    if (editableIndex !== -1) {
        window.editableFindings[editableIndex] = {
            ...window.editableFindings[editableIndex], // Mantiene los recursos
            name,
            description,
            remediation,
            severity
        };
    }
    
    applyReportFilters();
    closeEditFindingModal();
};

const generateCustomPDFReport = async (reportData) => {
    const { clientName, findings } = reportData;
    
    const generateButton = document.getElementById('generate-custom-pdf');
    const originalText = generateButton?.textContent || '';
    
    if (generateButton) {
        generateButton.textContent = 'Generating...';
        generateButton.disabled = true;
    }
    
    try {
        // Cargar template desde la ruta correcta
        const response = await fetch('/static/js/templates/pdf-report-template.html');
        if (!response.ok) {
            throw new Error(`Failed to load template: ${response.status}`);
        }
        const template = await response.text();
        
        const processedHTML = processTemplate(template, {
            clientName: clientName,
            findings: findings
        });
        
        await generateAndDownloadPDF(processedHTML, `AudiThor-Security-Report-${clientName.replace(/[^a-zA-Z0-9]/g, '-')}.pdf`);
        
        log('Custom PDF report generated successfully.', 'success');
        
    } catch (error) {
        console.error('Custom PDF Generation Error:', error);
        alert(`Error generating custom PDF: ${error.message}`);
        log(`Custom PDF generation failed: ${error.message}`, 'error');
        
    } finally {
        // Restaurar botón
        if (generateButton) {
            generateButton.textContent = originalText || 'Generate PDF Report';
            generateButton.disabled = false;
        }
    }
};

// --- IMPACT CLASSIFICATION ---
const classifyFindingImpact = (finding) => {
    const name = (finding.name || '').toLowerCase();
    const description = (finding.description || '').toLowerCase();
    const section = (finding.section || '').toLowerCase();
    const ruleId = (finding.rule_id || '').toLowerCase();

    if (ruleId.includes('pci') || name.includes('pci') || description.includes('pci') ||
        name.includes('cis') || description.includes('compliance') || 
        description.includes('standard') || description.includes('benchmark')) {
        return 'compliance';
    }

    if (name.includes('public') || name.includes('exposed') || name.includes('internet') ||
        description.includes('public access') || description.includes('publicly accessible') ||
        section.includes('internet exposure') || name.includes('unencrypted')) {
        return 'data_breach';
    }

    if (section.includes('identity') || section.includes('access') || 
        name.includes('mfa') || name.includes('password') || name.includes('policy') ||
        name.includes('permission') || name.includes('role') || name.includes('user')) {
        return 'access_control';
    }

    if (section.includes('logging') || section.includes('monitoring') || 
        name.includes('cloudtrail') || name.includes('guardduty') || name.includes('log') ||
        name.includes('disabled') || name.includes('not enabled')) {
        return 'monitoring';
    }

    if (name.includes('encrypt') || name.includes('kms') || description.includes('encrypt') ||
        section.includes('data protection')) {
        return 'encryption';
    }

    return 'operational';
};

export const buildGeminiReportView = () => {
    const container = document.getElementById('hs-report-content');
    if (!container) return;

    const defaultPrompt = `Act as a senior cybersecurity consultant from [Your Company Name]. The recipient of this email is our client, an individual in a technical leadership role (CTO, Tech Lead).

Your task is to draft a clear and concise email to notify the client about the security findings identified in their AWS account.

The email must have the following structure:

**Subject:** Executive Summary: Security Findings in Your AWS Account

**Email Body:**

* **Greeting:** A professional salutation (e.g., "Dear [Client Name],").
* **Introduction (1 paragraph):** Briefly state that a security review has been completed and that the key results are presented below.
* **Summary of Findings:** Present a bulleted list. For **each type of finding** identified in the JSON I provide, include a bullet point with:
    * The **finding's title**.
    * In parentheses, its **severity**.
    * A **brief description (1-2 sentences)** of the associated business risk. **Do not include the detailed list of affected resources**, only a summary of the issue.
* **Primary Recommendation:** Based on the findings, offer a general, prioritized recommendation (e.g., "We recommend focusing initial efforts on remediating Critical and High severity findings, especially those related to identity and access management.").
* **Next Steps:** Propose scheduling a meeting to review the full technical report and coordinate the remediation plan.
* **Closing:** A cordial and professional closing.

The goal is for the client to quickly understand the existing issues and their impact without being overwhelmed by technical details in the first contact. Ensure that **all types of findings** are listed.

Below are the findings in JSON format:`;

    container.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-1 text-[#204071]">Generate Report with AI (Gemini)</h3>
            <p class="text-sm text-gray-500 mb-4">This tool will use the findings to generate a draft executive report.</p>
            
            <div class="mb-4">
                <label for="gemini-api-key" class="block text-sm font-medium text-gray-700 mb-1">Your Google AI Studio (Gemini) API Key</label>
                <input type="password" id="gemini-api-key" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5" placeholder="Paste your API key here">
                <p class="text-xs text-gray-500 mt-1">Your key is used directly from your browser to call the Google API and is not stored anywhere.</p>
            </div>

            <div class="mb-4">
                <label for="gemini-region-filter" class="block text-sm font-medium text-gray-700 mb-1">Filter Findings by Region (Optional)</label>
                <select id="gemini-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5">
                    <option value="all">All Regions</option>
                </select>
            </div>

            <div class="mb-4">
                <label for="gemini-prompt" class="block text-sm font-medium text-gray-700 mb-1">Prompt for Gemini (Editable)</label>
                <textarea id="gemini-prompt" rows="10" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono">${defaultPrompt}</textarea>
            </div>

            <button id="generate-gemini-report-btn" class="bg-[#eb3496] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#d42c86] transition flex items-center justify-center space-x-2">
                <span id="gemini-btn-text">Generate Draft Email</span>
                <div id="gemini-spinner" class="spinner hidden"></div>
            </button>

            <div id="gemini-report-output" class="mt-6 hidden">
                 <h4 class="font-bold text-lg mb-2 text-[#204071]">Email Draft:</h4>
                 <div id="gemini-report-content" class="bg-slate-50 p-4 rounded-lg border text-sm whitespace-pre-wrap"></div>
            </div>
        </div>
    `;

    const genButton = document.getElementById('generate-gemini-report-btn');
    if (genButton) {
        genButton.addEventListener('click', generateGeminiReport);
    }
};

export const buildFindingsReportView = () => {
    const container = document.getElementById('hs-findings-report-content');
    if (!container) return;

    container.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-4 text-[#204071]">Generate Custom Findings Report</h3>
            
            <div class="mb-6">
                <label class="block text-sm font-medium text-gray-700 mb-2">Client Company</label>
                <input type="text" id="audited-company" class="w-full p-2 border border-gray-300 rounded-lg" placeholder="Client Company Name">
            </div>

            <div class="bg-gradient-to-r from-white to-gray-50 p-6 rounded-2xl border border-gray-200 shadow-sm mb-6">
                <div class="flex items-center justify-between mb-4">
                    <div class="flex items-center space-x-2">
                        <svg class="w-5 h-5 text-[#eb3496]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293.707L3.293 7.707A1 1 0 013 7V4z"></path>
                        </svg>
                        <h3 class="text-lg font-bold text-gray-800">Filter Options</h3>
                    </div>
                    <div id="report-findings-count-display" class="bg-[#eb3496] text-white px-3 py-1 rounded-full text-sm font-semibold"></div>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-4">
                    <div class="group">
                        <label for="report-region-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-blue-500" viewBox="0 0 16 16">
                                <path d="M12.166 8.94c-.524 1.062-1.234 2.12-1.96 3.07A32 32 0 0 1 8 14.58a32 32 0 0 1-2.206-2.57c-.726-.95-1.436-2.008-1.96-3.07C3.304 7.867 3 6.862 3 6a5 5 0 0 1 10 0c0 .862-.305 1.867-.834 2.94M8 16s6-5.686 6-10A6 6 0 0 0 2 6c0 4.314 6 10 6 10"/>
                                <path d="M8 8a2 2 0 1 1 0-4 2 2 0 0 1 0 4m0 1a3 3 0 1 0 0-6 3 3 0 0 0 0 6"/>
                            </svg>
                            Region
                        </label>
                        <select id="report-region-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-blue-300">
                            <option value="all">All Regions</option>
                        </select>
                    </div>
                    
                    <div class="group">
                        <label for="report-severity-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-red-500" viewBox="0 0 16 16">
                                <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1-.054-.06.18.18 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/>
                                <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/>
                            </svg>
                            Severity
                        </label>
                        <select id="report-severity-filter" class="severity-select w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-red-300">
                            <option value="all">All Severities</option>
                        </select>
                    </div>
                    
                    <div class="group">
                        <label for="report-section-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-green-500" viewBox="0 0 16 16">
                                <path d="M8.186 1.113a.5.5 0 0 0-.372 0L1.846 3.5 8 5.961 14.154 3.5zM15 4.239l-6.5 2.6v7.922l6.5-2.6V4.24zM7.5 14.762V6.838L1 4.239v7.923zM7.443.184a1.5 1.5 0 0 1 1.114 0l7.129 2.852A.5.5 0 0 1 16 3.5v8.662a1 1 0 0 1-.629.928l-7.185 2.874a.5.5 0 0 1-.372 0L.63 13.09a1 1 0 0 1-.63-.928V3.5a.5.5 0 0 1 .314-.464z"/>
                            </svg>
                            Section
                        </label>
                        <select id="report-section-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-green-300">
                            <option value="all">All Sections</option>
                        </select>
                    </div>
                    
                    <div class="group">
                        <label for="report-impact-filter" class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-purple-500" viewBox="0 0 16 16">
                                <path d="M8 16c3.314 0 6-2 6-5.5 0-1.5-.5-4-2.5-6 .25 1.5-1.25 2-1.25 2C11 4 9 .5 6 0c.357 2 .5 4-2 6-1.25 1-2 2.729-2 4.5C2 14 4.686 16 8 16m0-1c-1.657 0-3-1-3-2.75 0-.75.25-2 1.25-3C6.125 10 7 10.5 7 10.5c-.375-1.25.5-3.25 2-3.5-.179 1-.25 2 1 3 .625.5 1 1.364 1 2.25C11 14 9.657 15 8 15"/>
                            </svg>
                            Impact Type
                        </label>
                        <select id="report-impact-filter" class="impact-select w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300 group-hover:border-purple-300">
                            <option value="all">All Impact Types</option>
                        </select>
                    </div>
                </div>
                
                <div id="report-active-filters-display" class="hidden mb-4">
                    <div class="flex flex-wrap items-center gap-2">
                        <span class="text-sm font-medium text-gray-600">Active filters:</span>
                        <div id="report-active-filters-container" class="flex flex-wrap gap-2"></div>
                    </div>
                </div>
                
                <div class="flex justify-between items-center pt-4 border-t border-gray-200">
                    <button id="report-reset-filters-btn" class="inline-flex items-center px-4 py-2 text-sm font-medium text-[#eb3496] bg-pink-50 border border-pink-200 rounded-xl hover:bg-pink-100 hover:border-[#eb3496] transition-all duration-200 group">
                        <svg class="w-4 h-4 mr-2 group-hover:rotate-180 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                        </svg>
                        Reset All Filters
                    </button>
                    
                    <div class="flex items-center space-x-2 text-sm text-gray-600">
                        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"></path>
                        </svg>
                        <span>Active filters will update results instantly</span>
                    </div>
                </div>
            </div>
            
            <div class="mb-6">
                <h4 class="font-semibold text-gray-800 mb-3">Select Findings to Include</h4>
                <div id="findings-selection-list" class="space-y-2 max-h-96 overflow-y-auto border border-gray-200 rounded-lg p-4">
                    </div>
            </div>
            
            <div class="flex space-x-3">
                <button id="select-all-findings" class="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600">Select All</button>
                <button id="deselect-all-findings" class="px-4 py-2 bg-gray-400 text-white rounded-lg hover:bg-gray-500">Deselect All</button>
                <button id="reset-finding-edits" class="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">Reset Edits</button>
                <button id="generate-custom-pdf" class="px-4 py-2 bg-[#204071] text-white rounded-lg hover:bg-[#1a365d]">Generate PDF Report</button>
            </div>
        </div>
    `;
    
    setupFindingsReportEvents();
    
    // Refrescar datos cada vez que se muestre esta pestaña
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'attributes' && 
                mutation.attributeName === 'class' && 
                !container.classList.contains('hidden')) {
                // La pestaña se hizo visible, refrescar datos
                populateFindingsReportData();
            }
        });
    });
    
    observer.observe(container, { attributes: true });
};

// --- INTERNAL MODULE FUNCTIONS ---
export const generateGeminiReport = async () => {
    const apiKey = document.getElementById('gemini-api-key')?.value.trim();
    const userPrompt = document.getElementById('gemini-prompt')?.value.trim();
    const reportOutputContainer = document.getElementById('gemini-report-output');
    const reportContentDiv = document.getElementById('gemini-report-content');
    const runBtn = document.getElementById('generate-gemini-report-btn');
    const btnText = document.getElementById('gemini-btn-text');
    const spinner = document.getElementById('gemini-spinner');

    if (!apiKey) {
        alert('Please enter your Gemini API Key.');
        return;
    }
    
    if (!window.lastHealthyStatusFindings || window.lastHealthyStatusFindings.length === 0) {
        alert('There are no findings to generate a report. Please run an analysis first.');
        return;
    }

    if (runBtn) runBtn.disabled = true;
    if (spinner) spinner.classList.remove('hidden');
    if (btnText) btnText.textContent = 'Generating...';
    if (reportOutputContainer) reportOutputContainer.classList.add('hidden');
    if (reportContentDiv) reportContentDiv.textContent = 'Contacting the Gemini API...';
    log('Generating report with Gemini...', 'info');

    const selectedRegion = document.getElementById('gemini-region-filter')?.value || 'all';
    let findingsForReport = window.lastHealthyStatusFindings;

    if (selectedRegion !== 'all') {
        log(`Filtering findings for region: ${selectedRegion}`, 'info');
        findingsForReport = window.lastHealthyStatusFindings.map(finding => {
            const affectedInRegion = finding.affected_resources.filter(res => 
                res.region === selectedRegion || res.region === 'Global'
            );
            if (affectedInRegion.length > 0) {
                return { ...finding, affected_resources: affectedInRegion };
            }
            return null;
        }).filter(Boolean);
    }

    const findingsJson = JSON.stringify(findingsForReport, null, 2);
    const fullPrompt = `${userPrompt}\n\n${findingsJson}`;
    const API_ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${apiKey}`;

    try {
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{ parts: [{ text: fullPrompt }] }]
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(`Gemini API Error: ${errorData.error?.message || 'Unknown API error'}`);
        }

        const data = await response.json();
        const reportText = data.candidates?.[0]?.content?.parts?.[0]?.text || 'No response generated';
        
        if (reportContentDiv) reportContentDiv.textContent = reportText;
        if (reportOutputContainer) reportOutputContainer.classList.remove('hidden');
        log('Report generated by Gemini successfully.', 'success');

    } catch (error) {
        const errorMsg = `Error generating report:\n${error.message}`;
        if (reportContentDiv) reportContentDiv.textContent = errorMsg;
        if (reportOutputContainer) reportOutputContainer.classList.remove('hidden');
        log(`Error in Gemini API call: ${error.message}`, 'error');
    } finally {
        if (runBtn) runBtn.disabled = false;
        if (spinner) spinner.classList.add('hidden');
        if (btnText) btnText.textContent = 'Generate Draft Email';
    }
};

export const renderHealthyStatusFindings = (findings) => {
    const container = document.getElementById('healthy-status-container');
    if (!container) return;

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <div class="flex items-center justify-center text-gray-500">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="mr-3" viewBox="0 0 16 16">
                        <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/>
                        <path d="M8 4a.905.905 0 0 0-.9.995l.35 3.507a.552.552 0 0 0 1.1 0l.35-3.507A.905.905 0 0 0 8 4zm.002 6a1 1 0 1 0 0 2 1 1 0 0 0 0-2z"/>
                    </svg>
                    <p class="text-center font-medium text-lg text-gray-600">No findings were found for the selected criteria.</p>
                </div>
            </div>
        `;
        return;
    }

    const severityOrder = { 'Crítico': 1, 'Alto': 2, 'Medio': 3, 'Bajo': 4, 'Informativo': 5 };
    const sortedFindings = [...findings].sort((a, b) => (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99));

    container.innerHTML = '';
    
    sortedFindings.forEach(finding => {
        let borderColor = 'border-gray-500';
        let severityBadgeColor = 'bg-gray-100 text-gray-800';
        
        if (finding.severity === 'Crítico') {
            borderColor = 'border-red-600';
            severityBadgeColor = 'bg-red-100 text-red-800';
        }
        if (finding.severity === 'Alto') {
            borderColor = 'border-red-500';
            severityBadgeColor = 'bg-red-100 text-red-800';
        }
        if (finding.severity === 'Medio') {
            borderColor = 'border-yellow-500';
            severityBadgeColor = 'bg-yellow-100 text-yellow-800';
        }
        if (finding.severity === 'Bajo') {
            borderColor = 'border-blue-500';
            severityBadgeColor = 'bg-blue-100 text-blue-800';
        }
        if (finding.severity === 'Informativo') {
            borderColor = 'border-gray-400';
            severityBadgeColor = 'bg-gray-100 text-gray-600';
        }

        const severityToEnglish = {
            'Crítico': 'Critical',
            'Alto': 'High',
            'Medio': 'Medium',
            'Bajo': 'Low',
            'Informativo': 'Info'
        };
        const severityInEnglish = severityToEnglish[finding.severity] || finding.severity;

        const affectedResourcesWithDisplay = (finding.affected_resources || []).map(res => {
            if (typeof res === 'object' && res.resource && res.region) {
                return {
                    ...res,
                    display: `${res.resource} (${res.region})`
                };
            } else if (typeof res === 'string') {
                return {
                    resource: res,
                    region: 'Global',
                    display: `${res} (Global)`
                };
            } else {
                return {
                    resource: 'Unknown',
                    region: 'Global',
                    display: 'Unknown (Global)'
                };
            }
        });

        const affectedResourcesHtml = affectedResourcesWithDisplay.map(res => 
            `<li>${res.display}</li>`
        ).join('');
        
        const resourcesCount = affectedResourcesWithDisplay.length;
        const impactType = classifyFindingImpact(finding);
        const impactLabel = {
            'compliance': 'Compliance Risk',
            'data_breach': 'Data Breach Risk', 
            'operational': 'Operational Risk',
            'access_control': 'Access Control Risk',
            'monitoring': 'Monitoring Gap',
            'encryption': 'Encryption Issue'
        }[impactType] || 'Operational Risk';

        const pciBadgeHtml = finding.pci_requirement 
            ? `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800 border border-gray-300">${finding.pci_requirement}</span>`
            : '';
        
        const card = `
            <div class="bg-white p-4 rounded-xl mb-4 border-l-4 ${borderColor} shadow-sm">
                <div class="flex flex-wrap items-center justify-between mb-2">
                    <h3 class="text-xl font-bold text-[#204071] flex-grow">${finding.name || 'Unknown finding'}</h3>
                    <div class="flex flex-wrap gap-2 mt-1 sm:mt-0">
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${severityBadgeColor}">${severityInEnglish || 'UNKNOWN'}</span>
                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-50 text-blue-700">${impactLabel}</span>
                        ${pciBadgeHtml}
                    </div>
                </div>
                <p class="text-gray-600 mt-2 text-sm">${finding.description || 'No description available'}</p>
                <div class="mt-4">
                    <details class="group">
                        <summary class="font-semibold text-gray-800 text-sm cursor-pointer list-none flex items-center">
                            <svg class="w-4 h-4 mr-2 group-open:rotate-90 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                            Affected Resources (${resourcesCount}):
                        </summary>
                        <ul class="list-disc list-inside text-sm text-gray-700 bg-gray-50 p-2 rounded-md mt-2 font-mono ml-6">
                            ${affectedResourcesHtml}
                        </ul>
                    </details>
                </div>
                <div class="mt-4">
                    <h4 class="font-semibold text-gray-800 text-sm">Recommended Solution:</h4>
                    <p class="text-gray-600 text-sm">${finding.remediation || 'No remediation information available'}</p>
                </div>
            </div>
        `;
        container.innerHTML += card;
    });
};

export const populateHealthyStatusFilter = (findings) => {
    const regionSelect = document.getElementById('healthy-status-region-filter');
    const sectionSelect = document.getElementById('healthy-status-section-filter');
    const geminiRegionSelect = document.getElementById('gemini-region-filter');
    
    if (!regionSelect || !sectionSelect) return;

    const regions = new Set();
    
    (findings || []).forEach(finding => {
        (finding.affected_resources || []).forEach(res => {
            if (typeof res === 'object' && res !== null && res.region) {
                regions.add(res.region);
            } else {
                regions.add('Global');
            }
        });
    });

    regionSelect.innerHTML = '<option value="all">All Regions</option>';
    if (geminiRegionSelect) {
        geminiRegionSelect.innerHTML = '<option value="all">All Regions</option>';
    }
    
    const sortedRegions = Array.from(regions).sort();
    sortedRegions.forEach(region => {
        const option = document.createElement('option');
        option.value = region;
        option.textContent = region;
        regionSelect.appendChild(option);
        
        if (geminiRegionSelect) {
            const geminiOption = document.createElement('option');
            geminiOption.value = region;
            geminiOption.textContent = region;
            geminiRegionSelect.appendChild(geminiOption);
        }
    });

    const sections = new Set();
    
    (findings || []).forEach(finding => {
        if (finding.section) {
            sections.add(finding.section);
        }
    });

    sectionSelect.innerHTML = '<option value="all">All Sections</option>';
    const sortedSections = Array.from(sections).sort();
    sortedSections.forEach(section => {
        const option = document.createElement('option');
        option.value = section;
        option.textContent = section;
        sectionSelect.appendChild(option);
    });

    if (findings && findings.length > 0) {
        updateFindingsCount(findings.length, findings.length);
    }
};

/**
 * Construye la vista de inventario de recursos marcados (scoped) en una tabla unificada.
 */
export const buildScopedInventoryView = () => {
    const container = document.getElementById('hs-inventory-content');
    if (!container) return;

    const scopedResources = window.scopedResources || {};
    const arns = Object.keys(scopedResources);

    if (arns.length === 0) {
        container.innerHTML = `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <p class="text-center text-gray-500">No resources have been marked as 'in scope' yet.</p>
                <p class="text-center text-xs text-gray-400 mt-2">You can mark resources in their respective sections (e.g., Compute, Databases).</p>
            </div>`;
        return;
    }

    // Unificar todos los recursos en una sola lista con un formato estándar
    const unifiedScopedItems = [];
    arns.forEach(arn => {
        const comment = scopedResources[arn].comment;
        const service = arn.split(':')[2];

        switch (service) {

        case 'ec2':
            // Verificar si es una VPC o una instancia EC2
            if (arn.includes(':vpc/')) {
                // Es una VPC
                const vpc = window.networkPoliciesApiData?.results?.vpcs.find(v => {
                    const vpcArn = `arn:aws:ec2:${v.Region}:${window.iamApiData?.metadata?.accountId || 'unknown'}:vpc/${v.VpcId}`;
                    return vpcArn === arn;
                });
                if (vpc) {
                    unifiedScopedItems.push({
                        type: 'VPC',
                        region: vpc.Region,
                        identifier: vpc.VpcId,
                        details: `CIDR: ${vpc.CidrBlock}, Default: ${vpc.IsDefault ? 'YES' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                }
            } else if (arn.includes(':instance/')) {
                // Es una instancia EC2
                const ec2Instance = window.computeApiData?.results?.ec2_instances.find(i => i.ARN === arn);
                if (ec2Instance) {
                    unifiedScopedItems.push({
                        type: 'EC2 Instance',
                        region: ec2Instance.Region,
                        identifier: ec2Instance.InstanceId,
                        details: `Public IP: ${ec2Instance.PublicIpAddress || '-'}`,
                        comment: comment,
                        arn: arn
                    });
                }
            }
            break;
            
            case 'lambda':
                const lambdaFunc = window.computeApiData?.results?.lambda_functions.find(f => f.ARN === arn);
                if (lambdaFunc) {
                    unifiedScopedItems.push({
                        type: 'Lambda Function',
                        region: lambdaFunc.Region,
                        identifier: lambdaFunc.FunctionName,
                        details: `Runtime: ${lambdaFunc.Runtime}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            case 'rds':
                // Primero, intenta encontrarlo como una instancia RDS
                const rdsInstance = window.databasesApiData?.results?.rds_instances.find(db => db.ARN === arn);
                if (rdsInstance) {
                    unifiedScopedItems.push({
                        type: 'RDS Instance',
                        region: rdsInstance.Region,
                        identifier: rdsInstance.DBInstanceIdentifier,
                        details: `Public Access: ${rdsInstance.PubliclyAccessible ? '<span class="text-red-600 font-bold">YES</span>' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                    break; // Sale si lo encuentra
                }

                // Si no es una instancia, intenta encontrarlo como un cluster Aurora
                const auroraCluster = window.databasesApiData?.results?.aurora_clusters.find(c => c.ARN === arn);
                if (auroraCluster) {
                    unifiedScopedItems.push({
                        type: 'Aurora Cluster',
                        region: auroraCluster.Region,
                        identifier: auroraCluster.ClusterIdentifier,
                        details: `Encrypted: ${auroraCluster.Encrypted ? 'YES' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                    break; // Sale si lo encuentra
                }
                
                // Finalmente, intenta encontrarlo como un cluster DocumentDB
                const docdbCluster = window.databasesApiData?.results?.documentdb_clusters.find(c => c.ARN === arn);
                if (docdbCluster) {
                    unifiedScopedItems.push({
                        type: 'DocumentDB Cluster',
                        region: docdbCluster.Region,
                        identifier: docdbCluster.ClusterIdentifier,
                        details: `Encrypted: ${docdbCluster.Encrypted ? 'YES' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            case 'dynamodb':
                const dynamoTable = window.databasesApiData?.results?.dynamodb_tables.find(t => t.ARN === arn);
                if (dynamoTable) {
                    unifiedScopedItems.push({
                        type: 'DynamoDB Table',
                        region: dynamoTable.Region,
                        identifier: dynamoTable.TableName,
                        details: `Encrypted: ${dynamoTable.Encrypted ? 'YES' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            case 'secretsmanager':
                const secret = window.secretsManagerApiData?.results?.secrets.find(s => s.ARN === arn);
                if (secret) {
                    unifiedScopedItems.push({
                        type: 'Secret',
                        region: secret.Region,
                        identifier: secret.Name,
                        details: `Rotation: ${secret.RotationEnabled ? 'Enabled' : 'Disabled'}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            case 'kms':
                const kmsKey = window.kmsApiData?.results?.keys.find(k => k.ARN === arn);
                if (kmsKey) {
                    unifiedScopedItems.push({
                        type: 'KMS Key',
                        region: kmsKey.Region,
                        identifier: kmsKey.Aliases || kmsKey.KeyId,
                        details: `Manager: ${kmsKey.KeyManager}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            case 'acm':
                const certificate = window.acmApiData?.results?.certificates.find(c => c.CertificateArn === arn);
                if (certificate) {
                    unifiedScopedItems.push({
                        type: 'ACM Certificate',
                        region: certificate.Region,
                        identifier: certificate.DomainName,
                        details: `Status: ${certificate.Status}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            
            case 'eks':
                const eksCluster = window.computeApiData?.results?.eks_clusters.find(c => c.ARN === arn);
                if (eksCluster) {
                    unifiedScopedItems.push({
                        type: 'EKS Cluster',
                        region: eksCluster.Region,
                        identifier: eksCluster.ClusterName,
                        details: `Version: ${eksCluster.Version}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            case 'ecs':
                const ecsCluster = window.computeApiData?.results?.ecs_clusters.find(c => c.ARN === arn);
                if (ecsCluster) {
                    unifiedScopedItems.push({
                        type: 'ECS Cluster',
                        region: ecsCluster.Region,
                        identifier: ecsCluster.ClusterName,
                        details: `Status: ${ecsCluster.Status}, Services: ${ecsCluster.ServicesCount}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            }
    });

    // Renderizar la tabla unificada
    container.innerHTML = renderUnifiedScopedInventoryTable(unifiedScopedItems);
    setupScopedInventoryEvents(unifiedScopedItems);
};

const renderUnifiedScopedInventoryTable = (items) => {
    let tableRows = items.map((item, index) => `
        <tr class="hover:bg-gray-50" data-item-index="${index}" data-arn="${item.arn}">
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${item.region}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm font-semibold text-gray-700">${item.type}</td>
            <td class="px-4 py-4 text-sm font-medium text-gray-800 break-all">${item.identifier}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${item.details}</td>
            <td class="px-4 py-4 text-sm text-gray-600">
                <span class="comment-display" data-index="${index}">${item.comment}</span>
                <input type="text" class="comment-input hidden w-full px-2 py-1 text-sm border border-gray-300 rounded" 
                    data-index="${index}" value="${item.comment}" />
            </td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">
                <div class="flex space-x-2">
                    <button class="edit-btn text-blue-600 hover:text-blue-800" data-index="${index}" title="Edit">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-pencil" viewBox="0 0 16 16">
                            <path d="M12.146.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1 0 .708l-10 10a.5.5 0 0 1-.168.11l-5 2a.5.5 0 0 1-.65-.65l2-5a.5.5 0 0 1 .11-.168zM11.207 2.5 13.5 4.793 14.793 3.5 12.5 1.207zm1.586 3L10.5 3.207 4 9.707V10h.5a.5.5 0 0 1 .5.5v.5h.5a.5.5 0 0 1 .5.5v.5h.293zm-9.761 5.175-.106.106-1.528 3.821 3.821-1.528.106-.106A.5.5 0 0 1 5 12.5V12h-.5a.5.5 0 0 1-.5-.5V11h-.5a.5.5 0 0 1-.468-.325"/>
                        </svg>
                    </button>
                    <button class="save-btn hidden text-green-600" data-index="${index}" title="Save">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check-lg" viewBox="0 0 16 16">
                            <path d="M12.736 3.97a.733.733 0 0 1 1.047 0c.286.289.29.756.01 1.05L7.88 12.01a.733.733 0 0 1-1.065.02L3.217 8.384a.757.757 0 0 1 0-1.06.733.733 0 0 1 1.047 0l3.052 3.093 5.4-6.425z"/>
                        </svg>
                    </button>
                    <button class="cancel-btn hidden text-gray-600" data-index="${index}" title="Cancel">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-x-lg" viewBox="0 0 16 16">
                            <path d="M2.146 2.854a.5.5 0 1 1 .708-.708L8 7.293l5.146-5.147a.5.5 0 0 1 .708.708L8.707 8l5.147 5.146a.5.5 0 0 1-.708.708L8 8.707l-5.146 5.147a.5.5 0 0 1-.708-.708L7.293 8z"/>
                        </svg>
                    </button>
                    <button class="delete-btn text-red-600 hover:text-red-800" data-index="${index}" title="Delete">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-trash" viewBox="0 0 16 16">
                            <path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m2.5 0a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5m3 .5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0z"/>
                            <path d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1zM4.118 4 4 4.059V13a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4.059L11.882 4zM2.5 3h11V2h-11z"/>
                        </svg>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');

    return `
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 mb-6">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">Scoped Resources Inventory</h3>
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Resource Identifier</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reason for Scoping</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">${tableRows}</tbody>
            </table>
        </div>
    </div>`;
};

export const buildAuditorNotesView = () => {
    const container = document.getElementById('hs-notes-content');
    if (!container) return;

    const notes = window.auditorNotes || [];

    if (notes.length === 0) {
        container.innerHTML = `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <p class="text-center text-gray-500">You haven't written any notes yet.</p>
                <p class="text-center text-xs text-gray-400 mt-2">Click the floating pen icon to start documenting your findings.</p>
            </div>`;
        return;
    }

    const groupedNotes = notes.reduce((acc, note) => {
        const key = note.view || 'general';
        if (!acc[key]) {
            acc[key] = [];
        }
        acc[key].push(note);
        return acc;
    }, {});

    let html = '<div class="space-y-6 max-w-full overflow-x-hidden">';

    for (const view in groupedNotes) {
        const notesForView = groupedNotes[view].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        const viewLink = document.querySelector(`#sidebar-nav a[data-view="${view}"]`);
        const viewTitle = viewLink ? viewLink.querySelector('span div:last-child').textContent : view.replace('-', ' ').replace(/\b\w/g, l => l.toUpperCase());

        html += `
            <div class="bg-white p-5 rounded-xl shadow-sm border border-gray-100 max-w-full overflow-x-hidden">
                <h3 class="font-bold text-lg text-[#204071] mb-4 border-b pb-2">${viewTitle}</h3>
                <div class="space-y-4 max-w-full">
        `;

        notesForView.forEach(note => {
            const date = new Date(note.timestamp).toLocaleString();
            // Quitamos el replace de <br> aquí para el truncate
            const contentPreview = note.content.replace(/\n/g, ' '); 
            
            let arnHtml = '';
            if (note.arn) {
                arnHtml = `
                    <div class="mt-2 bg-gray-100 p-2 rounded-md max-w-full overflow-hidden">
                        <code class="text-xs text-gray-700 break-all block">
                            <span class="font-semibold">Resource:</span> ${note.arn}
                        </code>
                    </div>
                `;
            }

            let controlHtml = '';
            if (note.controlId) {
                controlHtml = `
                    <div class="mt-2 bg-yellow-50 p-2 rounded-md border-l-2 border-yellow-300 max-w-full overflow-hidden">
                        <code class="text-xs text-yellow-900 break-all block">
                            <span class="font-semibold">Control:</span> ${note.controlId}
                        </code>
                    </div>
                `;
            }

            html += `
                <div class="p-4 bg-blue-50/50 border-l-4 border-blue-300 rounded-r-lg shadow-sm cursor-pointer hover:shadow-md hover:border-blue-400 transition-shadow max-w-full overflow-hidden" 
                    onclick="window.showNoteDetails(${note.id})" style="word-break: break-word;">
                    <div class="flex justify-between items-start">
                        <h4 class="text-md font-bold text-gray-800 break-words max-w-[70%]">${note.title || 'Untitled Note'}</h4>
                        <p class="text-xs text-gray-500 flex-shrink-0 ml-4">${date}</p>
                    </div>
                    <p class="text-gray-700 text-sm mt-2 break-words overflow-hidden max-w-full" style="word-break: break-word;">${contentPreview}</p>
                    ${arnHtml}
                    ${controlHtml}
                </div>
            `;

        });

        html += '</div></div>';
    }

    html += '</div>';
    container.innerHTML = html;
};

window.removeFilter = removeFilter;

// Función para entrar en modo edición
const enterEditMode = (index) => {
    const commentDisplay = document.querySelector(`[data-index="${index}"].comment-display`);
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    const editBtn = document.querySelector(`[data-index="${index}"].edit-btn`);
    const saveBtn = document.querySelector(`[data-index="${index}"].save-btn`);
    const cancelBtn = document.querySelector(`[data-index="${index}"].cancel-btn`);
    
    commentDisplay.classList.add('hidden');
    commentInput.classList.remove('hidden');
    editBtn.classList.add('hidden');
    saveBtn.classList.remove('hidden');
    cancelBtn.classList.remove('hidden');
    
    commentInput.focus();
};

// Función para guardar comentario
const saveComment = (index, items) => {
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    const newComment = commentInput.value.trim();
    const arn = items[index].arn;
    
    updateScopedResourceComment(arn, newComment);
    refreshScopedInventory();
};

// Función para cancelar edición
const cancelEdit = (index, items) => {
    const originalComment = items[index].comment;
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    commentInput.value = originalComment;
    exitEditMode(index);
};

// Función para salir del modo edición
const exitEditMode = (index) => {
    const commentDisplay = document.querySelector(`[data-index="${index}"].comment-display`);
    const commentInput = document.querySelector(`[data-index="${index}"].comment-input`);
    const editBtn = document.querySelector(`[data-index="${index}"].edit-btn`);
    const saveBtn = document.querySelector(`[data-index="${index}"].save-btn`);
    const cancelBtn = document.querySelector(`[data-index="${index}"].cancel-btn`);
    
    commentDisplay.classList.remove('hidden');
    commentInput.classList.add('hidden');
    editBtn.classList.remove('hidden');
    saveBtn.classList.add('hidden');
    cancelBtn.classList.add('hidden');
};

// Función para eliminar recurso
// 17_healthy_status.js --> Reemplaza esta función
// EN 17_healthy_status.js --> Modifica también esta función

const deleteResource = (index, items) => {
    const arn = items[index].arn;
    const resourceName = items[index].identifier;
    
    console.group(`[INVENTORY] User initiated delete for item at index ${index}`);
    console.log(`Resource Name: ${resourceName}`);
    console.log(`ARN: ${arn}`);

    if (confirm(`¿Seguro que quieres quitar "${resourceName}" del scope?`)) {
        console.log('User confirmed deletion. Calling a function named removeScopedResource...');
        
        // Llamada que estamos investigando
        window.removeResourceScope(arn); 
        
        console.log('Calling refreshScopedInventory to update the inventory table...');
        refreshScopedInventory(); 
    } else {
        console.log('User cancelled deletion.');
    }
    console.groupEnd();
};

// Función para actualizar comentario
const updateScopedResourceComment = (arn, newComment) => {
    if (window.scopedResources[arn]) {
        window.scopedResources[arn].comment = newComment;
    }
};


// Función para refrescar vista
const refreshScopedInventory = () => {
    buildScopedInventoryView();
};

const setupScopedInventoryEvents = (items) => {
    const container = document.getElementById('hs-inventory-content');
    if (!container) return;

    // Edit buttons
    container.querySelectorAll('.edit-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            enterEditMode(index);
        });
    });

    // Save buttons  
    container.querySelectorAll('.save-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            saveComment(index, items);
        });
    });

    // Cancel buttons
    container.querySelectorAll('.cancel-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            cancelEdit(index, items);
        });
    });

    // Delete buttons
    container.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            deleteResource(index, items);
        });
    });
};


// Función para procesar el template con los datos

const processTemplate = (template, data) => {
    const { clientName, findings } = data;
    
    let awsAccountId = 'N/A';

    // Primer intento: desde la variable global de IAM
    if (window.iamApiData?.metadata?.accountId) {
        awsAccountId = window.iamApiData.metadata.accountId;
    }
    // Segundo intento: desde federationApiData
    else if (window.federationApiData?.metadata?.accountId) {
        awsAccountId = window.federationApiData.metadata.accountId;
    }
    // Tercer intento: desde lastAwsAccountId
    else if (window.lastAwsAccountId) {
        awsAccountId = window.lastAwsAccountId;
    }
    // Último recurso: extraer de un ARN si está disponible
    else if (findings && findings.length > 0) {
        for (const finding of findings) {
            if (finding.affected_resources && finding.affected_resources.length > 0) {
                for (const resource of finding.affected_resources) {
                    if (typeof resource === 'object' && resource.resource && resource.resource.includes(':')) {
                        // Extraer account ID del ARN: arn:aws:service:region:account-id:resource
                        const arnParts = resource.resource.split(':');
                        if (arnParts.length >= 5 && arnParts[4]) {
                            awsAccountId = arnParts[4];
                            break;
                        }
                    }
                }
                if (awsAccountId !== 'N/A') break;
            }
        }
    }

    const regionsFromFindings = new Set();

    // Solo extraer regiones que coinciden con el filtro aplicado
    findings.forEach(finding => {
        (finding.affected_resources || []).forEach(res => {
            if (typeof res === 'object' && res !== null && res.region) {
                // Si hay un filtro de región activo, solo incluir esa región
                const currentRegionFilter = document.getElementById('report-region-filter')?.value;
                if (currentRegionFilter && currentRegionFilter !== 'all') {
                    // Solo agregar la región filtrada
                    if (res.region === currentRegionFilter || res.region === 'Global') {
                        regionsFromFindings.add(res.region);
                    }
                } else {
                    // Sin filtro, agregar todas las regiones
                    regionsFromFindings.add(res.region);
                }
            }
        });
    });


    // Mapear severidades
    const severityMap = {
        'Crítico': 'Critical',
        'Alto': 'High',
        'Medio': 'Medium',
        'Bajo': 'Low',
        'Informativo': 'Info'
    };

    // Calcular conteos de hallazgos por severidad
    const criticalCount = findings.filter(f => f.severity === 'Crítico').length;
    const highCount = findings.filter(f => f.severity === 'Alto').length;
    const mediumCount = findings.filter(f => f.severity === 'Medio').length;
    const lowCount = findings.filter(f => f.severity === 'Bajo').length;

    // CORRECCIÓN: Generar lista de assets en scope usando window.scopedResources
    const scopedResources = window.scopedResources || {};
    const unifiedScopedItems = [];
    
    Object.keys(scopedResources).forEach(arn => {
        const comment = scopedResources[arn].comment;
        const service = arn.split(':')[2];

        switch (service) {
            
            case 'ec2':
                // Verificar si es una VPC o una instancia EC2 basándonos en el ARN
                if (arn.includes(':vpc/')) {
                    // Es una VPC. Búscala en los datos de políticas de red.
                    const vpc = window.networkPoliciesApiData?.results?.vpcs.find(v => {
                        // Reconstruimos el ARN para asegurar la coincidencia
                        const vpcArn = `arn:aws:ec2:${v.Region}:${window.iamApiData?.metadata?.accountId || 'unknown'}:vpc/${v.VpcId}`;
                        return vpcArn === arn;
                    });
                    if (vpc) {
                        unifiedScopedItems.push({
                            type: 'VPC',
                            region: vpc.Region,
                            identifier: vpc.VpcId,
                            details: `CIDR: ${vpc.CidrBlock}, Default: ${vpc.IsDefault ? 'YES' : 'NO'}`,
                            comment: comment,
                            arn: arn
                        });
                    }
                } else if (arn.includes(':instance/')) {
                    // Es una instancia EC2. Mantenemos la lógica original.
                    const ec2Instance = window.computeApiData?.results?.ec2_instances.find(i => i.ARN === arn);
                    if (ec2Instance) {
                        unifiedScopedItems.push({
                            type: 'EC2 Instance',
                            region: ec2Instance.Region,
                            identifier: ec2Instance.InstanceId,
                            details: `Public IP: ${ec2Instance.PublicIpAddress || '-'}`,
                            comment: comment,
                            arn: arn
                        });
                    }
                }
                // --- FIN DE LA CORRECCIÓN ---
            break;


            
            case 'lambda':
                const lambdaFunc = window.computeApiData?.results?.lambda_functions.find(f => f.ARN === arn);
                if (lambdaFunc) {
                    unifiedScopedItems.push({
                        type: 'Lambda Function',
                        region: lambdaFunc.Region,
                        identifier: lambdaFunc.FunctionName,
                        details: `Runtime: ${lambdaFunc.Runtime}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            case 'rds':
                // Primero, intenta encontrarlo como una instancia RDS
                const rdsInstance = window.databasesApiData?.results?.rds_instances.find(db => db.ARN === arn);
                if (rdsInstance) {
                    unifiedScopedItems.push({
                        type: 'RDS Instance',
                        region: rdsInstance.Region,
                        identifier: rdsInstance.DBInstanceIdentifier,
                        details: `Public Access: ${rdsInstance.PubliclyAccessible ? '<span class="text-red-600 font-bold">YES</span>' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                    break; // Sale si lo encuentra
                }

                // Si no, intenta encontrarlo como un cluster Aurora
                const auroraCluster = window.databasesApiData?.results?.aurora_clusters.find(c => c.ARN === arn);
                if (auroraCluster) {
                    unifiedScopedItems.push({
                        type: 'Aurora Cluster',
                        region: auroraCluster.Region,
                        identifier: auroraCluster.ClusterIdentifier,
                        details: `Encrypted: ${auroraCluster.Encrypted ? 'YES' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                    break; // Sale si lo encuentra
                }
                
                // Finalmente, intenta encontrarlo como un cluster DocumentDB
                const docdbCluster = window.databasesApiData?.results?.documentdb_clusters.find(c => c.ARN === arn);
                if (docdbCluster) {
                    unifiedScopedItems.push({
                        type: 'DocumentDB Cluster',
                        region: docdbCluster.Region,
                        identifier: docdbCluster.ClusterIdentifier,
                        details: `Encrypted: ${docdbCluster.Encrypted ? 'YES' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            case 'dynamodb':
                const dynamoTable = window.databasesApiData?.results?.dynamodb_tables.find(t => t.ARN === arn);
                if (dynamoTable) {
                    unifiedScopedItems.push({
                        type: 'DynamoDB Table',
                        region: dynamoTable.Region,
                        identifier: dynamoTable.TableName,
                        details: `Encrypted: ${dynamoTable.Encrypted ? 'YES' : 'NO'}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;

            case 'secretsmanager':
                const secret = window.secretsManagerApiData?.results?.secrets.find(s => s.ARN === arn);
                if (secret) {
                    unifiedScopedItems.push({
                        type: 'Secret',
                        region: secret.Region,
                        identifier: secret.Name,
                        details: `Rotation: ${secret.RotationEnabled ? 'Enabled' : 'Disabled'}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            case 'kms':
                const kmsKey = window.kmsApiData?.results?.keys.find(k => k.ARN === arn);
                if (kmsKey) {
                    unifiedScopedItems.push({
                        type: 'KMS Key',
                        region: kmsKey.Region,
                        identifier: kmsKey.Aliases || kmsKey.KeyId,
                        details: `Manager: ${kmsKey.KeyManager}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            case 'acm':
                const certificate = window.acmApiData?.results?.certificates.find(c => c.CertificateArn === arn);
                if (certificate) {
                    unifiedScopedItems.push({
                        type: 'ACM Certificate',
                        region: certificate.Region,
                        identifier: certificate.DomainName,
                        details: `Status: ${certificate.Status}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            case 'eks':
                const eksCluster = window.computeApiData?.results?.eks_clusters.find(c => c.ARN === arn);
                if (eksCluster) {
                    unifiedScopedItems.push({
                        type: 'EKS Cluster',
                        region: eksCluster.Region,
                        identifier: eksCluster.ClusterName,
                        details: `Status: Active`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            case 'ecs':
                const ecsCluster = window.computeApiData?.results?.ecs_clusters.find(c => c.ARN === arn);
                if (ecsCluster) {
                    unifiedScopedItems.push({
                        type: 'ECS Cluster',
                        region: ecsCluster.Region,
                        identifier: ecsCluster.ClusterName,
                        details: `Status: ${ecsCluster.Status}, Services: ${ecsCluster.ServicesCount}`,
                        comment: comment,
                        arn: arn
                    });
                }
                break;
            default:
                // Para otros servicios no reconocidos, agregar información básica
                unifiedScopedItems.push({
                    type: service.toUpperCase(),
                    region: 'Multiple',
                    identifier: arn.split('/').pop() || arn.split(':').pop(),
                    details: 'See ARN for full details',
                    comment: comment,
                    arn: arn
                });
                break;
        }
    });

    const scopedAssetsList = unifiedScopedItems.length > 0
        ? `<div class="scoped-assets-section">
            <table class="scoped-assets-table">
                <thead>
                    <tr>
                        <th>Resource Type</th>
                        <th>Identifier</th>
                        <th>Region</th>
                        <th>Details</th>
                        <th>Reason for Scoping</th>
                    </tr>
                </thead>
                <tbody>
                    ${unifiedScopedItems.map(item => `
                        <tr>
                            <td><strong>${item.type}</strong></td>
                            <td class="resource-id">${item.identifier}</td>
                            <td>${item.region}</td>
                            <td>${item.details}</td>
                            <td class="scope-reason"><em>${item.comment}</em></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
           </div>`
        : '<p class="no-scoped-assets">No specific assets were marked as in-scope during this assessment.</p>';

    // Detectar si hay VPCs marcadas para incluir diagrama de arquitectura
    const scopedVpcs = unifiedScopedItems.filter(item => item.type === 'VPC');
    const hasVpcsInScope = scopedVpcs.length > 0;

    let architectureDiagramSection = '';
    if (hasVpcsInScope) {
        architectureDiagramSection = generateArchitectureDiagramSection();
    }

    // Generar sección de notas del auditor
    const auditorNotes = window.auditorNotes || [];


    const auditorNotesSection = auditorNotes.length > 0
        ? `<div class="notes-section">
            <h2>Auditor Notes</h2>
            ${auditorNotes.map(note => `
                <div class="individual-note">
                    <h3>${note.title || 'Untitled Note'}</h3>
                    <div class="note-meta-info">
                        <div class="note-meta-item">
                            <div class="note-meta-label">Date Created</div>
                            <div class="note-meta-value">${note.timestamp ? new Date(note.timestamp).toLocaleDateString() : 'N/A'}</div>
                        </div>
                        ${note.arn ? `
                        <div class="note-meta-item">
                            <div class="note-meta-label">Related Resource</div>
                            <div class="note-meta-value">${note.arn}</div>
                        </div>
                        ` : ''}
                        ${note.controlId ? `
                        <div class="note-meta-item">
                            <div class="note-meta-label">Control ID</div>
                            <div class="note-meta-value">${note.controlId}</div>
                        </div>
                        ` : ''}
                    </div>
                    <div class="note-content-section">
                        <p>${note.content || ''}</p>
                    </div>
                </div>
            `).join('')}
        </div>`
        : '';

    // Generar tabla resumen de findings
    const findingsSummaryRows = findings.map(finding => {
        const severity = severityMap[finding.severity] || finding.severity;
        const severityClass = severity.toLowerCase().replace('crítico', 'critical');
        const affectedCount = (finding.affected_resources && finding.affected_resources.length) || 0;
        
        return `
            <tr>
                <td>
                    <div class="finding-name">${finding.name || 'Unknown Finding'}</div>
                </td>
                <td><span class="severity-${severityClass}">${severity}</span></td>
                <td><span class="category-badge">${finding.section || 'General'}</span></td>
                <td><span class="affected-count">${affectedCount}</span></td>
            </tr>
        `;
    }).join('');

    // Generar secciones detalladas individuales para cada finding
    const detailedFindingsSections = findings.map((finding, index) => {
        const severity = severityMap[finding.severity] || finding.severity;
        const severityClass = severity.toLowerCase().replace('crítico', 'critical');
        const affectedResources = finding.affected_resources || [];
        const resourcesHtml = affectedResources.map(resource => {
            if (typeof resource === 'object' && resource.resource && resource.region) {
                return `<li>${resource.resource} (${resource.region})</li>`;
            } else if (typeof resource === 'string') {
                return `<li>${resource} (Global)</li>`;
            } else {
                return `<li>Unknown Resource</li>`;
            }
        }).join('');

        const resourcesSection = resourcesHtml 
            ? `<div class="finding-resources">
                <h4>Affected Resources (${affectedResources.length})</h4>
                <ul class="resource-list">
                    ${resourcesHtml}
                </ul>
               </div>`
            : `<div class="finding-resources">
                <h4>Affected Resources</h4>
                <p class="description-text">No specific resources identified</p>
               </div>`;
        return `
            <div class="individual-finding">
                <h3>Finding ${index + 1}: ${finding.name || 'Unknown Finding'}</h3>
                
                <div class="finding-meta">
                    <div class="finding-meta-item">
                        <div class="finding-meta-label">Severity</div>
                        <div class="finding-meta-value severity-${severityClass}">${severity}</div>
                    </div>
                    <div class="finding-meta-item">
                        <div class="finding-meta-label">Category</div>
                        <div class="finding-meta-value category-badge">${finding.section || 'General'}</div>
                    </div>
                    <div class="finding-meta-item">
                        <div class="finding-meta-label">Rule ID</div>
                        <div class="finding-meta-value finding-rule">${finding.rule_id || 'N/A'}</div>
                    </div>
                </div>
                <div class="finding-description">
                    <div class="description-text">
                        ${finding.description || 'No description available'}
                    </div>
                </div>
                ${resourcesSection}
                <div class="finding-remediation">
                    <h4>Recommended Solution</h4>
                    <div class="description-text">
                        ${finding.remediation || 'No remediation information available'}
                    </div>
                </div>
            </div>
        `;
    }).join('');

    // Calcular datos para los gráficos
    const severityCounts = {
        critical: findings.filter(f => f.severity === 'Crítico').length,
        high: findings.filter(f => f.severity === 'Alto').length,
        medium: findings.filter(f => f.severity === 'Medio').length,
        low: findings.filter(f => f.severity === 'Bajo').length
    };

    const maxSeverityCount = Math.max(...Object.values(severityCounts));

// Generar datos para el gráfico stacked
    const sectionCounts = {};
    findings.forEach(finding => {
        const section = finding.section || 'Other';
        if (!sectionCounts[section]) {
            sectionCounts[section] = { critical: 0, high: 0, medium: 0, low: 0 };
        }
        
        switch(finding.severity) {
            case 'Crítico': sectionCounts[section].critical++; break;
            case 'Alto': sectionCounts[section].high++; break;
            case 'Medio': sectionCounts[section].medium++; break;
            case 'Bajo': sectionCounts[section].low++; break;
        }
    });

    // Generar HTML para el stacked chart
    let stackedChartData = '';
    const maxSectionTotal = Math.max(...Object.values(sectionCounts).map(s => s.critical + s.high + s.medium + s.low));

    Object.entries(sectionCounts)
        .sort(([,a], [,b]) => (b.critical + b.high + b.medium + b.low) - (a.critical + a.high + a.medium + a.low))
        .forEach(([section, counts]) => {
            const total = counts.critical + counts.high + counts.medium + counts.low;
            const barWidth = (total / maxSectionTotal) * 100;
            
            // Calcular porcentajes para cada segmento
            const criticalWidth = (counts.critical / total) * barWidth;
            const highWidth = (counts.high / total) * barWidth;
            const mediumWidth = (counts.medium / total) * barWidth;
            const lowWidth = (counts.low / total) * barWidth;
            
            stackedChartData += `
                <div class="stack-bar-row">
                    <div class="stack-bar" style="height: ${(total / maxSectionTotal) * 150}px; position: relative;">
                        <div class="stack-total">${total}</div>
                        ${counts.low > 0 ? `<div class="stack-segment severity-low" style="height: ${(counts.low / total) * ((total / maxSectionTotal) * 150)}px">${counts.low}</div>` : ''}
                        ${counts.medium > 0 ? `<div class="stack-segment severity-medium" style="height: ${(counts.medium / total) * ((total / maxSectionTotal) * 150)}px">${counts.medium}</div>` : ''}
                        ${counts.high > 0 ? `<div class="stack-segment severity-high" style="height: ${(counts.high / total) * ((total / maxSectionTotal) * 150)}px">${counts.high}</div>` : ''}
                        ${counts.critical > 0 ? `<div class="stack-segment severity-critical" style="height: ${(counts.critical / total) * ((total / maxSectionTotal) * 150)}px">${counts.critical}</div>` : ''}
                    </div>
                    <div class="stack-label">${section}</div>
                </div>
            `;
        });

    // Reemplazar placeholders
    template = template.replace(/{{STACKED_CHART_DATA}}/g, stackedChartData);



    // Reemplazar placeholders
    return template
        .replace(/{{CLIENT_NAME}}/g, clientName)
        .replace(/{{REPORT_DATE}}/g, new Date().toLocaleDateString())
        .replace(/{{AWS_ACCOUNT_ID}}/g, awsAccountId || 'N/A')
        .replace(/{{TOTAL_FINDINGS}}/g, findings.length.toString())
        .replace(/{{CRITICAL_COUNT}}/g, criticalCount)
        .replace(/{{HIGH_COUNT}}/g, highCount)
        .replace(/{{MEDIUM_COUNT}}/g, mediumCount)
        .replace(/{{LOW_COUNT}}/g, lowCount)
        .replace(/{{REGIONS_INCLUDED}}/g, regionsFromFindings.size > 0 ? Array.from(regionsFromFindings).sort().join(', ') : 'No regions in filtered results')
        .replace(/{{VPCS_INCLUDED}}/g, 'All VPCs in scope')
        .replace(/{{SCOPED_ASSETS_LIST}}/g, scopedAssetsList)
        .replace(/{{SCOPED_ASSETS_COUNT}}/g, unifiedScopedItems.length.toString())
        .replace(/{{FINDINGS_SUMMARY_ROWS}}/g, findingsSummaryRows)
        .replace(/{{DETAILED_FINDINGS_SECTIONS}}/g, detailedFindingsSections)
        .replace(/{{AUDITOR_NOTES_SECTION}}/g, auditorNotesSection)
        .replace(/{{ARCHITECTURE_DIAGRAM_SECTION}}/g, architectureDiagramSection);
};




// Función para generar y descargar PDF
const generateAndDownloadPDF = async (htmlContent, filename) => {
    try {
        // Crear una ventana nueva para el contenido
        const printWindow = window.open('', '_blank');
        printWindow.document.write(htmlContent);
        printWindow.document.close();
        
        // Esperar a que cargue el contenido
        await new Promise(resolve => {
            printWindow.onload = resolve;
            setTimeout(resolve, 1000); // fallback
        });
        
        // Abrir diálogo de impresión (usuario puede "Guardar como PDF")
        printWindow.print();
        
        // Cerrar ventana después de un momento
        setTimeout(() => {
            printWindow.close();
        }, 1000);
        
        log('PDF generation window opened. Use "Save as PDF" in the print dialog.', 'success');
        
    } catch (error) {
        console.error('Error generating PDF:', error);
        throw new Error(`Failed to generate PDF: ${error.message}`);
    }
};

// REEMPLAZA LA FUNCIÓN ENTERA
const removeResourceFromFinding = (findingIndex, resourceIndex) => {
    const currentlyDisplayedFindings = getCurrentlyDisplayedFindings();
    const findingToEdit = currentlyDisplayedFindings[findingIndex];
    
    if (!findingToEdit || !findingToEdit.affected_resources) return;
    
    // ¡CAMBIO CLAVE! Buscamos el hallazgo en la lista editable para modificar sus recursos.
    const editableIndex = window.editableFindings.findIndex(f => 
        f.rule_id === findingToEdit.rule_id && 
        f.name === findingToEdit.name && 
        f.section === findingToEdit.section
    );
    
    if (editableIndex !== -1) {
        const originalFinding = window.editableFindings[editableIndex];
        if (originalFinding.affected_resources && originalFinding.affected_resources[resourceIndex]) {
            originalFinding.affected_resources.splice(resourceIndex, 1);
            
            findingToEdit.affected_resources.splice(resourceIndex, 1);
            
            const resourcesList = document.getElementById('affected-resources-list');
            if (resourcesList) {
                updateResourcesListInModal(findingToEdit.affected_resources);
            }
            
            const label = document.querySelector('#edit-finding-modal label');
            if (label) {
                label.textContent = `Affected Resources (${findingToEdit.affected_resources.length})`;
            }
        }
    }
};

const updateResourcesListInModal = (resources) => {
    const container = document.getElementById('affected-resources-list');
    if (!container) return;
    
    if (resources.length === 0) {
        container.innerHTML = '<p class="text-gray-500 text-sm">No resources remaining</p>';
        return;
    }
    
    const resourcesHtml = resources.map((resource, resourceIndex) => {
        let resourceName, regionName;
        
        if (typeof resource === 'object' && resource.resource && resource.region) {
            resourceName = resource.resource;
            regionName = resource.region;
        } else if (typeof resource === 'string') {
            resourceName = resource;
            regionName = 'Global';
        } else {
            resourceName = 'Unknown Resource';
            regionName = 'Global';
        }
        
        return `
            <div class="resource-item flex items-center justify-between p-2 bg-gray-50 rounded border" data-resource-index="${resourceIndex}">
                <div class="flex-1 min-w-0">
                    <div class="text-sm font-medium text-gray-900 truncate">${resourceName}</div>
                    <div class="text-xs text-gray-500">${regionName}</div>
                </div>
                <button class="remove-resource-btn ml-2 text-red-600 hover:text-red-800 p-1" data-resource-index="${resourceIndex}" title="Remove Resource">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
        `;
    }).join('');
    
    container.innerHTML = resourcesHtml;
    
    // Re-agregar event listeners
    container.querySelectorAll('.remove-resource-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const resourceIndex = parseInt(e.currentTarget.getAttribute('data-resource-index'));
            const findingIndex = parseInt(document.querySelector('[onclick*="saveFindingChanges"]').onclick.toString().match(/\d+/)[0]);
            removeResourceFromFinding(findingIndex, resourceIndex);
        });
    });
};

// REEMPLAZA LA FUNCIÓN ENTERA
const applyReportFilters = () => {
    const regionValue = document.getElementById('report-region-filter')?.value || 'all';
    const severityValue = document.getElementById('report-severity-filter')?.value || 'all';
    const sectionValue = document.getElementById('report-section-filter')?.value || 'all';
    const impactValue = document.getElementById('report-impact-filter')?.value || 'all';

    // ¡CAMBIO CLAVE! Se filtra sobre la copia editable.
    let filteredFindings = [...(window.editableFindings || [])];

    if (regionValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => {
            const resources = finding.affected_resources || [];
            if (resources.length === 0) return false;

            return resources.some(res => {
                if (typeof res === 'object' && res !== null) {
                    const region = res.region || 'Global';
                    return region === regionValue || region === 'Global';
                } else if (typeof res === 'string') {
                    return regionValue === 'Global';
                }
                return false;
            });
        });
    }

    if (severityValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            finding.severity === severityValue
        );
    }

    if (sectionValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            finding.section === sectionValue
        );
    }

    if (impactValue !== 'all') {
        filteredFindings = filteredFindings.filter(finding => 
            classifyFindingImpact(finding) === impactValue
        );
    }

    updateFindingsCount(filteredFindings.length, (window.editableFindings || []).length, 'report-findings-count-display');
    updateActiveFiltersDisplay('report');
    renderFindingsSelectionList(filteredFindings);
};

const resetReportFilters = () => {
    const filters = [
        'report-region-filter', 
        'report-severity-filter', 
        'report-section-filter', 
        'report-impact-filter'
    ];

    filters.forEach(filterId => {
        const filter = document.getElementById(filterId);
        if (filter) {
            filter.value = 'all';
        }
    });

    setTimeout(applyReportFilters, 50);
};

// AÑADE ESTA FUNCIÓN COMPLETA
const resetFindingEdits = () => {
    if (confirm('¿Estás seguro de que quieres descartar todas las ediciones y restaurar los hallazgos originales?')) {
        // 1. Restaura la copia editable a partir de la fuente original
        window.editableFindings = JSON.parse(JSON.stringify(window.lastHealthyStatusFindings || []));
        
        // 2. Vuelve a aplicar los filtros y a dibujar la lista en pantalla
        applyReportFilters(); 
        
        log('Las ediciones de los hallazgos han sido reiniciadas.', 'info');
    }
};

const generateArchitectureDiagramSection = () => {
    if (!window.networkPoliciesApiData || !window.computeApiData || !window.databasesApiData) {
        return '';
    }

    const { vpcs, subnets } = window.networkPoliciesApiData.results;
    const { ec2_instances, lambda_functions } = window.computeApiData.results;
    const { rds_instances, aurora_clusters } = window.databasesApiData.results;
    const nat_gateways = window.networkPoliciesApiData.results.nat_gateways || [];

    // Filtrar solo las VPCs que están marcadas como "in scope"
    const scopedVpcs = vpcs.filter(vpc => {
        const vpcArn = `arn:aws:ec2:${vpc.Region}:${window.iamApiData?.metadata?.accountId || 'unknown'}:vpc/${vpc.VpcId}`;
        return window.scopedResources[vpcArn];
    });

    if (scopedVpcs.length === 0) return '';

    // Generar diagrama adaptado para PDF
    const diagramHtml = renderVpcDiagramForPdf(scopedVpcs, subnets, ec2_instances, lambda_functions, rds_instances, aurora_clusters, nat_gateways);

    return `
        <div class="architecture-section">
            <h2>Architecture Diagram</h2>
            <p>Network architecture for VPCs marked as in-scope during this assessment.</p>
            ${diagramHtml}
        </div>
    `;
};

const renderVpcDiagramForPdf = (vpcs, subnets, instances, lambdas, rdsInstances, auroraClusters, natGateways) => {
    if (!vpcs || vpcs.length === 0) return '<p>No VPCs were found to display in the diagram.</p>';
    
    let diagramHtml = '<div class="vpc-diagrams">';

    vpcs.forEach(vpc => {
        const vpcSubnets = subnets.filter(s => s.VpcId === vpc.VpcId);
        const vpcInstances = instances.filter(i => vpcSubnets.some(s => s.SubnetId === i.SubnetId));
        const vpcLambdas = lambdas.filter(l => l.VpcConfig && l.VpcConfig.VpcId === vpc.VpcId);
        const vpcRds = rdsInstances.filter(r => r.VpcId === vpc.VpcId);
        const vpcAurora = auroraClusters.filter(a => a.VpcId === vpc.VpcId);

        const totalResources = vpcInstances.length + vpcLambdas.length + vpcRds.length + vpcAurora.length;

        diagramHtml += `<div class="vpc-diagram">
            <h3>${vpc.Tags['Name'] || vpc.VpcId}</h3>
            <div class="vpc-info">${vpc.Region} | ${vpc.VpcId} | ${vpc.CidrBlock} | ${totalResources} resources</div>
            <div class="subnets-grid">`;

        vpcSubnets.forEach(subnet => {
            diagramHtml += `<div class="subnet-box">
                <div class="subnet-header">${subnet.Tags['Name'] || subnet.SubnetId}</div>
                <div class="subnet-cidr">${subnet.CidrBlock}</div>
                <div class="resources">`;
            
            // EC2 Instances
            const subnetInstances = vpcInstances.filter(i => i.SubnetId === subnet.SubnetId);
            subnetInstances.forEach(instance => {
                const state = instance.State.toLowerCase();
                const stateClass = (state === 'running') ? 'resource-running' : 'resource-stopped';
                diagramHtml += `<div class="resource ${stateClass}">EC2: ${instance.Tags['Name'] || instance.InstanceId}</div>`;
            });

            // Lambda Functions
            const subnetLambdas = vpcLambdas.filter(l => l.VpcConfig?.SubnetIds?.includes(subnet.SubnetId));
            subnetLambdas.forEach(lambda => {
                diagramHtml += `<div class="resource resource-lambda">Lambda: ${lambda.FunctionName}</div>`;
            });

            // NAT Gateways
            const subnetNatGateways = natGateways.filter(nat => nat.SubnetId === subnet.SubnetId);
            subnetNatGateways.forEach(nat => {
                const natName = nat.Tags['Name'] || nat.NatGatewayId;
                diagramHtml += `<div class="resource resource-nat">NAT: ${natName}</div>`;
            });

            if (subnetInstances.length === 0 && subnetLambdas.length === 0 && subnetNatGateways.length === 0) {
                diagramHtml += '<div class="no-resources">No resources</div>';
            }

            diagramHtml += `</div></div>`;
        });

        diagramHtml += `</div></div>`;
    });

    diagramHtml += '</div>';
    return diagramHtml;
};