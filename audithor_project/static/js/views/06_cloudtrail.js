/**
 * 06_cloudtrail.js
 * Contiene toda la lógica para construir y renderizar la vista de CloudTrail.
 */

// --- IMPORTACIONES ---
import { handleTabClick, renderSecurityHubFindings, log } from '../utils.js';


window.trailAlertsData = null;
window.rulesStatus = null;

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
                <a href="#" data-tab="ct-trailalerts-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">TrailAlerts</a>
                <a href="#" data-tab="ct-lookup-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Log Finder</a>
                <a href="#" data-tab="ct-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${cloudtrailFindings.length})</a>
            </nav>
        </div>
        <div id="cloudtrail-tab-content-container">
            <div id="ct-summary-content" class="cloudtrail-tab-content">${createCloudtrailSummaryCardsHtml()}</div>
            <div id="ct-trails-content" class="cloudtrail-tab-content hidden">${renderCloudtrailTrailsView(trails)}</div>
            <div id="ct-events-content" class="cloudtrail-tab-content hidden">${renderCloudtrailEventsTable(events)}</div>
            <div id="ct-trailguard-content" class="cloudtrail-tab-content hidden"></div>
            <div id="ct-trailalerts-content" class="cloudtrail-tab-content hidden"></div>
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

    const trailAlertsContainer = document.getElementById('ct-trailalerts-content');
    trailAlertsContainer.innerHTML = renderTrailAlertsView();
    initializeTrailAlertsEventListeners();
    loadRulesStatus();
    
    // NUEVO: Restaurar datos de TrailAlerts si existen datos importados
    setTimeout(() => {
        restoreTrailAlertsFromImport();
    }, 100); // Pequeño delay para asegurar que el DOM está listo
};


const renderSNSDetails = (snsTargets, context = 'eventbridge') => {
    if (!snsTargets || snsTargets.length === 0) {
        return '<p class="text-xs text-gray-500 italic">No SNS targets configured</p>';
    }
    
    let html = `<div class="mt-4 p-3 bg-green-100 border border-green-300 rounded">
        <h5 class="font-semibold text-sm text-green-800 mb-2">
            SNS Notifications (${snsTargets.length})
        </h5>
        <div class="space-y-3">`;
    
    snsTargets.forEach(sns => {
        const topicName = sns.TopicName || sns.TopicArn?.split(':').pop() || 'Unknown';
        
        html += `<div class="bg-green-50 border border-green-200 rounded p-2">
            <p class="text-xs font-semibold text-green-800">
                ${sns.DisplayName && sns.DisplayName !== topicName ? 
                    `${sns.DisplayName} (${topicName})` : 
                    `Topic: ${topicName}`
                }
            </p>`;
        
        if (sns.RuleName) {
            html += `<p class="text-xs text-gray-600 italic">via rule: ${sns.RuleName}</p>`;
        }
        
        // Mostrar subscripciones si están disponibles
        if (sns.Subscriptions && sns.Subscriptions.length > 0) {
            html += `<div class="mt-2 space-y-1">
                <p class="text-xs font-medium text-gray-700">
                    Subscriptions (${sns.SubscriptionCount}):
                </p>`;
            
            sns.Subscriptions.forEach(subscription => {
                const statusColor = subscription.Status === 'Confirmed' ? 'text-green-600' : 'text-orange-600';
                
                html += `<div class="ml-2 text-xs">
                    <span class="font-mono bg-gray-100 px-1 rounded">
                        ${subscription.Protocol}
                    </span>
                    <span class="ml-1 text-gray-700">${subscription.Endpoint}</span>
                    <span class="ml-1 ${statusColor} font-medium">
                        (${subscription.Status})
                    </span>
                </div>`;
            });
            
            html += `</div>`;
        } else if (sns.SubscriptionCount === 0) {
            html += `<p class="text-xs text-gray-500 mt-1 italic">
                No subscriptions or unable to retrieve
            </p>`;
        }
        
        if (sns.Error) {
            html += `<p class="text-xs text-red-600 mt-1">
                Error: ${sns.Error}
            </p>`;
        }
        
        html += `</div>`;
    });
    
    html += `</div></div>`;
    return html;
};


// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const renderCloudtrailFlowDiagram = (trailFlows) => {
    if (!trailFlows || trailFlows.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No CloudTrail configurations were found to display a data flow.</p></div>';
    }

    let diagramHtml = '<div class="space-y-8">';
    
    // Recopilar todas las reglas de EventBridge por región (evitar duplicados)
    const eventBridgeRulesByRegion = {};
    trailFlows.forEach(trail => {
        if (trail.DirectCloudTrailEventBridge && trail.DirectCloudTrailEventBridge.CloudTrailEventBridgeEnabled) {
            const rules = trail.DirectCloudTrailEventBridge.Rules || [];
            rules.forEach(rule => {
                const region = rule.Region || trail.Region;
                if (!eventBridgeRulesByRegion[region]) {
                    eventBridgeRulesByRegion[region] = [];
                }
                // Evitar duplicados por nombre de regla
                const ruleExists = eventBridgeRulesByRegion[region].some(existingRule => existingRule.Name === rule.Name);
                if (!ruleExists) {
                    eventBridgeRulesByRegion[region].push(rule);
                }
            });
        }
    });

    // SECCIÓN 1: REGLAS EVENTBRIDGE (INDEPENDIENTES)
const hasAnyEventBridgeRules = Object.keys(eventBridgeRulesByRegion).length > 0;
    
    if (hasAnyEventBridgeRules) {
        diagramHtml += `
        <div class="bg-white border border-gray-200 rounded-xl shadow-md">
            <div class="bg-gradient-to-r from-purple-50 to-indigo-50 p-4 border-b border-gray-200 rounded-t-xl">
                <h3 class="text-xl font-bold text-[#204071]">EventBridge Rules (Independent)</h3>
                <p class="text-sm text-gray-600 mt-1">Regional rules that process CloudTrail events in real-time, independent of trail configurations</p>
            </div>
            <div class="p-4">
        `;

        // Mostrar reglas por región
        Object.entries(eventBridgeRulesByRegion).forEach(([region, rules]) => {
            // Calcular SNS targets usando los nuevos detalles completos
            const allSNSTargets = rules.reduce((acc, rule) => {
                const ruleSNSTargets = rule.SNSTargets || [];
                return acc.concat(ruleSNSTargets);
            }, []);

            diagramHtml += `
                <div class="mb-6 bg-purple-50 border border-purple-200 rounded-lg p-4">
                    <div class="flex items-center justify-between mb-3">
                        <h4 class="text-lg font-semibold text-purple-800">
                            Region: ${region} (${rules.length} rules)
                        </h4>
                        ${allSNSTargets.length > 0 ? 
                            `<div class="flex items-center space-x-2">
                                <div class="w-3 h-3 bg-green-500 rounded-full"></div>
                                <span class="text-green-700 text-sm font-medium">Alert Flow Active</span>
                            </div>` :
                            `<div class="flex items-center space-x-2">
                                <div class="w-3 h-3 bg-yellow-500 rounded-full"></div>
                                <span class="text-yellow-700 text-sm font-medium">No SNS Configured</span>
                            </div>`
                        }
                    </div>
                    
                    <div class="space-y-3">
            `;

            rules.forEach(rule => {
                const snsTargets = rule.SNSTargets || []; // USAR NUEVOS DETALLES COMPLETOS
                
                diagramHtml += `
                    <div class="bg-purple-100 border border-purple-300 rounded p-3">
                        <div class="flex items-center justify-between mb-2">
                            <p class="font-semibold text-gray-800 text-sm">Rule: ${rule.Name}</p>
                            <span class="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded">CloudTrail Events</span>
                        </div>
                        <p class="text-gray-600 text-xs mb-2">Processes CloudTrail API events in real-time</p>
                `;

                if (rule.Targets && rule.Targets.length > 0) {
                    diagramHtml += `<div class="mt-2 space-y-1">`;
                    rule.Targets.forEach(target => {
                        const arn = target.Arn;
                        const targetType = arn.includes(':lambda:') ? 'Lambda' :
                                         arn.includes(':sqs:') ? 'SQS' :
                                         arn.includes(':sns:') ? 'SNS' : 'Other';
                        const targetName = arn.split(':').pop();
                        const dotColor = targetType === 'SNS' ? 'bg-green-400' : 
                                        targetType === 'Lambda' ? 'bg-blue-400' : 'bg-gray-400';
                        
                        diagramHtml += `<div class="pl-3 text-xs text-gray-700 flex items-center">
                            <span class="inline-block w-2 h-2 rounded-full ${dotColor} mr-2"></span>
                            ${targetType}: ${targetName}
                        </div>`;
                    });
                    diagramHtml += `</div>`;
                }

                // AGREGAR DETALLES COMPLETOS DE SNS
                if (snsTargets.length > 0) {
                    diagramHtml += renderSNSDetails(snsTargets, 'eventbridge_independent');
                }

                diagramHtml += `</div>`;
            });

            diagramHtml += `</div></div>`;
        });

        diagramHtml += `</div></div>`;
    }

    // SECCIÓN 2: CONFIGURACIÓN DE TRAILS CLOUDTRAIL
    diagramHtml += `
    <div class="bg-white border border-gray-200 rounded-xl shadow-md">
        <div class="bg-gradient-to-r from-blue-50 to-cyan-50 p-4 border-b border-gray-200 rounded-t-xl">
            <h3 class="text-xl font-bold text-[#204071]">CloudTrail Configuration Flow</h3>
            <p class="text-sm text-gray-600 mt-1">Trail configurations showing where CloudTrail logs are stored and processed</p>
        </div>
        <div class="p-4 space-y-6">
    `;

    // Mostrar cada trail
    trailFlows.forEach(trail => {
        // Determinar si hay flujo tradicional EventBridge (S3)
        const hasS3EventBridgeFlow = trail.EventBridgeFlow && trail.EventBridgeFlow.S3EventBridgeEnabled;
        const hasCompleteS3Flow = hasS3EventBridgeFlow && trail.EventBridgeFlow.CompleteFlow;

        diagramHtml += `
            <div class="bg-gray-50 border border-gray-300 rounded-lg p-4">
                <div class="mb-4">
                    <h4 class="text-lg font-semibold text-[#204071]">${trail.TrailName}</h4>
                    <p class="text-sm text-gray-500 font-mono">${trail.Region} | ${trail.TrailArn}</p>
                </div>
        `;

        // Indicador de estado del flujo para el trail
        if (hasCompleteS3Flow) {
            diagramHtml += `
                <div class="mb-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                    <div class="flex items-center space-x-2">
                        <div class="w-3 h-3 bg-blue-500 rounded-full"></div>
                        <span class="text-blue-800 font-semibold text-sm">S3 EventBridge Flow Active</span>
                    </div>
                    <p class="text-blue-700 text-xs mt-1">Trail → S3 → EventBridge → SNS</p>
                </div>
            `;
        } else if (hasS3EventBridgeFlow) {
            diagramHtml += `
                <div class="mb-4 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                    <div class="flex items-center space-x-2">
                        <div class="w-3 h-3 bg-yellow-500 rounded-full"></div>
                        <span class="text-yellow-800 font-semibold text-sm">Partial S3 EventBridge Flow</span>
                    </div>
                    <p class="text-yellow-700 text-xs mt-1">Trail → S3 → EventBridge (no SNS configured)</p>
                </div>
            `;
        } else {
            diagramHtml += `
                <div class="mb-4 p-3 bg-gray-50 border border-gray-200 rounded-lg">
                    <div class="flex items-center space-x-2">
                        <div class="w-3 h-3 bg-gray-400 rounded-full"></div>
                        <span class="text-gray-600 font-semibold text-sm">Basic Trail Logging</span>
                    </div>
                    <p class="text-gray-500 text-xs mt-1">Standard trail configuration without EventBridge</p>
                </div>
            `;
        }

        // Grid de destinos (S3 y CloudWatch)
        diagramHtml += `<div class="grid grid-cols-1 lg:grid-cols-2 gap-4">`;

        // S3 Destination
        if (trail.S3Destination) {
            const s3 = trail.S3Destination;
            diagramHtml += `
            <div class="bg-slate-50 border border-blue-200 rounded-lg p-3 flex flex-col">
                <div class="border-b border-blue-200 pb-2 mb-3">
                    <p class="font-bold text-sm text-blue-800">S3 Bucket: ${s3.BucketName}</p>
                </div>
                <div class="space-y-2 flex-grow">
            `;

            // EventBridge habilitado para S3
            if (hasS3EventBridgeFlow) {
                diagramHtml += `<div class="bg-orange-100 border border-orange-300 p-2 rounded-md text-xs">
                    <p class="font-semibold text-orange-800">S3 EventBridge Enabled</p>
                    <p class="text-gray-600">S3 events sent to EventBridge</p>
                </div>`;
            }

            // Notificaciones S3 tradicionales
            if (s3.Notifications && s3.Notifications.length > 0) {
                s3.Notifications.forEach(notif => {
                    diagramHtml += `<div class="bg-blue-100 border border-blue-300 p-2 rounded-md text-xs">
                        <p class="font-semibold text-gray-800 truncate" title="${notif.Target}">
                            ${notif.Type}: ${notif.Target.split(':').pop()}
                        </p>
                    </div>`;
                });
            } else if (!hasS3EventBridgeFlow) {
                diagramHtml += '<p class="text-center text-xs text-gray-400 py-4">No notifications configured</p>';
            }

            diagramHtml += `</div></div>`;
        } else {
            diagramHtml += '<div class="bg-gray-50 border border-gray-200 rounded-lg p-3 flex items-center justify-center"><p class="text-xs text-gray-400">No S3 destination</p></div>';
        }

        // CloudWatch Destination (sin cambios - ya funciona bien)
        if (trail.CloudWatchDestination) {
            const cw = trail.CloudWatchDestination;
            diagramHtml += `
            <div class="bg-slate-50 border border-purple-200 rounded-lg p-3 flex flex-col">
                <div class="border-b border-purple-200 pb-2 mb-3">
                    <p class="font-bold text-sm text-purple-800">CloudWatch Log Group: ${cw.LogGroupName}</p>
                </div>
                <div class="space-y-2 flex-grow">
            `;

            if (cw.Subscriptions && cw.Subscriptions.length > 0) {
                cw.Subscriptions.forEach(sub => {
                    diagramHtml += `<div class="bg-purple-100 border border-purple-300 p-2 rounded-md text-xs">
                        <p class="font-semibold text-gray-800 truncate" title="${sub.Target}">
                            ${sub.Type}: ${sub.Target.split(':').pop()}
                        </p>
                    </div>`;
                });
            } else {
                diagramHtml += '<p class="text-center text-xs text-gray-400">No subscriptions found</p>';
            }
            
            if (cw.MetricFilters && cw.MetricFilters.length > 0) {
                diagramHtml += '<hr class="my-2 border-purple-200">';
                cw.MetricFilters.forEach(mf => {
                   diagramHtml += `<div class="bg-purple-100 border border-purple-300 p-2 rounded-md text-xs mb-2">
                       <p class="font-semibold text-gray-800 truncate" title="${mf.FilterName}">
                           Metric Filter: ${mf.FilterName}
                       </p>`;
                   
                   if (mf.Alarms && mf.Alarms.length > 0) {
                       mf.Alarms.forEach(alarm => {
                           const alarmName = typeof alarm === 'string' ? alarm : alarm.AlarmName;
                           const alarmState = typeof alarm === 'object' ? alarm.State : 'UNKNOWN';
                           const snsTopics = typeof alarm === 'object' ? alarm.SNSTopics : [];
                           
                           diagramHtml += `<div class="pl-3 mt-2 border-l-2 border-purple-400">
                               <p class="text-gray-700 font-medium truncate" title="${alarmName}">
                                   Alarm: ${alarmName}
                               </p>`;
                           
                           if (typeof alarm === 'object') {
                               const stateColor = alarmState === 'OK' ? 'text-green-600' : 
                                                alarmState === 'ALARM' ? 'text-red-600' : 'text-yellow-600';
                               diagramHtml += `<p class="text-xs ${stateColor} ml-2">
                                   State: ${alarmState}
                               </p>`;
                           }
                           
                           // Mostrar SNS Topics y subscriptions
                           if (snsTopics && snsTopics.length > 0) {
                               snsTopics.forEach(snsDetail => {
                                   diagramHtml += `<div class="ml-4 mt-2 p-2 bg-green-50 border border-green-200 rounded">
                                       <p class="text-xs font-semibold text-green-800">
                                           SNS Topic: ${snsDetail.TopicName}
                                       </p>`;
                                   
                                   if (snsDetail.DisplayName && snsDetail.DisplayName !== snsDetail.TopicName) {
                                       diagramHtml += `<p class="text-xs text-gray-600 italic">
                                           Display Name: ${snsDetail.DisplayName}
                                       </p>`;
                                   }
                                   
                                   if (snsDetail.Subscriptions && snsDetail.Subscriptions.length > 0) {
                                       diagramHtml += `<div class="mt-2 space-y-1">
                                           <p class="text-xs font-medium text-gray-700">
                                               Subscriptions (${snsDetail.SubscriptionCount}):
                                           </p>`;
                                       
                                       snsDetail.Subscriptions.forEach(subscription => {
                                           const statusColor = subscription.Status === 'Confirmed' ? 'text-green-600' : 'text-orange-600';
                                           
                                           diagramHtml += `<div class="ml-2 text-xs">
                                               <span class="font-mono bg-gray-100 px-1 rounded">
                                                   ${subscription.Protocol}
                                               </span>
                                               <span class="ml-1 text-gray-700">${subscription.Endpoint}</span>
                                               <span class="ml-1 ${statusColor} font-medium">
                                                   (${subscription.Status})
                                               </span>
                                           </div>`;
                                       });
                                       
                                       diagramHtml += `</div>`;
                                   } else {
                                       diagramHtml += `<p class="text-xs text-gray-500 mt-1 italic">
                                           No subscriptions or unable to retrieve
                                       </p>`;
                                   }
                                   
                                   if (snsDetail.Error) {
                                       diagramHtml += `<p class="text-xs text-red-600 mt-1">
                                           Error: ${snsDetail.Error}
                                       </p>`;
                                   }
                                   
                                   diagramHtml += `</div>`;
                               });
                           } else {
                               diagramHtml += `<p class="text-xs text-gray-500 ml-4 mt-1 italic">
                                   No SNS actions configured
                               </p>`;
                           }
                           
                           diagramHtml += `</div>`;
                       });
                   }
                   diagramHtml += `</div>`;
                });
           }
           diagramHtml += `</div></div>`;
        } else {
            diagramHtml += '<div class="bg-gray-50 border border-gray-200 rounded-lg p-3 flex items-center justify-center"><p class="text-xs text-gray-400">No CloudWatch destination</p></div>';
        }

        diagramHtml += `</div>`; // Cierra grid

        // EventBridge S3 section (MODIFICADA)
        if (hasS3EventBridgeFlow) {
            const eb = trail.EventBridgeFlow;
            diagramHtml += `
                <div class="mt-6 bg-orange-50 border border-orange-200 rounded-lg p-4">
                    <h4 class="text-md font-semibold text-orange-800 mb-3">
                        S3 EventBridge Processing (${eb.Rules.length} rules)
                    </h4>
                    <div class="space-y-2">
            `;

            eb.Rules.forEach(rule => {
                const ruleSNSTargets = rule.SNSTargets || []; // USAR DETALLES COMPLETOS
                
                diagramHtml += `
                    <div class="bg-orange-100 border border-orange-300 rounded p-3">
                        <p class="font-semibold text-gray-800 text-sm">Rule: ${rule.Name}</p>
                        <p class="text-gray-600 text-xs mt-1">Processes S3 events from this bucket</p>
                `;

                if (rule.Targets && rule.Targets.length > 0) {
                    diagramHtml += `<div class="mt-2 space-y-1">`;
                    rule.Targets.forEach(target => {
                        const arn = target.Arn;
                        const targetType = arn.includes(':lambda:') ? 'Lambda' :
                                         arn.includes(':sqs:') ? 'SQS' :
                                         arn.includes(':sns:') ? 'SNS' : 'Other';
                        
                        diagramHtml += `<div class="pl-3 text-xs text-gray-700">
                            Target ${targetType}: ${arn.split(':').pop()}
                        </div>`;
                    });
                    diagramHtml += `</div>`;
                }

                // AGREGAR DETALLES COMPLETOS DE SNS PARA S3 EVENTBRIDGE TAMBIÉN
                if (ruleSNSTargets.length > 0) {
                    diagramHtml += renderSNSDetails(ruleSNSTargets, 'eventbridge_s3');
                }

                diagramHtml += `</div>`;
            });

            diagramHtml += `</div></div>`;
        }

        diagramHtml += `</div>`; // Cierra contenedor del trail
    });

    diagramHtml += `</div></div>`; // Cierra sección de trails

    diagramHtml += '</div>'; // Cierra contenedor principal

    // Footer
    const footerHtml = `
        <div class="mt-8 text-center text-xs text-gray-400">
            <p>Enhanced TrailGuard analysis showing independent EventBridge rules and CloudTrail configuration flows.</p>
            <p class="mt-1">Inspired by <a href="https://github.com/adanalvarez/TrailGuard" target="_blank" class="text-blue-400 hover:underline">adanalvarez/TrailGuard</a>.</p>
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

// === FUNCIONES TRAILALERTS ===


const renderTrailAlertsView = () => {
    const currentDate = new Date();
    const defaultEndDate = currentDate.toISOString().split('T')[0];
    const defaultStartDate = new Date(currentDate.setDate(currentDate.getDate() - 30)).toISOString().split('T')[0];

    return `
        <div class="space-y-6">
            <!-- Header con info de reglas -->
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <div class="flex justify-between items-start mb-4">
                    <div>
                        <h3 class="font-bold text-lg text-[#204071]">Sigma Rules Database</h3>
                        <p class="text-sm text-gray-500">MITRE ATT&CK mapped detection rules</p>
                    </div>
                    <div id="rules-status-indicator" class="text-right">
                        <div class="inline-flex items-center px-3 py-1 rounded-full text-xs bg-gray-100 text-gray-600">
                            <div class="animate-spin h-3 w-3 border-2 border-gray-400 border-t-transparent rounded-full mr-2"></div>
                            Loading...
                        </div>
                    </div>
                </div>
                
                <div id="rules-status-details" class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4 hidden">
                    <div class="text-center">
                        <div class="text-2xl font-bold text-[#204071]" id="rules-count">--</div>
                        <div class="text-sm text-gray-500">Available Rules</div>
                    </div>
                    <div class="text-center">
                        <div class="text-sm font-medium text-gray-700" id="last-update">--</div>
                        <div class="text-xs text-gray-500">Last Updated</div>
                    </div>
                    <div class="text-center">
                        <div class="text-sm font-medium text-gray-700" id="rules-source">TrailAlerts</div>
                        <div class="text-xs text-gray-500">Source</div>
                    </div>
                </div>
                
                <button id="update-rules-btn" class="bg-blue-600 text-white px-4 py-2 rounded-lg font-medium text-sm hover:bg-blue-700 transition flex items-center space-x-2">
                    <span id="update-rules-text">Update Rules Database</span>
                    <div id="update-rules-spinner" class="spinner hidden"></div>
                </button>
            </div>

            <!-- Panel de análisis -->
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <h3 class="font-bold text-lg mb-4 text-[#204071]">Security Event Analysis</h3>
                
                <div class="bg-blue-50 border border-blue-200 rounded p-3 mb-4">
                    <p class="text-sm text-blue-700">
                        <strong>Threat Detection:</strong> Analyzes CloudTrail events against Sigma rules mapped to MITRE ATT&CK techniques to identify potential security threats and suspicious activities.
                    </p>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label for="ta-start-date" class="block text-sm font-medium text-gray-700 mb-1">Analysis Start Date</label>
                        <input type="date" id="ta-start-date" value="${defaultStartDate}" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5">
                    </div>
                    <div>
                        <label for="ta-end-date" class="block text-sm font-medium text-gray-700 mb-1">Analysis End Date</label>
                        <input type="date" id="ta-end-date" value="${defaultEndDate}" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5">
                    </div>
                </div>

                <button id="analyze-events-btn" class="bg-[#eb3496] text-white px-6 py-2.5 rounded-lg font-bold text-md hover:bg-[#d12b7e] transition flex items-center space-x-2" disabled>
                    <span id="analyze-events-text">Analyze Security Events</span>
                    <div id="analyze-events-spinner" class="spinner hidden"></div>
                </button>
                
                <!-- NUEVA SECCIÓN MEJORADA -->
                <div class="mt-3 p-3 bg-gray-50 rounded-lg">
                    <p id="analysis-description" class="text-sm text-gray-600">
                        Analysis will be performed on <span id="events-count" class="font-medium text-[#204071]">--</span> CloudTrail events <span id="analysis-method-text" class="text-gray-500">from cached events</span>
                    </p>
                    <div id="events-info" class="text-xs text-gray-500 mt-1">
                        <span id="date-range-info">Using default cached events from the last 7 days</span>
                    </div>
                </div>
            </div>

            <!-- Resultados del análisis -->
            <div id="trailalerts-results-container"></div>
        </div>
    `;
};

const initializeTrailAlertsEventListeners = () => {
    // Botón actualizar reglas
    const updateBtn = document.getElementById('update-rules-btn');
    if (updateBtn) {
        updateBtn.addEventListener('click', updateSigmaRules);
    }

    // Botón analizar eventos
    const analyzeBtn = document.getElementById('analyze-events-btn');
    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', runTrailAlertsAnalysis);
    }
    
    // NUEVO: Configurar listeners para cambios de fecha y conteo inicial
    setupDateChangeListeners();
    
    // Inicializar el conteo de eventos con los datos actuales
    const initialEventsCount = window.cloudtrailApiData?.results?.events?.length || 0;
    updateEventsCount(initialEventsCount, 'cached');
};

const loadRulesStatus = async () => {
    try {
        const response = await fetch('http://127.0.0.1:5001/api/get-sigma-rules-status');
        const data = await response.json();
        
        window.rulesStatus = data;
        updateRulesStatusDisplay(data);
        
        // Habilitar botón de análisis si hay reglas disponibles
        const analyzeBtn = document.getElementById('analyze-events-btn');
        if (analyzeBtn && data.rules_available) {
            analyzeBtn.disabled = false;
        }
        
    } catch (error) {
        log('Error loading Sigma rules status', 'error');
        updateRulesStatusDisplay({ 
            status: 'error', 
            rules_available: false, 
            rules_count: 0 
        });
    }
};

const updateRulesStatusDisplay = (status) => {
    const indicator = document.getElementById('rules-status-indicator');
    const details = document.getElementById('rules-status-details');
    const rulesCount = document.getElementById('rules-count');
    const lastUpdate = document.getElementById('last-update');
    
    if (!indicator) return;

    if (status.rules_available) {
        indicator.innerHTML = `
            <div class="inline-flex items-center px-3 py-1 rounded-full text-xs bg-green-100 text-green-800">
                <div class="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                ${status.rules_count} rules loaded
            </div>
        `;
        
        if (details) details.classList.remove('hidden');
        if (rulesCount) rulesCount.textContent = status.rules_count;
        if (lastUpdate && status.last_update) {
            const date = new Date(status.last_update);
            lastUpdate.textContent = date.toLocaleDateString();
        }
    } else {
        indicator.innerHTML = `
            <div class="inline-flex items-center px-3 py-1 rounded-full text-xs bg-red-100 text-red-800">
                <div class="w-2 h-2 bg-red-500 rounded-full mr-2"></div>
                No rules available
            </div>
        `;
        if (details) details.classList.add('hidden');
    }
};

const updateSigmaRules = async () => {
    const btn = document.getElementById('update-rules-btn');
    const btnText = document.getElementById('update-rules-text');
    const spinner = document.getElementById('update-rules-spinner');
    
    if (!btn || !btnText || !spinner) return;

    btn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Downloading...';
    
    try {
        log('Downloading Sigma rules from TrailAlerts repository...', 'info');
        
        const response = await fetch('http://127.0.0.1:5001/api/update-sigma-rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            log(`Rules updated successfully: ${data.message}`, 'success');
            
            // Actualizar display
            await loadRulesStatus();
            
            // Habilitar botón de análisis
            const analyzeBtn = document.getElementById('analyze-events-btn');
            if (analyzeBtn) analyzeBtn.disabled = false;
            
        } else {
            throw new Error(data.message || 'Failed to update rules');
        }
        
    } catch (error) {
        log(`Error updating rules: ${error.message}`, 'error');
        
        const resultsContainer = document.getElementById('trailalerts-results-container');
        if (resultsContainer) {
            resultsContainer.innerHTML = `
                <div class="bg-red-50 text-red-700 p-4 rounded-lg">
                    <h4 class="font-bold">Update Failed</h4>
                    <p>${error.message}</p>
                </div>
            `;
        }
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Update Rules Database';
    }
};

const runTrailAlertsAnalysis = async () => {
    const btn = document.getElementById('analyze-events-btn');
    const btnText = document.getElementById('analyze-events-text');
    const spinner = document.getElementById('analyze-events-spinner');
    const resultsContainer = document.getElementById('trailalerts-results-container');
    
    if (!btn || !btnText || !spinner || !resultsContainer) return;

    // Obtener fechas
    const startDateInput = document.getElementById('ta-start-date')?.value;
    const endDateInput = document.getElementById('ta-end-date')?.value;
    
    // Verificar credenciales para lookup dinámico
    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');
    
    if (!accessKeyInput?.value || !secretKeyInput?.value) {
        resultsContainer.innerHTML = `
            <div class="bg-red-50 text-red-700 p-4 rounded-lg">
                <h4 class="font-bold">Credentials Required</h4>
                <p>Please enter AWS credentials in the header to perform TrailAlerts analysis.</p>
            </div>
        `;
        return;
    }

    btn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Analyzing...';
    resultsContainer.innerHTML = '';
    
    try {
        // Determinar si usar lookup dinámico o eventos en memoria
        const allEvents = window.cloudtrailApiData?.results?.events || [];
        let useDynamicLookup = false;
        let analysisMessage = `Starting TrailAlerts analysis...`;
        
        // Usar lookup dinámico si:
        // 1. Hay fechas personalizadas
        // 2. Las fechas están fuera del rango de eventos en memoria
        if (startDateInput && endDateInput && allEvents.length > 0) {
            const oldestEvent = new Date(Math.min(...allEvents.map(e => new Date(e.EventTime))));
            const newestEvent = new Date(Math.max(...allEvents.map(e => new Date(e.EventTime))));
            const requestedStart = new Date(startDateInput);
            const requestedEnd = new Date(endDateInput);
            
            if (requestedStart < oldestEvent || requestedEnd > newestEvent) {
                useDynamicLookup = true;
                analysisMessage = `Searching CloudTrail across all regions for custom date range...`;
            }
        } else if (startDateInput || endDateInput) {
            useDynamicLookup = true;
            analysisMessage = `Searching CloudTrail across all regions for custom date range...`;
        }
        
        log(analysisMessage, 'info');
        
        const payload = {
            access_key: accessKeyInput.value.trim(),
            secret_key: secretKeyInput.value.trim(),
            session_token: sessionTokenInput.value.trim() || null,
            start_date: startDateInput ? `${startDateInput}T00:00:00Z` : null,
            end_date: endDateInput ? `${endDateInput}T23:59:59Z` : null,
            use_dynamic_lookup: useDynamicLookup
        };
        
        // Solo incluir eventos en memoria si no usamos lookup dinámico
        if (!useDynamicLookup) {
            payload.events = allEvents;
        }
        
        const response = await fetch('http://127.0.0.1:5001/api/run-trailalerts-analysis', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            window.trailAlertsData = data;
            renderTrailAlertsResults(data);
            
            // NUEVO: Actualizar el conteo con los eventos realmente analizados
            const actualEventsAnalyzed = data.metadata.events_analyzed;
            const analysisMethod = data.metadata.analysis_method || 'cached_events';
            
            updateEventsCount(actualEventsAnalyzed, analysisMethod);
            updateAnalysisDescription(`Analysis completed on <span id="events-count" class="font-medium text-green-600">${actualEventsAnalyzed}</span> CloudTrail events <span id="analysis-method-text" class="text-gray-500">${analysisMethod === 'dynamic_lookup' ? 'via dynamic CloudTrail search' : 'from cached events'}</span>`);
            
            // Actualizar información de rango de fechas post-análisis
            const dateRangeInfo = document.getElementById('date-range-info');
            if (dateRangeInfo) {
                dateRangeInfo.textContent = `Found ${data.results.alerts.length} security alerts`;
            }
            
            const method = analysisMethod === 'dynamic_lookup' ? 'dynamic CloudTrail lookup' : 'cached events';
            log(`Analysis completed using ${method}. Found ${data.results.alerts.length} security alerts.`, 'success');
        } else {
            throw new Error(data.error || 'Analysis failed');
        }
        
    } catch (error) {
        log(`TrailAlerts analysis error: ${error.message}`, 'error');
        resultsContainer.innerHTML = `
            <div class="bg-red-50 text-red-700 p-4 rounded-lg">
                <h4 class="font-bold">Analysis Failed</h4>
                <p>${error.message}</p>
            </div>
        `;
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Analyze Security Events';
    }
};

const renderTrailAlertsResults = (data) => {
    const container = document.getElementById('trailalerts-results-container');
    if (!container || !data.results) return;

    const { alerts, summary } = data.results;
    const { events_analyzed, rules_loaded } = data.metadata;

    let resultsHtml = `
        <!-- Summary Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div class="bg-white p-4 rounded-lg border border-gray-200">
                <div class="text-2xl font-bold text-[#204071]">${summary.total_alerts}</div>
                <div class="text-sm text-gray-500">Total Alerts</div>
            </div>
            <div class="bg-white p-4 rounded-lg border border-gray-200">
                <div class="text-2xl font-bold text-red-600">${summary.critical_alerts + summary.high_alerts}</div>
                <div class="text-sm text-gray-500">High Risk</div>
            </div>
            <div class="bg-white p-4 rounded-lg border border-gray-200">
                <div class="text-2xl font-bold text-[#204071]">${events_analyzed}</div>
                <div class="text-sm text-gray-500">Events Analyzed</div>
            </div>
            <div class="bg-white p-4 rounded-lg border border-gray-200">
                <div class="text-2xl font-bold text-[#204071]">${rules_loaded}</div>
                <div class="text-sm text-gray-500">Rules Applied</div>
            </div>
        </div>
    `;

    if (alerts.length === 0) {
        resultsHtml += `
            <div class="bg-green-50 text-green-700 p-6 rounded-lg text-center">
                <div class="flex justify-center mb-2">
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="bi bi-shield-fill-check mx-auto" viewBox="0 0 16 16">
                        <path fill-rule="evenodd" d="M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99a11.8 11.8 0 0 0 2.517 2.453c.386.273.744.482 1.048.625.28.132.581.24.829.24s.548-.108.829-.24a7 7 0 0 0 1.048-.625 11.8 11.8 0 0 0 2.517-2.453c1.678-2.195 3.061-5.513 2.465-9.99a1.54 1.54 0 0 0-1.044-1.263 63 63 0 0 0-2.887-.87C9.843.266 8.69 0 8 0m2.146 5.146a.5.5 0 0 1 .708.708l-3 3a.5.5 0 0 1-.708 0l-1.5-1.5a.5.5 0 1 1 .708-.708L7.5 7.793z"/>
                    </svg>
                </div>
                <h4 class="font-bold text-lg">No Security Threats Detected</h4>
                <p>All ${events_analyzed} CloudTrail events passed security analysis.</p>
            </div>
        `;
    } else {
        resultsHtml += `
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <h4 class="font-bold text-lg mb-4 text-[#204071]">Security Alerts Found</h4>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Alert</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">MITRE ATT&CK</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Event</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
        `;

        alerts.forEach((alert, index) => {
            const severityClass = getSeverityClass(alert.severity);
            const mitreTag = alert.mitre_tags[0] || 'No tag';
            const eventTime = new Date(alert.matched_event.EventTime).toLocaleString();
            
            resultsHtml += `
                <tr class="hover:bg-blue-50 cursor-pointer transition-colors" onclick="showTrailAlertEventDetails(${index})" title="Click to view full event details">
                    <td class="px-4 py-4 whitespace-nowrap">
                        <span class="px-2 py-1 text-xs font-semibold rounded-full ${severityClass}">
                            ${alert.severity.toUpperCase()}
                        </span>
                    </td>
                    <td class="px-4 py-4">
                        <div class="text-sm font-medium text-gray-900">${alert.title}</div>
                        <div class="text-sm text-gray-500 truncate" style="max-width: 300px;">${alert.description}</div>
                    </td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-mono text-gray-600">
                        ${mitreTag.replace('attack.', '').toUpperCase()}
                    </td>
                    <td class="px-4 py-4">
                        <div class="text-sm text-gray-900">${alert.matched_event.EventName}</div>
                        <div class="text-sm text-gray-500">${alert.matched_event.Username}</div>
                    </td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-500">
                        ${eventTime}
                        <div class="text-xs text-blue-600 mt-1">Click for details →</div>
                    </td>
                </tr>
            `;
        });

        resultsHtml += `
                        </tbody>
                    </table>
                </div>
            </div>
        `;
    }

    // Añadir contenedor para mostrar detalles del evento
    resultsHtml += `<div id="trailalerts-event-detail-container" class="mt-6"></div>`;

    // Footer con reconocimiento
    const footerHtml = `
        <div class="mt-8 text-center text-xs text-gray-400">
            <p>Advanced threat detection using Sigma rules mapped to MITRE ATT&CK framework for comprehensive CloudTrail security analysis.</p>
            <p class="mt-1">Inspired by <a href="https://github.com/adanalvarez/TrailAlerts" target="_blank" class="text-blue-400 hover:underline">adanalvarez/TrailAlerts</a>.</p>
        </div>
    `;

    // Añadir el footer al HTML
    resultsHtml += footerHtml;

    container.innerHTML = resultsHtml;
};



window.showTrailAlertEventDetails = (alertIndex) => {
    if (!window.trailAlertsData?.results?.alerts?.[alertIndex]) {
        console.error('Alert not found at index:', alertIndex);
        return;
    }
    
    const alert = window.trailAlertsData.results.alerts[alertIndex];
    const detailContainer = document.getElementById('trailalerts-event-detail-container');
    
    if (!detailContainer) {
        console.error('Detail container not found');
        return;
    }

    // Highlight de la fila seleccionada
    const table = detailContainer.parentElement.querySelector('table');
    if (table) {
        table.querySelectorAll('tr.bg-blue-100').forEach(row => {
            row.classList.remove('bg-blue-100');
            row.classList.add('hover:bg-blue-50');
        });
        
        const rows = table.querySelectorAll('tbody tr');
        if (rows[alertIndex]) {
            rows[alertIndex].classList.add('bg-blue-100');
            rows[alertIndex].classList.remove('hover:bg-blue-50');
        }
    }

    // Determinar qué datos del evento tenemos disponibles
    let eventData = null;
    let eventId = 'unknown';
    let dataSource = 'limited';
    
    // 1. Prioridad: evento completo desde full_event (nuevo backend)
    if (alert.matched_event.full_event) {
        eventData = alert.matched_event.full_event;
        eventId = eventData.EventId || alert.matched_event.EventId || 'unknown';
        dataSource = 'complete';
    }
    // 2. Si tenemos CloudTrailEvent JSON
    else if (alert.matched_event.CloudTrailEvent) {
        eventData = {
            EventId: alert.matched_event.EventId || 'unknown',
            CloudTrailEvent: alert.matched_event.CloudTrailEvent,
            EventName: alert.matched_event.EventName,
            EventTime: alert.matched_event.EventTime,
            Username: alert.matched_event.Username
        };
        eventId = alert.matched_event.EventId || 'unknown';
        dataSource = 'json_available';
    }
    // 3. Fallback: datos básicos solamente
    else {
        eventData = {
            EventId: 'limited-data',
            CloudTrailEvent: JSON.stringify(alert.matched_event),
            EventName: alert.matched_event.EventName,
            EventTime: alert.matched_event.EventTime,
            Username: alert.matched_event.Username
        };
        dataSource = 'limited';
    }

    // Header con información de la alerta
    const alertHeaderHtml = `
        <div class="bg-gradient-to-r from-red-50 to-orange-50 border border-red-200 rounded-lg p-4 mb-4">
            <div class="flex items-start justify-between">
                <div class="flex-1">
                    <h3 class="text-lg font-bold text-red-800 mb-2 flex items-center">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.996-.833-2.464 0L3.732 16c-.77.833.192 2.5 1.732 2.5z"></path>
                        </svg>
                        Security Alert Triggered
                    </h3>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div>
                            <span class="font-medium text-red-700">Rule:</span>
                            <span class="ml-2 text-red-900">${alert.title}</span>
                        </div>
                        <div>
                            <span class="font-medium text-red-700">Severity:</span>
                            <span class="ml-2 px-2 py-1 text-xs font-semibold rounded-full ${getSeverityClass(alert.severity)}">
                                ${alert.severity.toUpperCase()}
                            </span>
                        </div>
                        <div>
                            <span class="font-medium text-red-700">Risk Score:</span>
                            <span class="ml-2 font-bold text-lg text-red-600">${alert.risk_score}/100</span>
                        </div>
                        <div>
                            <span class="font-medium text-red-700">MITRE ATT&CK:</span>
                            <div class="ml-2 mt-1">
                                ${alert.mitre_tags.map(tag => `<span class="inline-block bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded mr-1 mb-1">${tag}</span>`).join('')}
                            </div>
                        </div>
                    </div>
                    <div class="mt-3">
                        <span class="font-medium text-red-700">Description:</span>
                        <p class="mt-1 text-red-800">${alert.description}</p>
                    </div>
                </div>
                <button onclick="closeTrailAlertDetails()" 
                        class="ml-4 text-red-400 hover:text-red-600 transition-colors">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
        </div>
    `;

    // Crear el HTML del evento
    let eventDetailHtml = '';
    
    try {
        const parsedEvent = JSON.parse(eventData.CloudTrailEvent);
        const formattedJson = JSON.stringify(parsedEvent, null, 2);
        
        // Indicador de calidad de datos
        const dataIndicators = {
            'complete': '<span class="bg-green-100 text-green-800 text-xs px-2 py-1 rounded">✓ Complete Event Data</span>',
            'json_available': '<span class="bg-blue-100 text-blue-800 text-xs px-2 py-1 rounded">✓ Full CloudTrail JSON</span>',
            'limited': '<span class="bg-red-100 text-red-800 text-xs px-2 py-1 rounded">⚠ Limited Data</span>'
        };
        
        eventDetailHtml = `
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-xl font-bold text-[#204071]">Event Detail: ${eventId}</h3>
                ${dataIndicators[dataSource]}
            </div>
            <pre class="bg-[#204071] text-white p-4 rounded-lg text-xs font-mono overflow-x-auto">${formattedJson}</pre>
        `;
        
    } catch (e) {
        console.error('Error parsing CloudTrail event JSON:', e);
        eventDetailHtml = `
            <h3 class="text-xl font-bold text-[#204071] mb-4">Event Detail: ${eventId}</h3>
            <p class="text-red-500">The event details could not be displayed due to JSON parsing error.</p>
        `;
    }

    // Combinar y mostrar
    detailContainer.innerHTML = alertHeaderHtml + eventDetailHtml;
    
    // Scroll suave hacia el detalle
    detailContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
};

window.closeTrailAlertDetails = () => {
    const detailContainer = document.getElementById('trailalerts-event-detail-container');
    if (detailContainer) {
        detailContainer.innerHTML = '';
        
        // Remover highlight de las filas
        const table = detailContainer.parentElement.querySelector('table');
        if (table) {
            table.querySelectorAll('tr.bg-blue-100').forEach(row => {
                row.classList.remove('bg-blue-100');
                row.classList.add('hover:bg-blue-50');
            });
        }
    }
};


const getSeverityClass = (severity) => {
    const classes = {
        'critical': 'bg-red-100 text-red-800',
        'high': 'bg-orange-100 text-orange-800',
        'medium': 'bg-yellow-100 text-yellow-800',
        'low': 'bg-blue-100 text-blue-800',
        'info': 'bg-gray-100 text-gray-800'
    };
    return classes[severity.toLowerCase()] || classes['info'];
};

const filterEventsByDateRange = (events, startDate, endDate) => {
    if (!startDate && !endDate) return events;
    
    const startDateTime = startDate ? new Date(`${startDate}T00:00:00Z`) : null;
    const endDateTime = endDate ? new Date(`${endDate}T23:59:59Z`) : null;
    
    return events.filter(event => {
        try {
            const eventTime = new Date(event.EventTime);
            
            if (startDateTime && eventTime < startDateTime) return false;
            if (endDateTime && eventTime > endDateTime) return false;
            
            return true;
        } catch (error) {
            // Si no se puede parsear la fecha, incluir el evento
            return true;
        }
    });
};

// Funciones auxiliares - AÑADIR AL FINAL DE 06_cloudtrail.js ANTES de las exportaciones

// Actualizar el conteo de eventos dinámicamente
const updateEventsCount = (count, method = 'cached') => {
    const eventsCountSpan = document.getElementById('events-count');
    const methodText = document.getElementById('analysis-method-text');
    
    if (eventsCountSpan) {
        eventsCountSpan.textContent = count;
    }
    
    if (methodText) {
        const methodDescription = method === 'dynamic_lookup' ? 
            'via dynamic CloudTrail search' : 
            'from cached events';
        methodText.textContent = methodDescription;
    }
};

// Calcular eventos disponibles según el rango de fechas
const calculateAvailableEvents = (startDate, endDate) => {
    const allEvents = window.cloudtrailApiData?.results?.events || [];
    
    if (!startDate && !endDate) {
        return allEvents.length;
    }
    
    try {
        const filteredEvents = filterEventsByDateRange(allEvents, startDate, endDate);
        return filteredEvents.length;
    } catch (error) {
        console.error('Error calculating available events:', error);
        return allEvents.length;
    }
};

// Actualizar la descripción del análisis
const updateAnalysisDescription = (description) => {
    const descriptionElement = document.getElementById('analysis-description');
    if (descriptionElement) {
        descriptionElement.innerHTML = description;
    }
};

// Actualizar información del rango de fechas
const updateDateRangeInfo = (startDate, endDate, useDynamicLookup) => {
    const dateRangeInfo = document.getElementById('date-range-info');
    if (!dateRangeInfo) return;
    
    if (!startDate && !endDate) {
        dateRangeInfo.textContent = 'Using default cached events from the last 7 days';
    } else if (useDynamicLookup) {
        const start = startDate ? new Date(startDate).toLocaleDateString() : 'earliest';
        const end = endDate ? new Date(endDate).toLocaleDateString() : 'latest';
        dateRangeInfo.textContent = `Will search CloudTrail from ${start} to ${end}`;
    } else {
        const start = startDate ? new Date(startDate).toLocaleDateString() : 'earliest';
        const end = endDate ? new Date(endDate).toLocaleDateString() : 'latest';
        dateRangeInfo.textContent = `Using cached events from ${start} to ${end}`;
    }
};

// Configurar listeners para cambios de fecha
const setupDateChangeListeners = () => {
    const startDateInput = document.getElementById('ta-start-date');
    const endDateInput = document.getElementById('ta-end-date');
    
    if (startDateInput && endDateInput) {
        const handleDateChange = () => {
            const startDate = startDateInput.value ? `${startDateInput.value}T00:00:00Z` : null;
            const endDate = endDateInput.value ? `${endDateInput.value}T23:59:59Z` : null;
            
            // Determinar si necesitamos lookup dinámico
            const allEvents = window.cloudtrailApiData?.results?.events || [];
            let useDynamicLookup = false;
            
            if (startDate && endDate && allEvents.length > 0) {
                const oldestEvent = new Date(Math.min(...allEvents.map(e => new Date(e.EventTime))));
                const newestEvent = new Date(Math.max(...allEvents.map(e => new Date(e.EventTime))));
                const requestedStart = new Date(startDate);
                const requestedEnd = new Date(endDate);
                
                if (requestedStart < oldestEvent || requestedEnd > newestEvent) {
                    useDynamicLookup = true;
                }
            } else if (startDate || endDate) {
                useDynamicLookup = true;
            }
            
            if (useDynamicLookup) {
                updateEventsCount('TBD', 'dynamic_lookup');
                updateAnalysisDescription(`Analysis will search CloudTrail for <span id="events-count" class="font-medium text-[#204071]">TBD</span> events <span id="analysis-method-text" class="text-gray-500">via dynamic CloudTrail search</span>`);
            } else {
                const availableEvents = calculateAvailableEvents(startDate, endDate);
                updateEventsCount(availableEvents, 'cached');
                updateAnalysisDescription(`Analysis will be performed on <span id="events-count" class="font-medium text-[#204071]">${availableEvents}</span> CloudTrail events <span id="analysis-method-text" class="text-gray-500">from cached events</span>`);
            }
            
            updateDateRangeInfo(startDate, endDate, useDynamicLookup);
        };
        
        startDateInput.addEventListener('change', handleDateChange);
        endDateInput.addEventListener('change', handleDateChange);
        
        // Ejecutar una vez al cargar para inicializar
        setTimeout(handleDateChange, 100);
    }
};

const restoreTrailAlertsFromImport = () => {
    if (!window.trailAlertsData) return;
    
    const trailAlertsContainer = document.getElementById('ct-trailalerts-content');
    if (!trailAlertsContainer) return;
    
    // Verificar si ya hay datos renderizados para evitar duplicación
    const existingResults = trailAlertsContainer.querySelector('#trailalerts-results-container');
    if (existingResults && existingResults.innerHTML.trim() !== '') {
        // Ya hay datos renderizados, no hacer nada
        return;
    }
    
    // Verificar si la vista ya está renderizada
    if (trailAlertsContainer.innerHTML.trim() === '') {
        // Renderizar la vista base si no existe
        trailAlertsContainer.innerHTML = renderTrailAlertsView();
        initializeTrailAlertsEventListeners();
        loadRulesStatus();
    }
    
    // Renderizar los resultados importados solo si no están ya renderizados
    renderTrailAlertsResults(window.trailAlertsData);
    
    // Solo mostrar el mensaje una vez
    const alertsCount = window.trailAlertsData.results?.alerts?.length || 0;
    log(`TrailAlerts data restored: ${alertsCount} security alerts from import`, 'success');
};
