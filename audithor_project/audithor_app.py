# ==============================================================================
# audithor_app.py - FICHERO PRINCIPAL (REFACTORIZADO)
# ==============================================================================
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_cors import CORS
import threading
import webbrowser
from datetime import datetime, timedelta
import pytz
import json
import subprocess
import shutil
import boto3

# Importa el motor de reglas (sin cambios)
from rules import RULES_TO_CHECK
from collectors.network_policies import get_network_details_table
from botocore.exceptions import BotoCoreError, ClientError

# --- 1. IMPORTA TUS NUEVOS MÓDULOS ---
from collectors import (
    utils, iam, securityhub, exposure, guardduty, waf, cloudtrail,
    cloudwatch, inspector, kms, acm, compute, databases,
    network_policies, connectivity, config_sh, playground, ecr
)




def get_boto_session(access_key, secret_key, session_token=None):
    """Creates and returns a Boto3 session from credentials."""
    try:
        # If the session token is empty or None, don't include it
        if session_token:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token
            )
        else:
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
        
        # Verify that the credentials are valid by making a simple call
        sts_client = session.client('sts')
        sts_client.get_caller_identity()
        
        return session
    except (BotoCoreError, ClientError) as e:
        # If credentials are invalid or another error occurs, return None
        print(f"[ERROR] Boto3 session could not be created: {e}")
        return None


# ==============================================================================
# CONF. APLICACIÓN FLASK
# ==============================================================================
app = Flask(__name__)
CORS(app)

# ==============================================================================
# ENDPOINTS API (ADAPTADOS)
# ==============================================================================

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/run-iam-audit', methods=['POST'])
def run_iam_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        iam_results = iam.collect_iam_data(session)
        iam_results["users"] = iam.check_critical_permissions(session, iam_results["users"])
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": iam_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting IAM data: {str(e)}"}), 500

@app.route('/api/run-securityhub-audit', methods=['POST'])
def run_securityhub_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        all_regions = utils.get_all_aws_regions(session)
        service_status = securityhub.check_security_hub_status_in_regions(session, all_regions)
        findings_data = securityhub.get_and_filter_security_hub_findings(session, service_status)
        enabled_service_status = [s for s in service_status if s['SecurityHubEnabled']]
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z") }, "results": { "servicesStatus": enabled_service_status, "findings": findings_data } })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Security Hub data: {str(e)}"}), 500

@app.route('/api/run-exposure-audit', methods=['POST'])
def run_exposure_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        exposure_results = exposure.collect_exposure_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": exposure_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Internet exposure.: {str(e)}"}), 500

@app.route('/api/run-guardduty-audit', methods=['POST'])
def run_guardduty_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        guardduty_results = guardduty.collect_guardduty_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": guardduty_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting GuardDuty data: {str(e)}"}), 500

@app.route('/api/run-waf-audit', methods=['POST'])
def run_waf_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        waf_results = waf.collect_waf_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": waf_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting WAF data {str(e)}"}), 500

@app.route('/api/run-cloudtrail-lookup', methods=['POST'])
def run_cloudtrail_lookup():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    
    data = request.get_json()
    event_name = data.get('event_name')
    start_date_str = data.get('start_date')
    end_date_str = data.get('end_date')
    region = data.get('region')

    if not all([start_date_str, end_date_str, region]):
        return jsonify({"error": "Missing parameters. Required: 'start_date', 'end_date' and 'region'."}), 400
        
    try:
        start_time = datetime.strptime(start_date_str, '%d-%m-%Y').replace(tzinfo=pytz.utc)
        end_time = (datetime.strptime(end_date_str, '%d-%m-%Y') + timedelta(days=1, seconds=-1)).replace(tzinfo=pytz.utc)
    except ValueError:
        return jsonify({"error": "Invalid date format. Use: 'dd-mm-yyyy'."}), 400

    try:
        lookup_results = cloudtrail.lookup_cloudtrail_events(session, region, event_name, start_time, end_time)
        return jsonify({"results": lookup_results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/run-cloudwatch-audit', methods=['POST'])
def run_cloudwatch_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        cloudwatch_results = cloudwatch.collect_cloudwatch_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": cloudwatch_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting CloudWatch/SNS data: {str(e)}"}), 500

@app.route('/api/run-inspector-audit', methods=['POST'])
def run_inspector_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        inspector_status = inspector.collect_inspector_status(session)
        inspector_status["findings"] = [] # Default empty findings for fast scan
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": inspector_status })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Inspector status: {str(e)}"}), 500

@app.route('/api/run-acm-audit', methods=['POST'])
def run_acm_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        acm_results = acm.collect_acm_data_web(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": acm_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting ACM data: {str(e)}"}), 500

@app.route('/api/run-compute-audit', methods=['POST'])
def run_compute_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        compute_results = compute.collect_compute_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": compute_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Compute data: {str(e)}"}), 500

@app.route('/api/run-databases-audit', methods=['POST'])
def run_databases_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        database_results = databases.collect_database_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": database_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Databases data: {str(e)}"}), 500

@app.route('/api/run-network-policies-audit', methods=['POST'])
def run_network_policies_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        network_policies_results = network_policies.collect_network_policies_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": network_policies_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Network Policies data: {str(e)}"}), 500
        
@app.route('/api/run-config-sh-audit', methods=['POST'])
def run_config_sh_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        results = config_sh.collect_config_sh_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Config & Security Hub data: {str(e)}"}), 500

@app.route('/api/run-config-sh-status-audit', methods=['POST'])
def run_config_sh_status_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        results = config_sh.collect_config_sh_status_only(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Config & SH status: {str(e)}"}), 500


@app.route('/api/run-network-detail-audit', methods=['POST'])
def handle_network_detail_audit():
    """
    Handles the request to get detailed rules for a specific network resource.
    """
    # Obtenemos las credenciales y creamos la sesión de Boto3
    # (Asegúrate de que tu lógica para get_boto_session esté aquí)
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request: No JSON payload found."}), 400

        access_key = data.get('access_key')
        secret_key = data.get('secret_key')
        session_token = data.get('session_token')

        session = get_boto_session(access_key, secret_key, session_token)
        if not session:
            return jsonify({"error": "Failed to create AWS session from provided credentials."}), 500

        # Extraemos el ID y la región del cuerpo de la petición
        resource_id = data.get('resource_id')
        region = data.get('region')

        if not resource_id or not region:
            return jsonify({"error": "Missing 'resource_id' or 'region' in the request payload."}), 400

        # --- LÓGICA CORREGIDA Y SIMPLIFICADA ---
        # Llamamos directamente a la función robusta que ya depuramos en network_policies.py
        details = get_network_details_table(session, resource_id, region)
        
        # Si la función devuelve un string que empieza con "Error:", lo tratamos como un error del lado del cliente
        if isinstance(details, str) and details.startswith("Error:"):
            return jsonify({"error": details}), 400

        # Si todo va bien, devolvemos el resultado
        return jsonify({"results": {"details_table": details}})

    except Exception as e:
        # Capturamos cualquier otro error inesperado y lo devolvemos de forma clara
        print(f"[ERROR] en handle_network_detail_audit: {e}") # Log para tu consola
        return jsonify({"error": f"An unexpected server error occurred: {str(e)}"}), 500

@app.route('/api/run-connectivity-audit', methods=['POST'])
def run_connectivity_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        connectivity_results = connectivity.collect_connectivity_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": connectivity_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting connectivity data: {str(e)}"}), 500

@app.route('/api/run-playground-audit', methods=['POST'])
def run_playground_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        data = request.get_json()
        source_arn = data.get('source_arn')
        target_arn = data.get('target_arn')
        if not source_arn or not target_arn:
            return jsonify({"error": "Source and destination ARN are required."}), 400

        path_results = playground.analyze_network_path_data(session, source_arn, target_arn)

        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": path_results })
    except ValueError as e: 
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error while analyzing the network route: {str(e)}"}), 500

@app.route('/api/run-kms-audit', methods=['POST'])
def run_kms_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        kms_results = kms.collect_kms_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": kms_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting KMS data: {str(e)}"}), 500

@app.route('/api/run-sslscan', methods=['POST'])
def run_sslscan():
    data = request.get_json()
    targets_str = data.get('target')
    if not targets_str:
        return jsonify({"error": "No target has been provided."}), 400
    
    results = playground.run_sslscan_on_targets(targets_str)
    return jsonify({"results": results})

@app.route('/run_executive_summary', methods=['POST'])
def run_executive_summary():
    audit_data = request.json
    if not audit_data:
        return jsonify({"error": "No audit data provided"}), 400

    executive_summary_findings = []
    for rule in RULES_TO_CHECK:
        check_function = rule.get("check_function")
        if callable(check_function):
            violating_resources_raw = check_function(audit_data)
            if violating_resources_raw:
                affected_resources_structured = []
                for resource in violating_resources_raw:
                    if isinstance(resource, dict):
                        affected_resources_structured.append({
                            "display": f"{resource['resource']} in {resource['region']}",
                            "region": resource.get("region", "Global")
                        })
                    else:
                        affected_resources_structured.append({
                            "display": str(resource),
                            "region": "Global"
                        })
                
                finding = {
                    "rule_id": rule.get("rule_id"), "name": rule.get("name"),
                    "severity": rule.get("severity"), "description": rule.get("description"),
                    "remediation": rule.get("remediation"), "status": "🚩 RED FLAG",
                    "affected_resources": affected_resources_structured
                }
                executive_summary_findings.append(finding)
    return jsonify(executive_summary_findings)

@app.route('/api/run-federation-audit', methods=['POST'])
def run_federation_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        federation_results = iam.collect_federation_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": federation_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting federation data: {str(e)}"}), 500

@app.route('/api/run-access-analyzer-audit', methods=['POST'])
def run_access_analyzer_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        analyzer_results = iam.collect_access_analyzer_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": { "accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": analyzer_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Access Analyzer data: {str(e)}"}), 500

@app.route('/api/run-inspector-findings-audit', methods=['POST'])
def run_inspector_findings_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        inspector_findings = inspector.collect_inspector_findings(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": inspector_findings })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting Inspector findings: {str(e)}"}), 500

@app.route('/api/get-sso-group-members', methods=['POST'])
def get_sso_group_members_endpoint():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    
    data = request.get_json()
    group_id = data.get('group_id')
    if not group_id:
        return jsonify({"error": "Group_id is required."}), 400

    try:
        members = iam.get_sso_group_members(session, group_id)
        return jsonify({"members": members})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/run-cloudtrail-audit', methods=['POST'])
def run_cloudtrail_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        # Esta función ahora devuelve trails, events y trailguard_findings
        cloudtrail_results = cloudtrail.collect_cloudtrail_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": cloudtrail_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting CloudTrail data.: {str(e)}"}), 500

@app.route('/api/run-ecr-audit', methods=['POST'])
def run_ecr_audit():
    session, error = utils.get_session(request.get_json())
    if error: return jsonify({"error": error}), 401
    try:
        ecr_results = ecr.collect_ecr_data(session)
        sts = session.client("sts")
        return jsonify({ "metadata": {"accountId": sts.get_caller_identity()["Account"], "executionDate": datetime.now(pytz.timezone("Europe/Madrid")).strftime("%Y-%m-%d %H:%M:%S %Z")}, "results": ecr_results })
    except Exception as e:
        return jsonify({"error": f"Unexpected error while collecting ECR data: {str(e)}"}), 500

@app.route('/api/check-healthy-status-rules', methods=['POST'])
def check_healthy_status_rules_endpoint():
    """
    Endpoint to check healthy status rules against audit data.
    This processes the audit data through all rules defined in rules.py
    """
    audit_data = request.json
    if not audit_data:
        return jsonify({"error": "No audit data provided"}), 400

    try:
        findings = []
        
        # Transform the audit data to match what the rules expect
        # The frontend sends data with structure: { iam: {metadata: {}, results: {}}, ... }
        # But the rules expect: { iam: {users: [], roles: [], ...}, ... }
        transformed_data = {}
        for service_key, service_data in audit_data.items():
            if service_data and isinstance(service_data, dict) and 'results' in service_data:
                transformed_data[service_key] = service_data['results']
            else:
                transformed_data[service_key] = service_data
        
        # Apply each rule from RULES_TO_CHECK
        for rule in RULES_TO_CHECK:
            check_function = rule.get("check_function")
            if callable(check_function):
                try:
                    violating_resources = check_function(transformed_data)
                    if violating_resources:
                        affected_resources_list = []
                        for resource in violating_resources:
                            if isinstance(resource, dict) and 'resource' in resource and 'region' in resource:
                                affected_resources_list.append(resource)
                            else:
                                affected_resources_list.append({
                                    "resource": str(resource),
                                    "region": "Global"
                                })
                        
                        finding = {
                            "rule_id": rule.get("rule_id"),
                            "section": rule.get("section"),
                            "name": rule.get("name"),
                            "severity": rule.get("severity"),
                            "description": rule.get("description"),
                            "remediation": rule.get("remediation"),
                            "affected_resources": affected_resources_list
                        }
                        findings.append(finding)
                except Exception as e:
                    print(f"[ERROR] Rule {rule.get('rule_id', 'unknown')} failed: {e}")
                    continue
        
        return jsonify(findings)
    
    except Exception as e:
        print(f"[ERROR] in check_healthy_status_rules_endpoint: {e}")
        return jsonify({"error": f"An error occurred while checking rules: {str(e)}"}), 500

# ==============================================================================
# EJECUCIÓN SERVIDOR
# ==============================================================================
if __name__ == '__main__':
    port = 5001
    url = f"http://127.0.0.1:{port}/"
    def open_browser():
        webbrowser.open_new(url)
    threading.Timer(1, open_browser).start()
    app.run(host='0.0.0.0', port=port, debug=False)

