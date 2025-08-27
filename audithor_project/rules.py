# ==============================================================================
# rules.py - Motor de Reglas para AudiThor-AWS (ACTUALIZADO)
# ==============================================================================
from datetime import datetime, timezone, timedelta

# ------------------------------------------------------------------------------
# 1. Definición de Niveles de Severidad
# ------------------------------------------------------------------------------
SEVERITY = {
    "CRITICAL": "Crítico",
    "HIGH": "Alto",
    "MEDIUM": "Medio",
    "LOW": "Bajo",
    "INFO": "Informativo"
}

# ------------------------------------------------------------------------------
# 2. Funciones de Chequeo de Reglas
# ------------------------------------------------------------------------------

def check_mfa_for_all_users(audit_data):
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    for user in users:
        if not user.get("MFADevices"):
            failing_resources.append(user.get("arn", user.get("UserName")))
    return failing_resources

def check_iam_access_key_age(audit_data):
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    ninety_days = 90
    now = datetime.now(timezone.utc)
    for user in users:
        for key in user.get("AccessKeys", []):
            try:
                create_date_str = key.get("CreateDate")
                create_date = datetime.fromisoformat(create_date_str)
                age = now - create_date
                if age.days > ninety_days:
                    user_identifier = user.get("arn", user.get("UserName"))
                    if user_identifier not in failing_resources:
                        failing_resources.append(user_identifier)
            except (ValueError, TypeError):
                continue
    return failing_resources

def check_password_policy_strength(audit_data):
    policy = audit_data.get("iam", {}).get("password_policy", {})
    if policy.get("Error"):
        return ["Account Password Policy"]
    checks = [
        policy.get("MinimumPasswordLength", 0) >= 12,
        policy.get("RequireUppercaseCharacters") is True,
        policy.get("RequireLowercaseCharacters") is True,
        policy.get("RequireNumbers") is True,
        policy.get("RequireSymbols") is True,
        policy.get("MaxPasswordAge") is not None and policy.get("MaxPasswordAge") <= 90,
        policy.get("PasswordReusePrevention", 0) >= 4,
    ]
    if not all(checks):
        return ["Account Password Policy"]
    return []

def check_guardduty_disabled(audit_data):
    """Verifica si GuardDuty está deshabilitado o suspendido."""
    failing_resources = []
    guardduty_status = audit_data.get("guardduty", {}).get("status", [])

    if not guardduty_status:
        failing_resources.append({"resource": "GuardDuty (Todas las regiones)", "region": "Global"})
        return failing_resources

    for status in guardduty_status:
        if status.get("Status") != "Enabled":
            failing_resources.append({
                "resource": "GuardDuty",
                "region": status.get('Region')
            })
    return failing_resources

def check_config_disabled(audit_data):
    """Verifica si AWS Config está deshabilitado."""
    failing_resources = []
    config_sh_status = audit_data.get("config_sh", {}).get("service_status", [])

    if not any(s.get("ConfigEnabled") for s in config_sh_status):
         failing_resources.append({"resource": "AWS Config (Todas las regiones)", "region": "Global"})
         return failing_resources

    for status in config_sh_status:
        if not status.get("ConfigEnabled"):
            failing_resources.append({
                "resource": "AWS Config",
                "region": status.get('Region')
            })
    return failing_resources

def check_security_hub_disabled(audit_data):
    """Verifica si AWS Security Hub está deshabilitado."""
    failing_resources = []
    config_sh_status = audit_data.get("config_sh", {}).get("service_status", [])

    if not any(s.get("SecurityHubEnabled") for s in config_sh_status):
         failing_resources.append({"resource": "Security Hub (Todas las regiones)", "region": "Global"})
         return failing_resources

    for status in config_sh_status:
        if not status.get("SecurityHubEnabled"):
            failing_resources.append({
                "resource": "Security Hub",
                "region": status.get('Region')
            })
    return failing_resources

def check_pci_dss_3_2_1_standard_enabled(audit_data):
    """
    Verifica si el estándar de Security Hub 'PCI DSS v3.2.1' está habilitado.
    """
    service_status = audit_data.get("config_sh", {}).get("service_status", [])

    for region_status in service_status:
        for standard_arn in region_status.get("EnabledStandards", []):
            arn_lower = standard_arn.lower()
            if "pci-dss" in arn_lower and "3.2.1" in arn_lower:
                return [] 
    
    return ["PCI DSS v3.2.1 Standard"]

def check_pci_dss_4_0_1_standard_enabled(audit_data):
    """
    Verifica si el estándar de Security Hub 'PCI DSS v4.0.1' está habilitado.
    """
    service_status = audit_data.get("config_sh", {}).get("service_status", [])

    for region_status in service_status:
        for standard_arn in region_status.get("EnabledStandards", []):
            arn_lower = standard_arn.lower()
            if "pci-dss" in arn_lower and "4.0.1" in arn_lower:
                return [] 
    
    return ["PCI DSS v4.0.1 Standard"]

def check_cis_1_2_0_standard_enabled(audit_data):
    """
    Verifica si el estándar de Security Hub 'CIS AWS Foundations Benchmark v1.2.0' está habilitado.
    """
    service_status = audit_data.get("config_sh", {}).get("service_status", [])

    for region_status in service_status:
        for standard_arn in region_status.get("EnabledStandards", []):
            arn_lower = standard_arn.lower()
            if "cis-aws-foundations-benchmark" in arn_lower and "1.2.0" in arn_lower:
                return [] 
    
    return ["CIS AWS Foundations Benchmark v1.2.0 Standard"]

def check_aws_foundational_security_standard_enabled(audit_data):
    """
    Verifica si el estándar 'AWS Foundational Security Best Practices v1.0.0' está habilitado.
    """
    service_status = audit_data.get("config_sh", {}).get("service_status", [])

    for region_status in service_status:
        for standard_arn in region_status.get("EnabledStandards", []):
            arn_lower = standard_arn.lower()
            if "aws-foundational-security-best-practices" in arn_lower:
                return [] 
    
    return ["AWS Foundational Security Best Practices Standard"]

def check_inspector_platform_eol(audit_data):
    """
    Busca hallazgos de Inspector que indiquen que una plataforma ha llegado al final de su vida útil (End of Life).
    """
    failing_resources = []
    inspector_findings = audit_data.get("inspector", {}).get("findings", [])

    for finding in inspector_findings:
        # Comparamos si la cadena de texto está presente en el título
        if "Platform End Of Life" in finding.get("title", ""):
            if finding.get("resources"):
                resource_id = finding["resources"][0].get("id", "ID no encontrado")
                failing_resources.append(resource_id)
                
    return failing_resources

def check_inspector_old_critical_findings(audit_data):
    """
    Busca hallazgos de Inspector con severidad Crítica o Alta que tengan una antigüedad mayor a 30 días.
    """
    failing_resources = []
    inspector_findings = audit_data.get("inspector", {}).get("findings", [])
    
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

    for finding in inspector_findings:
        severity = finding.get("severity")
        
        if severity in ["CRITICAL", "HIGH"]:
            try:
                first_observed_str = finding.get("firstObservedAt")
                if first_observed_str:
                    
                    # --- LÍNEA CORREGIDA ---
                    # Usamos strptime con el formato correcto en lugar de fromisoformat
                    finding_date = datetime.strptime(first_observed_str, "%a, %d %b %Y %H:%M:%S %Z").replace(tzinfo=timezone.utc)
                    
                    if finding_date < thirty_days_ago:
                        title = finding.get("title", "Título no disponible")
                        resource_id = "Recurso no disponible"
                        if finding.get("resources"):
                            resource_id = finding["resources"][0].get("id", "ID no disponible")
                        
                        failing_resources.append(f"{title} (Recurso: {resource_id})")

            except (ValueError, TypeError) as e:
                print(f"[WARN] No se pudo procesar la fecha para un finding de Inspector: {e}")
                continue
                
    return failing_resources

def check_user_has_attached_policies(audit_data):
    """Verifica si un usuario tiene políticas de IAM adjuntadas directamente."""
    failing_resources = []
    users = audit_data.get("iam", {}).get("users", [])
    for user in users:
        if user.get("AttachedPolicies"):
            failing_resources.append(user.get("UserName"))
    return failing_resources

def check_guardduty_malware_protection_disabled_with_ec2(audit_data):
    """
    Verifica si GuardDuty Malware Protection para EC2 está desactivado en regiones
    donde existen instancias EC2 y GuardDuty está habilitado.
    """
    failing_resources = []
    guardduty_status = audit_data.get("guardduty", {}).get("status", [])
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])

    regions_with_ec2 = {instance['Region'] for instance in ec2_instances}
    
    for status in guardduty_status:
        region = status.get("Region")
        
        cond1_gd_enabled = status.get("Status") == "Enabled"
        cond2_malware_disabled = status.get("EC2 Malware Protection") in ["Deshabilitado", "N/A"]
        cond3_ec2_present = region in regions_with_ec2

        if (cond1_gd_enabled and cond2_malware_disabled and cond3_ec2_present):
            failing_resources.append({
                "resource": "GuardDuty Malware Protection para EC2",
                "region": region
            })
    return failing_resources

def check_no_cloudtrail_in_region(audit_data):
    """
    Verifica cada región para asegurar que al menos un trail de CloudTrail está definido,
    teniendo en cuenta los trails multi-región.
    """
    all_regions = audit_data.get("networkPolicies", {}).get("all_regions", [])
    if not all_regions:
        return [] 

    trails = audit_data.get("cloudtrail", {}).get("trails", [])

    # Si no se recibe ningún trail, todas las regiones fallan.
    if not trails:
        return [{"resource": "CloudTrail", "region": region} for region in all_regions]

    # Comprobar si existe algún trail multi-región.
    is_any_trail_multiregion = any(trail.get("IsMultiRegionTrail") for trail in trails)
    if is_any_trail_multiregion:
        # Si existe, todas las regiones están cubiertas.
        return [] 
    
    # Si no hay trail multi-región, verificamos región por región.
    failing_resources = []
    regions_with_trails = {trail.get("HomeRegion") for trail in trails}
    for region in all_regions:
        if region not in regions_with_trails:
            failing_resources.append({
                "resource": "CloudTrail",
                "region": region
            })
    return failing_resources

def check_inspector_ec2_scanning_disabled(audit_data):
    """
    Verifica si el escaneo de EC2 de Inspector está desactivado en regiones donde existen instancias EC2.
    """
    failing_resources = []
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])
    inspector_status = audit_data.get("inspector", {}).get("scan_status", [])

    regions_with_ec2 = {instance['Region'] for instance in ec2_instances}
    inspector_ec2_scan_status = {status['Region']: status.get('ScanEC2') for status in inspector_status}

    for region in regions_with_ec2:
        scan_status = inspector_ec2_scan_status.get(region)
        if scan_status != 'ENABLED':
            failing_resources.append({
                "resource": "Inspector EC2 Scanning",
                "region": region
            })
    return failing_resources

def check_inspector_lambda_scanning_disabled(audit_data):
    """
    Verifica si el escaneo de Lambda de Inspector está desactivado en regiones donde existen funciones Lambda.
    """
    failing_resources = []
    lambda_functions = audit_data.get("compute", {}).get("lambda_functions", [])
    inspector_status = audit_data.get("inspector", {}).get("scan_status", [])

    regions_with_lambdas = {function['Region'] for function in lambda_functions}
    inspector_lambda_scan_status = {status['Region']: status.get('ScanLambda') for status in inspector_status}

    for region in regions_with_lambdas:
        scan_status = inspector_lambda_scan_status.get(region)
        if scan_status != 'ENABLED':
            failing_resources.append({
                "resource": "Inspector Lambda Scanning",
                "region": region
            })
    return failing_resources

def check_inspector_ecr_scanning_disabled(audit_data):
    """
    Verifica si el escaneo de ECR de Inspector está desactivado en regiones donde existen repositorios.
    """
    failing_resources = []
    ecr_repositories = audit_data.get("ecr", {}).get("repositories", [])
    inspector_status = audit_data.get("inspector", {}).get("scan_status", [])
    
    regions_with_ecr = {repo['Region'] for repo in ecr_repositories}
    inspector_ecr_scan_status = {status['Region']: status.get('ScanECR') for status in inspector_status}
    
    for region in regions_with_ecr:
        scan_status = inspector_ecr_scan_status.get(region)
        if scan_status != 'ENABLED':
            failing_resources.append({
                "resource": "Inspector ECR Scanning",
                "region": region
            })
            
    return failing_resources

def check_network_connectivity_exists(audit_data):
    """
    Verifica si existen componentes de red avanzados que justifiquen una revisión de segmentación.
    """
    connectivity_data = audit_data.get("connectivity", {})
    
    peering_exists = len(connectivity_data.get("peering_connections", [])) > 0
    tgw_exists = len(connectivity_data.get("tgw_attachments", [])) > 0
    vpn_exists = len(connectivity_data.get("vpn_connections", [])) > 0
    endpoints_exist = len(connectivity_data.get("vpc_endpoints", [])) > 0

    if peering_exists or tgw_exists or vpn_exists or endpoints_exist:
        return ["Servicios de Conectividad de Red Avanzada"]
        
    return []

def check_acm_expired_certificates(audit_data):
    """
    Verifica si existen certificados de ACM que han expirado.
    """
    failing_resources = []
    # Navegamos de forma segura hasta la lista de certificados
    certificates = audit_data.get("acm", {}).get("certificates", [])

    for cert in certificates:
        if cert.get("Status") == "EXPIRED":
            # Añadimos el dominio del certificado expirado a la lista de recursos fallidos
            failing_resources.append(cert.get("DomainName", cert.get("CertificateArn")))
            
    return failing_resources

def check_cloudtrail_kms_encryption_disabled(audit_data):
    """
    Verifica si los trails de CloudTrail tienen el cifrado con KMS habilitado.
    """
    failing_resources = []
    # Obtenemos la lista de trails del análisis
    trails = audit_data.get("cloudtrail", {}).get("trails", [])

    for trail in trails:
        # La ausencia de una KmsKeyId indica que el cifrado KMS no está activado
        if not trail.get("KmsKeyId"):
            # Añadimos el nombre del trail a la lista de recursos que fallan la comprobación
            failing_resources.append(trail.get("Name", trail.get("TrailARN")))
            
    return failing_resources

def check_cloudtrail_log_file_validation_disabled(audit_data):
    """
    Verifica si los trails de CloudTrail tienen la validación de integridad de logs activada.
    """
    failing_resources = []
    trails = audit_data.get("cloudtrail", {}).get("trails", [])

    for trail in trails:
        # La clave 'LogFileValidationEnabled' será False si la opción no está activada.
        if not trail.get("LogFileValidationEnabled"):
            # Añadimos el nombre del trail que no cumple con la regla.
            failing_resources.append(trail.get("Name", trail.get("TrailARN")))
            
    return failing_resources

def check_rds_publicly_accessible(audit_data):
    """
    Verifica si existen instancias de RDS configuradas con acceso público.
    """
    failing_resources = []
    # Navegamos de forma segura hasta la lista de instancias RDS
    rds_instances = audit_data.get("databases", {}).get("rds_instances", [])

    for instance in rds_instances:
        # La clave 'PubliclyAccessible' será True si la opción está activada
        if instance.get("PubliclyAccessible"):
            failing_resources.append({
                "resource": instance.get("DBInstanceIdentifier", "ID Desconocido"),
                "region": instance.get("Region", "Región Desconocida")
            })
            
    return failing_resources

def check_alb_outdated_tls_policy(audit_data):
    """
    Revisa los balanceadores de carga públicos (ALB/NLB) en busca de listeners
    que soporten versiones de TLS obsoletas (inferiores a TLSv1.2).
    """
    failing_resources = []
    # Navegamos de forma segura hasta los datos de balanceadores de carga por región
    lb_data_by_region = audit_data.get("exposure", {}).get("details", {}).get("ALB/NLB Public", {})

    # Iteramos sobre cada región que tiene balanceadores públicos
    for region, load_balancers in lb_data_by_region.items():
        for lb in load_balancers:
            # Iteramos sobre cada listener del balanceador
            for listener in lb.get("listeners", []):
                tls_versions = listener.get("tlsVersions", [])
                # Comprobamos si alguna de las versiones es obsoleta
                if any(version in ['TLSv1.0', 'TLSv1.1', 'SSLv3'] for version in tls_versions):
                    failing_resources.append({
                        "resource": f"{lb.get('name')} (Listener en puerto: {listener.get('port')})",
                        "region": region
                    })
            
    return failing_resources

def check_rds_instance_unencrypted(audit_data):
    """
    Verifica si existen instancias RDS standalone sin el cifrado en reposo habilitado.
    """
    failing_resources = []
    rds_instances = audit_data.get("databases", {}).get("rds_instances", [])
    for instance in rds_instances:
        if not instance.get("Encrypted"):
            failing_resources.append({
                "resource": instance.get("DBInstanceIdentifier"),
                "region": instance.get("Region")
            })
    return failing_resources

def check_aurora_cluster_unencrypted(audit_data):
    """
    Verifica si existen clústeres Aurora sin el cifrado en reposo habilitado.
    """
    failing_resources = []
    aurora_clusters = audit_data.get("databases", {}).get("aurora_clusters", [])
    for cluster in aurora_clusters:
        if not cluster.get("Encrypted"):
            failing_resources.append({
                "resource": cluster.get("ClusterIdentifier"),
                "region": cluster.get("Region")
            })
    return failing_resources

def check_dynamodb_table_unencrypted(audit_data):
    """
    Verifica si existen tablas de DynamoDB sin el cifrado en reposo habilitado.
    """
    failing_resources = []
    dynamodb_tables = audit_data.get("databases", {}).get("dynamodb_tables", [])
    for table in dynamodb_tables:
        if not table.get("Encrypted"):
            failing_resources.append({
                "resource": table.get("TableName"),
                "region": table.get("Region")
            })
    return failing_resources

def check_docdb_cluster_unencrypted(audit_data):
    """
    Verifica si existen clústeres de DocumentDB sin el cifrado en reposo habilitado.
    """
    failing_resources = []
    docdb_clusters = audit_data.get("databases", {}).get("documentdb_clusters", [])
    for cluster in docdb_clusters:
        if not cluster.get("Encrypted"):
            failing_resources.append({
                "resource": cluster.get("ClusterIdentifier"),
                "region": cluster.get("Region")
            })
    return failing_resources

def check_ec2_publicly_exposed(audit_data):
    """
    Checks for EC2 instances that have a public IP address assigned.
    """
    failing_resources = []
    # Safely navigate to the list of EC2 instances
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])

    for instance in ec2_instances:
        # Check if the PublicIpAddress key exists and has a valid value
        if instance.get("PublicIpAddress") and instance.get("PublicIpAddress") != "N/A":
            failing_resources.append({
                "resource": instance.get("InstanceId", "Unknown ID"),
                "region": instance.get("Region", "Unknown Region")
            })
            
    return failing_resources

def check_cloudtrail_cloudwatch_destination_disabled(audit_data):
    """
    Checks if CloudTrail trails have a CloudWatch Logs log group destination enabled.
    """
    failing_resources = []
    # Safely get the list of trails from the audit data
    trails = audit_data.get("cloudtrail", {}).get("trails", [])

    for trail in trails:
        # If the 'CloudWatchLogsLogGroupArn' key is missing or empty, the destination is not configured
        if not trail.get("CloudWatchLogsLogGroupArn"):
            # Add the name of the non-compliant trail to the list of failing resources
            failing_resources.append(trail.get("Name", trail.get("TrailARN")))
            
    return failing_resources


def check_kms_customer_key_rotation_disabled(audit_data):
    """
    Checks for customer-managed KMS keys that do not have automatic rotation enabled.
    """
    failing_resources = []
    # Safely navigate to the list of KMS keys
    kms_keys = audit_data.get("kms", {}).get("keys", [])

    for key in kms_keys:
        # Check for two conditions: the key is customer-managed AND rotation is disabled
        is_customer_managed = key.get("KeyManager") == "CUSTOMER"
        is_rotation_disabled = key.get("RotationEnabled") == "Disabled"

        if is_customer_managed and is_rotation_disabled:
            # If both conditions are true, add the key to the list of failing resources
            failing_resources.append({
                "resource": key.get("Aliases") or key.get("KeyId", "Unknown ID"),
                "region": key.get("Region", "Unknown Region")
            })
            
    return failing_resources

def check_ecr_tag_mutability(audit_data):
    """
    Checks for ECR repositories configured with mutable image tags.
    """
    failing_resources = []
    # Safely get the list of repositories from the audit data
    repositories = audit_data.get("ecr", {}).get("repositories", [])

    for repo in repositories:
        # Check if the image tag mutability is set to MUTABLE
        if repo.get("ImageTagMutability") == "MUTABLE":
            failing_resources.append({
                "resource": repo.get("RepositoryName", "Unknown ID"),
                "region": repo.get("Region", "Unknown Region")
            })
            
    return failing_resources

def check_ecr_scan_on_push_disabled(audit_data):
    """
    Checks for ECR repositories that do not have the 'scan on push' feature enabled.
    """
    failing_resources = []
    # Safely get the list of repositories from the audit data
    repositories = audit_data.get("ecr", {}).get("repositories", [])

    for repo in repositories:
        # The key 'ScanOnPush' will be False if the setting is disabled
        if not repo.get("ScanOnPush"):
            failing_resources.append({
                "resource": repo.get("RepositoryName", "Unknown ID"),
                "region": repo.get("Region", "Unknown Region")
            })
            
    return failing_resources


def check_waf_sampled_requests_disabled(audit_data):
    """
    Checks for WAF Web ACLs that do not have Sampled Requests enabled.
    """
    failing_resources = []
    # Safely get the list of Web ACLs
    acls = audit_data.get("waf", {}).get("acls", [])

    for acl in acls:
        # The setting is inside the VisibilityConfig dictionary
        vc_config = acl.get("VisibilityConfig", {})
        if not vc_config.get("SampledRequestsEnabled"):
            failing_resources.append({
                "resource": acl.get("Name", "Unknown ID"),
                "region": acl.get("Region", "Unknown Region")
            })

    return failing_resources

def check_waf_logging_destination_disabled(audit_data):
    """
    Checks for WAF Web ACLs that do not have a full logging destination configured.
    """
    failing_resources = []
    # Safely get the list of Web ACLs from the audit data
    acls = audit_data.get("waf", {}).get("acls", [])

    for acl in acls:
        # Get the logging configuration, defaulting to an empty dictionary
        logging_config = acl.get("LoggingConfiguration", {})
        
        # A disabled logging destination will have no 'LogDestinationConfigs' or it will be an empty list
        if not logging_config.get("LogDestinationConfigs"):
            failing_resources.append({
                "resource": acl.get("Name", "Unknown ID"),
                "region": acl.get("Region", "Unknown Region")
            })
            
    return failing_resources

def check_ec2_instance_missing_iam_role(audit_data):
    """
    Checks for running EC2 instances that do not have an IAM role associated.
    """
    failing_resources = []
    # Navegamos de forma segura hasta la lista de instancias EC2
    ec2_instances = audit_data.get("compute", {}).get("ec2_instances", [])

    for instance in ec2_instances:
        # Condición 1: La instancia debe estar en ejecución
        is_running = instance.get("State") == "running"
        
        # Condición 2: El perfil de IAM no debe estar asignado
        has_no_role = not instance.get("IamInstanceProfile") or instance.get("IamInstanceProfile") == "N/A"

        if is_running and has_no_role:
            failing_resources.append({
                "resource": instance.get("InstanceId", "ID Desconocido"),
                "region": instance.get("Region", "Región Desconocida")
            })
            
    return failing_resources


# ------------------------------------------------------------------------------
# 3. Master Rule List
# ------------------------------------------------------------------------------
RULES_TO_CHECK = [
    {
        "rule_id": "IAM_001",
        "section": "Identity & Access",
        "name": "User without MFA enabled",
        "severity": SEVERITY["HIGH"],
        "description": "An IAM user does not have Multi-Factor Authentication (MFA) enabled. Requiring MFA for all users is a fundamental security best practice to add an extra layer of protection against unauthorized access.",
        "remediation": "Navigate to the IAM service in the AWS console, select the affected user, and on the 'Security credentials' tab, assign an MFA device.",
        "check_function": check_mfa_for_all_users
    },
    {
        "rule_id": "IAM_002",
        "section": "Identity & Access",
        "name": "Access Key older than 90 days",
        "severity": SEVERITY["MEDIUM"],
        "description": "Programmatic access keys older than 90 days exist. It is a security best practice to rotate credentials regularly to limit the risk in case a key is compromised.",
        "remediation": "In the IAM console, create a new access key for the user, update the applications that use it, and then deactivate and delete the old key.",
        "check_function": check_iam_access_key_age
    },
    {
        "rule_id": "IAM_003",
        "section": "Identity & Access",
        "name": "Password policy is not strong enough",
        "severity": SEVERITY["HIGH"],
        "description": "The account's password policy does not meet recommended security standards, making user accounts more vulnerable to brute-force or guessing attacks.",
        "remediation": "In the IAM console, go to 'Account settings' and edit the password policy to meet all requirements: length >= 12, use of uppercase, lowercase, numbers, and symbols, expiration <= 90 days, reuse prevention >= 4, and hard expiry.",
        "check_function": check_password_policy_strength
    },
    {
        "rule_id": "IAM_004",
        "section": "Identity & Access",
        "name": "User with directly attached policies",
        "severity": SEVERITY["LOW"],
        "description": "A user has been detected with one or more IAM policies attached directly to their identity. AWS best practice recommends managing permissions through groups and roles to simplify administration and reduce the risk of configuration errors.",
        "remediation": "Create an IAM group that represents the user's role, attach the necessary policies to that group, and then add the user to the group. Finally, remove the policies that are directly attached to the user.",
        "check_function": check_user_has_attached_policies
    },
    {
        "rule_id": "GUARDDUTY_001",
        "section": "Security Services",
        "name": "GuardDuty not enabled in some regions",
        "severity": SEVERITY["LOW"],
        "description": "AWS GuardDuty, the threat detection service, is not enabled or is suspended in one or more regions. Enabling it is key to detecting malicious or unauthorized activity in the account.",
        "remediation": "Access the AWS console, go to the GuardDuty service, and enable it in the indicated regions to improve your account's threat detection.",
        "check_function": check_guardduty_disabled
    },
    {
        "rule_id": "GUARDDUTY_002",
        "section": "Security Services",
        "name": "GuardDuty Malware Protection disabled with EC2 instances present",
        "severity": SEVERITY["LOW"],
        "description": "GuardDuty Malware Protection is disabled in a region where EC2 instances exist. Although GuardDuty is active, this specific feature adds a layer of protection to detect malicious software on EC2 workloads and should be enabled if these instances are used.",
        "remediation": "Access the GuardDuty console, go to the detector settings for the affected region, and enable the 'Malware Protection' feature. This has no additional cost unless malware is detected and a scan is initiated.",
        "check_function": check_guardduty_malware_protection_disabled_with_ec2
    },
    {
        "rule_id": "CONFIG_001",
        "section": "Security Services",
        "name": "AWS Config not enabled in some regions",
        "severity": SEVERITY["MEDIUM"],
        "description": "AWS Config is not enabled in one or more regions. This service is essential for auditing and evaluating the configurations of AWS resources, allowing for continuous compliance monitoring.",
        "remediation": "Access the AWS console, go to the AWS Config service, and enable it in the indicated regions to improve visibility and configuration compliance of your resources.",
        "check_function": check_config_disabled
    },
    {
        "rule_id": "SECURITYHUB_001",
        "section": "Security Services",
        "name": "AWS Security Hub not enabled in some regions",
        "severity": SEVERITY["MEDIUM"],
        "description": "AWS Security Hub is not enabled in one or more regions. Security Hub provides a comprehensive view of high-priority security alerts and compliance status across all AWS services.",
        "remediation": "Access the AWS console, go to the Security Hub service, and enable it in the indicated regions to centralize and manage your account's security posture.",
        "check_function": check_security_hub_disabled
    },
    {
        "rule_id": "SECURITYHUB_002",
        "section": "Security Services",
        "name": "Security Hub Standard PCI DSS 3.2.1 not enabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "The 'PCI DSS v3.2.1' security standard is not enabled in AWS Security Hub. If the account processes, stores, or transmits credit card data, enabling this standard is crucial for monitoring compliance with the required security controls.",
        "remediation": "Access the AWS Security Hub console, navigate to the 'Security standards' section, and search for and enable the 'PCI DSS v3.2.1' standard.",
        "check_function": check_pci_dss_3_2_1_standard_enabled
    },
    {
        "rule_id": "SECURITYHUB_003",
        "section": "Security Services",
        "name": "Security Hub Standard PCI DSS 4.0.1 not enabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "The 'PCI DSS v4.0.1' security standard is not enabled in AWS Security Hub. If the account processes, stores, or transmits credit card data, enabling this standard is crucial for monitoring compliance with the required security controls.",
        "remediation": "Access the AWS Security Hub console, navigate to the 'Security standards' section, and search for and enable the 'PCI DSS v4.0.1' standard.",
        "check_function": check_pci_dss_4_0_1_standard_enabled
    },
    {
        "rule_id": "SECURITYHUB_004",
        "section": "Security Services",
        "name": "CIS AWS Foundations Benchmark v1.2.0 Standard not enabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "The 'CIS AWS Foundations Benchmark v1.2.0' security standard is not enabled in Security Hub. This benchmark provides a set of security recommendations for configuring AWS and helps align the account with industry best practices.",
        "remediation": "Access the AWS Security Hub console, navigate to the 'Security standards' section, and search for and enable the 'CIS AWS Foundations Benchmark v1.2.0' standard.",
        "check_function": check_cis_1_2_0_standard_enabled
    },
    {
        "rule_id": "SECURITYHUB_005",
        "section": "Security Services",
        "name": "AWS Foundational Security Best Practices Standard not enabled",
        "severity": SEVERITY["HIGH"],
        "description": "The 'AWS Foundational Security Best Practices' standard is not enabled in Security Hub. This is the primary AWS standard that helps detect when accounts and resources deviate from security best practices. It is essential to have it activated.",
        "remediation": "Access the AWS Security Hub console, navigate to the 'Security standards' section, and search for and enable the 'AWS Foundational Security Best Practices v1.0.0' standard.",
        "check_function": check_aws_foundational_security_standard_enabled
    },
    {
        "rule_id": "INSPECTOR_001",
        "section": "Vulnerability Management",
        "name": "Resource with End of Life (EOL) platform",
        "severity": SEVERITY["CRITICAL"],
        "description": "A resource (such as an EC2 instance) has been detected using an operating system or platform that has reached its 'End of Life' (EOL). This means it no longer receives security updates from the provider, leaving it exposed to known and future vulnerabilities.",
        "remediation": "Migrate the application or service to an instance with a supported operating system or platform that receives security updates. Plan to upgrade resources before they reach their EOL date.",
        "check_function": check_inspector_platform_eol
    },
    {
        "rule_id": "INSPECTOR_002",
        "section": "Vulnerability Management",
        "name": "Inspector EC2 scanning disabled in region with instances",
        "severity": SEVERITY["MEDIUM"],
        "description": "EC2 instances have been detected in a region where Amazon Inspector vulnerability scanning for EC2 is not activated. This represents a security blind spot, as new vulnerabilities in these instances will not be discovered.",
        "remediation": "Access the Amazon Inspector console, go to 'Account settings' -> 'Scan status', and ensure that 'Amazon EC2 scanning' is activated for the affected region.",
        "check_function": check_inspector_ec2_scanning_disabled
    },
    {
        "rule_id": "INSPECTOR_003",
        "section": "Vulnerability Management",
        "name": "Inspector Lambda scanning disabled in region with functions",
        "severity": SEVERITY["MEDIUM"],
        "description": "Lambda functions have been detected in a region where Amazon Inspector vulnerability scanning for Lambda is not activated. This can leave your functions' code and dependencies unscanned for known vulnerabilities.",
        "remediation": "Access the Amazon Inspector console, go to 'Account settings' -> 'Scan status', and ensure that 'Lambda functions scanning' is activated for the affected region.",
        "check_function": check_inspector_lambda_scanning_disabled
    },
    {
        "rule_id": "INSPECTOR_004",
        "section": "Vulnerability Management",
        "name": "Inspector ECR scanning disabled in region with repositories",
        "severity": SEVERITY["MEDIUM"],
        "description": "ECR repositories have been detected in a region where Amazon Inspector container image scanning is not activated. Images can contain vulnerabilities in their operating system or software packages, and not scanning them represents a significant security risk.",
        "remediation": "Access the Amazon Inspector console, go to 'Account settings' -> 'Scan status', and ensure that 'Amazon ECR scanning' is activated for the affected region.",
        "check_function": check_inspector_ecr_scanning_disabled
    },
    {
        "rule_id": "INSPECTOR_005",
        "section": "Vulnerability Management",
        "name": "Critical or High vulnerability unpatched for over 30 days",
        "severity": SEVERITY["HIGH"],
        "description": "Inspector findings with 'Critical' or 'High' severity have been detected that have not been remediated in over 30 days. This represents a significant and prolonged security risk, indicating a potential gap in the vulnerability and patch management process.",
        "remediation": "Immediately prioritize and remediate these old findings. Review your patch management processes to ensure high-impact vulnerabilities are addressed within an acceptable timeframe (SLA).",
        "check_function": check_inspector_old_critical_findings
    },
    {
        "rule_id": "CLOUDTRAIL_001",
        "section": "Logging & Monitoring",
        "name": "Region without a defined CloudTrail trail",
        "severity": SEVERITY["MEDIUM"],
        "description": "An AWS region has been detected that does not have any CloudTrail trail defined. Having an audit log of all API calls in every region is a fundamental security practice for incident investigation and activity monitoring.",
        "remediation": "Create a CloudTrail trail in the affected region. It is highly recommended to create a multi-region trail from the primary region to consolidate logs from all regions into a single S3 bucket.",
        "check_function": check_no_cloudtrail_in_region
    },
    {
        "rule_id": "CLOUDTRAIL_002",
        "section": "Logging & Monitoring",
        "name": "CloudTrail trail without KMS encryption enabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "A CloudTrail trail has been detected that does not use AWS KMS encryption to protect the log files. Encrypting logs at rest is a fundamental security practice to protect sensitive audit information from unauthorized access if the S3 bucket is compromised.",
        "remediation": "Navigate to the CloudTrail console, select the affected trail, and edit its configuration. In the storage section, enable log data encryption with AWS KMS, using either an AWS-managed key or a customer-managed key (CMK).",
        "check_function": check_cloudtrail_kms_encryption_disabled
    },
    {
        "rule_id": "CLOUDTRAIL_003",
        "section": "Logging & Monitoring",
        "name": "CloudTrail log file integrity validation disabled",
        "severity": SEVERITY["HIGH"],
        "description": "A CloudTrail trail has been detected that does not have log file integrity validation enabled. This feature is crucial to ensure that logs have not been altered or deleted after being delivered to the S3 bucket. Without it, the reliability of the audit records cannot be guaranteed.",
        "remediation": "Navigate to the CloudTrail console, select the affected trail, and edit its configuration. In the 'Storage properties' section, ensure that the 'Enable log file integrity validation' option is checked.",
        "check_function": check_cloudtrail_log_file_validation_disabled
    },
    {
        "rule_id": "CLOUDTRAIL_004",
        "section": "Logging & Monitoring",
        "name": "CloudTrail trail without CloudWatch Logs destination",
        "severity": SEVERITY["MEDIUM"],
        "description": "A CloudTrail trail has been detected that does not have a CloudWatch Logs destination configured. This prevents the ability to create metric filters and alarms for real-time monitoring of critical API calls, such as root user logins, security group changes, or unauthorized API activity.",
        "remediation": "Navigate to the CloudTrail console, select the affected trail, and edit its configuration. In the 'CloudWatch Logs' section, enable the option and either create a new log group or select an existing one to send the logs to.",
        "check_function": check_cloudtrail_cloudwatch_destination_disabled
    },
    {
        "rule_id": "CONNECTIVITY_001",
        "section": "Network & Connectivity",
        "name": "Network segmentation review recommended",
        "severity": SEVERITY["INFO"],
        "description": "The use of advanced network components such as VPC Peering, Transit Gateway, VPNs, or VPC Endpoints has been detected. These services indicate a complex network architecture that interconnects different environments. It is a good practice to perform network segmentation tests to ensure that the isolation between VPCs and on-premises networks is as expected and that no unintended communication paths exist.",
        "remediation": "Plan and execute a network segmentation test. Verify that only explicitly permitted traffic flows are possible between the different network segments (e.g., development, pre-production, production) and with corporate networks.",
        "check_function": check_network_connectivity_exists
    },
    {
        "rule_id": "DB_001",
        "section": "Network & Connectivity",
        "name": "RDS instance with public access",
        "severity": SEVERITY["HIGH"],
        "description": "An RDS database instance has been detected that is configured to be publicly accessible from the Internet. This exposes the database to direct attacks, such as brute-force attempts, SQL injection, or vulnerability exploitation, and significantly increases the risk of a data breach.",
        "remediation": "Navigate to the RDS console, select the affected instance, and click 'Modify'. In the 'Connectivity' section, change the 'Public access' option from 'Yes' to 'No'. Ensure that your resources within the VPC (such as EC2 instances or Lambda functions) have the necessary network connectivity to access the database privately.",
        "check_function": check_rds_publicly_accessible
    },
    {
        "rule_id": "DB_002",
        "section": "Data Protection",
        "name": "RDS instance is not encrypted at rest",
        "severity": SEVERITY["CRITICAL"],
        "description": "An RDS database instance has been detected that does not have storage encryption enabled. This is a critical security gap, especially for PCI DSS compliance, as it leaves sensitive data unprotected on the underlying storage.",
        "remediation": "Encryption must be enabled at the time of instance creation. To remediate this, create a snapshot of the unencrypted instance, copy the snapshot while enabling encryption on the copy, and finally, restore the database from the new encrypted snapshot.",
        "check_function": check_rds_instance_unencrypted
    },
    {
        "rule_id": "DB_003",
        "section": "Data Protection",
        "name": "Aurora cluster is not encrypted at rest",
        "severity": SEVERITY["CRITICAL"],
        "description": "An Aurora database cluster has been detected that does not have storage encryption enabled. As with RDS, this is a critical risk that exposes data to unauthorized access at the disk level.",
        "remediation": "Encryption for an Aurora cluster is defined at the time of its creation. To fix this finding, it is necessary to create a new cluster with encryption enabled and migrate the data from the unencrypted cluster.",
        "check_function": check_aurora_cluster_unencrypted
    },
    {
        "rule_id": "DB_004",
        "section": "Data Protection",
        "name": "DynamoDB table is not encrypted with a managed key",
        "severity": SEVERITY["HIGH"],
        "description": "A DynamoDB table has been detected that does not use encryption at rest with a customer-managed key (CMK) or an AWS-managed key (KMS). Although DynamoDB encrypts data by default, using KMS keys provides an additional layer of control and auditability.",
        "remediation": "In the DynamoDB console, select the table, go to the 'Additional settings' tab, and in the 'Encryption at rest' section, change the encryption key to an AWS-managed (KMS) or customer-managed (CMK) key.",
        "check_function": check_dynamodb_table_unencrypted
    },
    {
        "rule_id": "DB_005",
        "section": "Data Protection",
        "name": "DocumentDB cluster is not encrypted at rest",
        "severity": SEVERITY["CRITICAL"],
        "description": "A DocumentDB cluster has been detected that does not have storage encryption enabled. This is a critical security risk, as the data on the disk is not protected against unauthorized access.",
        "remediation": "Encryption for DocumentDB must be enabled during cluster creation and cannot be changed afterward. Remediation involves creating a new cluster with encryption enabled and migrating the data.",
        "check_function": check_docdb_cluster_unencrypted
    },
    {
        "rule_id": "EXPOSURE_001",
        "section": "Internet Exposure",
        "name": "Load Balancer with outdated TLS Policy",
        "severity": SEVERITY["HIGH"],
        "description": "A public load balancer (ALB/NLB) has been detected whose HTTPS/TLS listener allows the use of outdated TLS versions (TLS 1.0 or TLS 1.1). These protocols have known vulnerabilities (such as POODLE and BEAST) and do not support modern encryption algorithms, exposing traffic to potential interception and decryption attacks.",
        "remediation": "Navigate to the EC2 console -> Load Balancers. Select the affected listener and edit its configuration to assign a modern security policy that requires at least TLSv1.2, such as 'ELBSecurityPolicy-TLS-1-2-2017-01' or a later version.",
        "check_function": check_alb_outdated_tls_policy
    },
    {
        "rule_id": "EXPOSURE_002",
        "section": "Internet Exposure",
        "name": "EC2 instance with a public IP address",
        "severity": SEVERITY["MEDIUM"],
        "description": "An EC2 instance has been detected with a public IP address, making it directly accessible from the Internet. This increases the attack surface, exposing it to scans, brute-force attacks, and exploitation of unpatched vulnerabilities.",
        "remediation": "Review if the instance requires direct public access. If not, disassociate the Elastic IP or modify the subnet settings to prevent auto-assignment of public IPs. If public access is necessary, ensure its Security Group is highly restrictive, allowing traffic only from trusted sources on the required ports.",
        "check_function": check_ec2_publicly_exposed
    },
    {
        "rule_id": "ACM_001",
        "section": "Security Services",
        "name": "Expired ACM certificate detected",
        "severity": SEVERITY["HIGH"],
        "description": "A certificate managed by AWS Certificate Manager (ACM) has been detected that has expired. Expired certificates cause trust errors in browsers and can disrupt service for applications that use them.",
        "remediation": "Navigate to the ACM console, locate the affected certificate by its domain name, and proceed to renew it. If the certificate is no longer in use, delete it to avoid alerts.",
        "check_function": check_acm_expired_certificates
    },
    {
        "rule_id": "KMS_001",
        "section": "Data Protection",
        "name": "Customer Managed KMS Key with Rotation Disabled",
        "severity": SEVERITY["MEDIUM"],
        "description": "A customer-managed KMS key (CMK) has been detected without automatic key rotation enabled. Regularly rotating keys is a security best practice that limits the potential impact of a compromised key and reduces the amount of data protected by a single encryption key version.",
        "remediation": "Navigate to the KMS console, select the affected key, and go to the 'Key rotation' tab. Check the box to enable automatic key rotation. AWS will then automatically generate new key material every year.",
        "check_function": check_kms_customer_key_rotation_disabled
    },
    {
        "rule_id": "ECR_001",
        "section": "Vulnerability Management",
        "name": "ECR repository with mutable image tags",
        "severity": SEVERITY["MEDIUM"],
        "description": "An ECR repository allows image tags to be overwritten. This practice goes against the principle of immutability and can lead to confusion in deployments, making it difficult to track which version of an image is running. In a worst-case scenario, a malicious image could be pushed with a production tag.",
        "remediation": "Navigate to the ECR console, select the repository, and edit its settings to change 'Tag immutability' to 'Immutable'. This ensures that once an image tag is pushed, it cannot be modified.",
        "check_function": check_ecr_tag_mutability
    },
    {
        "rule_id": "ECR_002",
        "section": "Vulnerability Management",
        "name": "ECR repository with scan on push disabled",
        "severity": SEVERITY["HIGH"],
        "description": "An ECR repository does not automatically scan images for vulnerabilities upon being pushed. This is a critical security gap, as it allows potentially vulnerable container images to be stored and later deployed into production environments without a security check.",
        "remediation": "Navigate to the ECR console, select the repository, and edit its settings. In the 'Image scanning' section, enable the 'Scan on push' configuration. This will trigger a vulnerability scan for every new image pushed to the repository.",
        "check_function": check_ecr_scan_on_push_disabled
    },
    {
        "rule_id": "WAF_001",
        "section": "Logging & Monitoring",
        "name": "WAF with disabled Sampled Requests",
        "severity": SEVERITY["LOW"],
        "description": "A Web ACL does not have 'Sampled Requests' enabled. While not as critical as full logging, this feature provides free, real-time visibility into the traffic that matches the rules, which is very useful for debugging and operational monitoring.",
        "remediation": "Navigate to the WAF console, select the affected Web ACL, go to the 'Visibility and metrics' tab, and enable the 'Sampled requests' option.",
        "check_function": check_waf_sampled_requests_disabled
    },
    {
        "rule_id": "WAF_002",
        "section": "Logging & Monitoring",
        "name": "WAF Web ACL with Full Logging Disabled",
        "severity": SEVERITY["HIGH"],
        "description": "A Web ACL does not have a logging destination configured. This is a critical security gap as it prevents the collection of detailed traffic logs necessary for incident investigation, forensic analysis, and compliance auditing. Without these logs, it is nearly impossible to analyze an attack or troubleshoot false positives.",
        "remediation": "Navigate to the WAF console, select the affected Web ACL, go to the 'Logging and metrics' tab, and enable logging. You will need to configure an Amazon Kinesis Data Firehose as the destination to store the logs, which can then be sent to S3, CloudWatch, or other analysis tools.",
        "check_function": check_waf_logging_destination_disabled
    },
    {
        "rule_id": "COMPUTE_001",
        "section": "Identity & Access",
        "name": "Running EC2 instance has no IAM role associated",
        "severity": SEVERITY["MEDIUM"],
        "description": "An active EC2 instance has been detected without an associated IAM role. This directly implies that it lacks the necessary permissions to interact with other AWS services. For example, it cannot send logs to CloudWatch, which prevents security tools installed on the instance (like a FIM such as OSSEC) from forwarding their critical alerts. This creates a major gap in security visibility and centralized monitoring.",
        "remediation": "Create an IAM role with the minimum necessary permissions for the instance's function (e.g., 'CloudWatchAgentServerPolicy' for logging). Then, navigate to the EC2 console, select the instance, and under 'Actions' -> 'Security' -> 'Modify IAM role', attach the newly created role.",
        "check_function": check_ec2_instance_missing_iam_role
    }
]