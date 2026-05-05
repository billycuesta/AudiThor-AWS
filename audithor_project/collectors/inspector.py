# collectors/inspector.py
import json
import boto3
from botocore.exceptions import ClientError
from collections import defaultdict
from .utils import get_all_aws_regions # Importación relativa


import boto3
from botocore.exceptions import ClientError, ConnectTimeoutError, EndpointConnectionError
from collections import defaultdict
from .utils import get_all_aws_regions  # Relative import


def collect_inspector_status(session):
    """
    Retrieves the activation status of AWS Inspector v2 for each available region.

    This function iterates through all regions where Inspector v2 is available,
    checks the account status, and compiles a list of regions where it is
    enabled or in the process of enabling.

    Args:
        session (boto3.Session): The boto3 session to use for creating clients.

    Returns:
        dict: A dictionary containing the scan status information, with the key "scan_status".
              The value is a list of dicts, each detailing the status for a region.

    Example:
        >>> current_session = boto3.Session()
        >>> status = collect_inspector_status(current_session)
        >>> print(status)
        {'scan_status': [{'Region': 'us-east-1', 'InspectorStatus': 'ENABLED', 'ScanEC2': 'ENABLED', ...}]}
    """
    result_scan_status = []
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        inspector_regions = session.get_available_regions('inspector2')
    except Exception:
        inspector_regions = []

    for region in inspector_regions:
        try:
            inspector_client = session.client("inspector2", region_name=region)
            status_response = inspector_client.batch_get_account_status(accountIds=[account_id])
            account_state = status_response.get('accounts', [{}])[0]

            if account_state.get('state', {}).get('status') in ['ENABLED', 'ENABLING']:
                resource_state = account_state.get('resourceState', {})
                status = {
                    "Region": region,
                    "InspectorStatus": account_state.get('state', {}).get('status'),
                    "ScanEC2": resource_state.get('ec2', {}).get('status'),
                    "ScanECR": resource_state.get('ecr', {}).get('status'),
                    "ScanLambda": resource_state.get('lambda', {}).get('status', 'NOT_AVAILABLE')
                }
                result_scan_status.append(status)
        except (ClientError, ConnectTimeoutError, EndpointConnectionError):
            continue
    return {"scan_status": result_scan_status}

def collect_inspector_findings(session):
    """
    Collects all active findings from AWS Inspector v2 across all enabled regions.

    This function iterates through regions, retrieves all active findings, and
    enriches EC2 instance findings with their corresponding "Name" tag.
    The final list of findings is sorted by severity.

    Args:
        session (boto3.Session): The boto3 session used for creating service clients.

    Returns:
        dict: A dictionary containing a list of all findings under the key "findings",
              sorted from CRITICAL to LOW.

    Example:
        >>> current_session = boto3.Session()
        >>> findings_report = collect_inspector_findings(current_session)
        >>> print(findings_report['findings'][0]['severity'])
        'CRITICAL'
    """
    result_findings = []
    account_id = session.client("sts").get_caller_identity()["Account"]
    try:
        inspector_regions = session.get_available_regions('inspector2')
    except Exception:
        inspector_regions = []

    for region in inspector_regions:
        try:
            inspector_client = session.client("inspector2", region_name=region)
            status_response = inspector_client.batch_get_account_status(accountIds=[account_id])
            if status_response.get('accounts', [{}])[0].get('state', {}).get('status') != 'ENABLED':
                continue

            paginator = inspector_client.get_paginator('list_findings')
            pages = paginator.paginate(filterCriteria={'findingStatus': [{'comparison': 'EQUALS', 'value': 'ACTIVE'}]})
            for page in pages:
                for finding in page.get('findings', []):
                    finding['Region'] = region
                    result_findings.append(finding)
        except (ClientError, ConnectTimeoutError, EndpointConnectionError):
            continue

    # Group EC2 instance IDs by region for efficient querying
    ec2_findings_by_region = defaultdict(list)
    for f in result_findings:
        if f.get('resources', [{}])[0].get('type') == 'AWS_EC2_INSTANCE':
            region = f['Region']
            instance_id = f['resources'][0]['id']
            ec2_findings_by_region[region].append(instance_id)

    # Map to store instance names: { "i-12345": "WebServer01" }
    instance_name_map = {}

    # Query instance names in batches for each region
    for region, instance_ids in ec2_findings_by_region.items():
        if not instance_ids:
            continue
        try:
            ec2_client = session.client('ec2', region_name=region)
            paginator = ec2_client.get_paginator('describe_instances')
            pages = paginator.paginate(InstanceIds=list(set(instance_ids)))
            for page in pages:
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        name_tag = next((tag['Value'] for tag in instance.get('Tags', []) if tag['Key'] == 'Name'), None)
                        if name_tag:
                            instance_name_map[instance['InstanceId']] = name_tag
        except (ClientError, ConnectTimeoutError, EndpointConnectionError):
            continue

    # Add the resolved name back to the finding object
    for f in result_findings:
        if f.get('resources', [{}])[0].get('type') == 'AWS_EC2_INSTANCE':
            instance_id = f['resources'][0]['id']
            f['resourceName'] = instance_name_map.get(instance_id, '')

    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFORMATIONAL': 4, 'UNDEFINED': 5}
    result_findings.sort(key=lambda f: severity_order.get(f.get('severity'), 99))
    
    return {"findings": result_findings}