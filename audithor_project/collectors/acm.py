# collectors/acm.py
import json
import boto3
from botocore.exceptions import ClientError, ConnectTimeoutError, EndpointConnectionError
from .utils import get_all_aws_regions # Importación relativa


def collect_acm_data_web(session: boto3.Session):
    """
    Collects details for all ACM certificates from all available AWS regions.

    This function iterates through every AWS region where AWS Certificate Manager (ACM)
    is available. It lists all certificates in each region, fetches their
    detailed information, and compiles them into a single list.

    Args:
        session: A Boto3 session instance used to create AWS clients.

    Returns:
        A dictionary with one key, 'certificates', containing a list of dictionaries.
        Each dictionary holds the detailed information for an ACM certificate,
        sorted by region and then by domain name.

    Example:
        >>> import boto3
        >>> aws_session = boto3.Session()
        >>> acm_data = collect_acm_data_web(aws_session)
    """
    all_regions = session.get_available_regions('acm')
    result_certificates = []

    # Iterate through each region where ACM service is available.
    for region in all_regions:
        try:
            acm_client = session.client("acm", region_name=region)
            paginator_certs = acm_client.get_paginator('list_certificates')
            
            # Paginate through all certificates in the current region.
            for page in paginator_certs.paginate():
                for cert_summary in page.get('CertificateSummaryList', []):
                    cert_arn = cert_summary['CertificateArn']
                    try:
                        # Fetch the full details for each certificate.
                        cert_details = acm_client.describe_certificate(
                            CertificateArn=cert_arn
                        )['Certificate']
                        
                        # Add the region to the details for context.
                        cert_details['Region'] = region

                        # Convert datetime objects to ISO format strings for serialization.
                        if 'IssuedAt' in cert_details:
                            cert_details['IssuedAt'] = cert_details['IssuedAt'].isoformat()
                        if 'NotAfter' in cert_details:
                            cert_details['NotAfter'] = cert_details['NotAfter'].isoformat()
                        
                        result_certificates.append(cert_details)

                    except (ClientError, ConnectTimeoutError, EndpointConnectionError) as e:
                        if "OptInRequired" in str(e) or "endpoint" in str(e):
                            continue

        except (ClientError, ConnectTimeoutError, EndpointConnectionError) as e:
            # Skip regions not enabled, opt-in, or unreachable (e.g. me-south-1)
            continue

    # Sort the final list of certificates by Region, then by Domain Name.
    result_certificates.sort(key=lambda x: (x.get('Region', ''), x.get('DomainName', '')))
    
    return {"certificates": result_certificates}

