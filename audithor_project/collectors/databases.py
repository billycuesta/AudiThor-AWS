# collectors/databases.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


# collectors/databases.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions # Importación relativa


def collect_database_data(session):
    """
    Collects data on AWS database services, including detailed encryption, SUBNET, and VPC info.

    This function scans all accessible AWS regions for RDS instances, Aurora
    clusters, DynamoDB tables, and DocumentDB clusters. It now also resolves
    the DBSubnetGroup for RDS and Aurora to retrieve the specific Subnet IDs and the VpcId,
    which is crucial for network diagramming.
    """
    rds_instances = []
    aurora_clusters = []
    dynamodb_tables = []
    documentdb_clusters = []
    
    try:
        regions = session.get_available_regions("rds")
    except ClientError:
        regions = get_all_aws_regions(session)

    for region in regions:
        try:
            rds_client = session.client("rds", region_name=region)
            dynamodb_client = session.client("dynamodb", region_name=region)
            docdb_client = session.client("docdb", region_name=region)
            kms_client = session.client("kms", region_name=region)

            alias_map = {}
            try:
                paginator = kms_client.get_paginator('list_aliases')
                for page in paginator.paginate():
                    for alias in page.get('Aliases', []):
                        alias_name = alias.get('AliasName')
                        if alias.get('TargetKeyId') and not alias_name.startswith('alias/aws/'):
                            alias_map[alias['TargetKeyId']] = alias_name
            except ClientError:
                pass

            # --- FUNCIÓN INTERNA MEJORADA PARA OBTENER SUBNETS Y VPC ID ---
            def get_subnet_and_vpc_info(db_subnet_group_name):
                if not db_subnet_group_name:
                    return [], None
                try:
                    subnet_group_details = rds_client.describe_db_subnet_groups(
                        DBSubnetGroupName=db_subnet_group_name
                    ).get('DBSubnetGroups', [{}])[0]
                    
                    subnets = subnet_group_details.get('Subnets', [])
                    subnet_ids = [s['SubnetIdentifier'] for s in subnets]
                    vpc_id = subnet_group_details.get('VpcId')
                    return subnet_ids, vpc_id
                except ClientError:
                    return [], None # Retorna vacío si hay error

            # --- 2. Collect Aurora Clusters (CORREGIDO) ---
            aurora_paginator = rds_client.get_paginator("describe_db_clusters")
            for page in aurora_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    kms_key_id = cluster.get("KmsKeyId")
                    key_id_for_lookup = kms_key_id.split('/')[-1] if kms_key_id else None
                    sg_ids = [sg['VpcSecurityGroupId'] for sg in cluster.get('VpcSecurityGroups', [])]
                    subnet_ids, vpc_id = get_subnet_and_vpc_info(cluster.get("DBSubnetGroup"))
                    
                    aurora_clusters.append({
                        "Region": region,
                        "ClusterIdentifier": cluster.get("DBClusterIdentifier"),
                        "Engine": cluster.get("Engine"),
                        "Status": cluster.get("Status"),
                        "Endpoint": cluster.get("Endpoint", "N/A"),
                        "Encrypted": cluster.get("StorageEncrypted", False),
                        "KmsKeyId": kms_key_id,
                        "KmsKeyAlias": alias_map.get(key_id_for_lookup, kms_key_id or "N/A"),
                        "ARN": cluster.get("DBClusterArn"),
                        "SubnetIds": subnet_ids,
                        "VpcId": vpc_id,
                        "SecurityGroupIds": sg_ids
                    })
            
            # --- 3. Collect RDS Instances (CORREGIDO) ---
            rds_paginator = rds_client.get_paginator("describe_db_instances")
            for page in rds_paginator.paginate():
                for instance in page.get("DBInstances", []):
                    if not instance.get("DBClusterIdentifier"):
                        kms_key_id = instance.get("KmsKeyId")
                        key_id_for_lookup = kms_key_id.split('/')[-1] if kms_key_id else None
                        
                        db_subnet_group = instance.get("DBSubnetGroup", {})
                        subnet_ids, vpc_id = get_subnet_and_vpc_info(db_subnet_group.get('DBSubnetGroupName'))
                        sg_ids = [sg['VpcSecurityGroupId'] for sg in instance.get('VpcSecurityGroups', [])]


                        rds_instances.append({
                            "Region": region,
                            "DBInstanceIdentifier": instance.get("DBInstanceIdentifier"),
                            "DBInstanceClass": instance.get("DBInstanceClass"),
                            "Engine": instance.get("Engine"),
                            "DBInstanceStatus": instance.get("DBInstanceStatus"),
                            "PubliclyAccessible": instance.get('PubliclyAccessible', False),
                            "Endpoint": instance.get("Endpoint", {}).get("Address", "N/A"),
                            "Encrypted": instance.get("StorageEncrypted", False),
                            "KmsKeyId": kms_key_id,
                            "KmsKeyAlias": alias_map.get(key_id_for_lookup, kms_key_id or "N/A"),
                            "ARN": instance.get("DBInstanceArn"),
                            "SubnetIds": subnet_ids,
                            "VpcId": vpc_id,
                            "SecurityGroupIds": sg_ids
                        })

            # --- 4. Collect DynamoDB Tables (sin cambios) ---
            dynamo_paginator = dynamodb_client.get_paginator("list_tables")
            for page in dynamo_paginator.paginate():
                 for table_name in page.get("TableNames", []):
                    details = dynamodb_client.describe_table(TableName=table_name).get("Table", {})
                    sse_details = details.get("SSEDescription")
                    kms_key_arn = sse_details.get("KMSMasterKeyArn") if sse_details else None
                    key_id_for_lookup = kms_key_arn.split('/')[-1] if kms_key_arn else None
                    
                    alias = "N/A"
                    if sse_details and sse_details.get("Status") == "ENABLED":
                        alias = alias_map.get(key_id_for_lookup, kms_key_arn or "AWS Owned Key")

                    dynamodb_tables.append({
                        "Region": region, "TableName": table_name, "Status": details.get("TableStatus"),
                        "ItemCount": details.get("ItemCount", 0), "SizeBytes": details.get("TableSizeBytes", 0),
                        "Encrypted": bool(sse_details and sse_details.get("Status") == "ENABLED"),
                        "KmsKeyId": key_id_for_lookup, "KmsKeyAlias": alias, "ARN": details.get("TableArn")
                    })

            # --- 5. Collect DocumentDB Clusters (CORREGIDO) ---
            docdb_paginator = docdb_client.get_paginator("describe_db_clusters")
            for page in docdb_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    kms_key_id = cluster.get("KmsKeyId")
                    key_id_for_lookup = kms_key_id.split('/')[-1] if kms_key_id else None
                    sg_ids = [sg['VpcSecurityGroupId'] for sg in cluster.get('VpcSecurityGroups', [])]
                    subnet_ids, vpc_id = get_subnet_and_vpc_info(cluster.get("DBSubnetGroup"))

                    documentdb_clusters.append({
                        "Region": region, "ClusterIdentifier": cluster.get("DBClusterIdentifier"),
                        "Engine": cluster.get("Engine"), "Status": cluster.get("Status"),
                        "Endpoint": cluster.get("Endpoint", "N/A"), "Encrypted": cluster.get("StorageEncrypted", False),
                        "KmsKeyId": kms_key_id, "KmsKeyAlias": alias_map.get(key_id_for_lookup, kms_key_id or "N/A"),
                        "ARN": cluster.get("DBClusterArn"),
                        "SubnetIds": subnet_ids,
                        "VpcId": vpc_id,
                        "SecurityGroupIds": sg_ids
                    })

        except ClientError as e:
            common_errors = ['InvalidClientTokenId', 'UnrecognizedClientException', 'AuthFailure', 'AccessDeniedException', 'OptInRequired']
            if e.response['Error']['Code'] not in common_errors:
                print(f"Error processing databases in region {region}: {e}")
            continue
    
    return {
        "rds_instances": rds_instances,
        "aurora_clusters": aurora_clusters,
        "dynamodb_tables": dynamodb_tables,
        "documentdb_clusters": documentdb_clusters
    }