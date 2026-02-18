# collectors/databases.py
import json
import boto3
from botocore.exceptions import ClientError
from .utils import get_all_aws_regions  # Importación relativa


def collect_database_data(session):
    """
    Recolecta datos de servicios de BBDD en AWS con detalles de cifrado,
    subnets y VPC: RDS, Aurora, DynamoDB y DocumentDB.
    """
    rds_instances = []
    aurora_clusters = []
    dynamodb_tables = []
    documentdb_clusters = []

    # Regiones
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

            # ----- Aliases de KMS por TargetKeyId (excluye alias/aws/*) -----
            alias_map = {}
            try:
                paginator = kms_client.get_paginator("list_aliases")
                for page in paginator.paginate():
                    for alias in page.get("Aliases", []):
                        alias_name = alias.get("AliasName")
                        if alias.get("TargetKeyId") and not (alias_name or "").startswith("alias/aws/"):
                            alias_map[alias["TargetKeyId"]] = alias_name
            except ClientError:
                # No interrumpir si no hay permisos de KMS
                pass

            # ----- Helper: obtener SubnetIds y VpcId a partir del DBSubnetGroup -----
            def get_subnet_and_vpc_info(db_subnet_group_name):
                if not db_subnet_group_name:
                    return [], None
                try:
                    resp = rds_client.describe_db_subnet_groups(DBSubnetGroupName=db_subnet_group_name)
                    subnet_group = resp.get("DBSubnetGroups", [{}])[0]
                    subnets = subnet_group.get("Subnets", [])
                    subnet_ids = [s.get("SubnetIdentifier") for s in subnets if s.get("SubnetIdentifier")]
                    vpc_id = subnet_group.get("VpcId")
                    return subnet_ids, vpc_id
                except ClientError:
                    # Retornar vacío si no hay permisos o el grupo no existe
                    return [], None

            # ==================================================================
            # 2) Aurora (corregido: obtiene SGs, Subnets y VPC; mapea alias KMS)
            # ==================================================================
            aurora_paginator = rds_client.get_paginator("describe_db_clusters")
            for page in aurora_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    engine = (cluster.get("Engine") or "").lower()
                    if "aurora" in engine:
                        kms_key_id = cluster.get("KmsKeyId")
                        key_id_for_lookup = kms_key_id.split("/")[-1] if kms_key_id else None
                        sg_ids = [sg.get("VpcSecurityGroupId") for sg in cluster.get("VpcSecurityGroups", []) if sg.get("VpcSecurityGroupId")]
                        subnet_ids, vpc_id = get_subnet_and_vpc_info(cluster.get("DBSubnetGroup"))

                        aurora_clusters.append(
                            {
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
                                "SecurityGroupIds": sg_ids,
                            }
                        )

            # ==================================================================
            # 3) RDS Instances (corregido: SGs, Subnets/VPC, alias KMS)
            # ==================================================================
            rds_paginator = rds_client.get_paginator("describe_db_instances")
            for page in rds_paginator.paginate():
                for instance in page.get("DBInstances", []):
                    # Omitir las instancias que pertenecen a un cluster de Aurora
                    if instance.get("DBClusterIdentifier"):
                        continue

                    kms_key_id = instance.get("KmsKeyId")
                    key_id_for_lookup = kms_key_id.split("/")[-1] if kms_key_id else None

                    db_subnet_group = instance.get("DBSubnetGroup") or {}
                    subnet_ids, vpc_id = get_subnet_and_vpc_info(db_subnet_group.get("DBSubnetGroupName"))
                    sg_ids = [sg.get("VpcSecurityGroupId") for sg in instance.get("VpcSecurityGroups", []) if sg.get("VpcSecurityGroupId")]

                    rds_instances.append(
                        {
                            "Region": region,
                            "DBInstanceIdentifier": instance.get("DBInstanceIdentifier"),
                            "DBInstanceClass": instance.get("DBInstanceClass"),
                            "Engine": instance.get("Engine"),
                            "DBInstanceStatus": instance.get("DBInstanceStatus"),
                            "PubliclyAccessible": instance.get("PubliclyAccessible", False),
                            "Endpoint": (instance.get("Endpoint") or {}).get("Address", "N/A"),
                            "Encrypted": instance.get("StorageEncrypted", False),
                            "KmsKeyId": kms_key_id,
                            "KmsKeyAlias": alias_map.get(key_id_for_lookup, kms_key_id or "N/A"),
                            "ARN": instance.get("DBInstanceArn"),
                            "SubnetIds": subnet_ids,
                            "VpcId": vpc_id,
                            "SecurityGroupIds": sg_ids,
                        }
                    )

            # ==================================================================
            # 4) DynamoDB (ajuste de indentación + alias KMS si aplica)
            # ==================================================================
            dynamo_paginator = dynamodb_client.get_paginator("list_tables")
            for page in dynamo_paginator.paginate():
                for table_name in page.get("TableNames", []):
                    details = dynamodb_client.describe_table(TableName=table_name).get("Table", {})
                    sse_details = details.get("SSEDescription")
                    kms_key_arn = sse_details.get("KMSMasterKeyArn") if sse_details else None
                    key_id_for_lookup = kms_key_arn.split("/")[-1] if kms_key_arn else None

                    alias = "N/A"
                    if sse_details and sse_details.get("Status") == "ENABLED":
                        alias = alias_map.get(key_id_for_lookup, kms_key_arn or "AWS Owned Key")

                    dynamodb_tables.append(
                        {
                            "Region": region,
                            "TableName": table_name,
                            "Status": details.get("TableStatus"),
                            "ItemCount": details.get("ItemCount", 0),
                            "SizeBytes": details.get("TableSizeBytes", 0),
                            "Encrypted": bool(sse_details and sse_details.get("Status") == "ENABLED"),
                            "KmsKeyId": key_id_for_lookup,
                            "KmsKeyAlias": alias,
                            "ARN": details.get("TableArn"),
                        }
                    )

            # ==================================================================
            # 5) DocumentDB Clusters (corregido: SGs, Subnets/VPC, alias KMS)
            # ==================================================================
            docdb_paginator = docdb_client.get_paginator("describe_db_clusters")
            for page in docdb_paginator.paginate():
                for cluster in page.get("DBClusters", []):
                    kms_key_id = cluster.get("KmsKeyId")
                    key_id_for_lookup = kms_key_id.split("/")[-1] if kms_key_id else None
                    sg_ids = [sg.get("VpcSecurityGroupId") for sg in cluster.get("VpcSecurityGroups", []) if sg.get("VpcSecurityGroupId")]
                    subnet_ids, vpc_id = get_subnet_and_vpc_info(cluster.get("DBSubnetGroup"))

                    documentdb_clusters.append(
                        {
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
                            "SecurityGroupIds": sg_ids,
                        }
                    )

        except ClientError as e:
            common = {
                "InvalidClientTokenId",
                "UnrecognizedClientException",
                "AuthFailure",
                "AccessDeniedException",
                "OptInRequired",
            }
            if e.response.get("Error", {}).get("Code") not in common:
                print(f"[databases] Error en región {region}: {e}")
            continue

    return {
        "rds_instances": rds_instances,
        "aurora_clusters": aurora_clusters,
        "dynamodb_tables": dynamodb_tables,
        "documentdb_clusters": documentdb_clusters,
    }