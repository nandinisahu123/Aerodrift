import asyncio
import boto3

async def collect_aws_state():
    """Collect a small, read-only AWS snapshot.

    This uses boto3 in a worker thread so the application can keep an
    asynchronous orchestration layer without blocking the event loop.
    """
    def collect():
        ec2 = boto3.client("ec2")
        groups = ec2.describe_security_groups()["SecurityGroups"]
        result = {"security_groups": [], "resources": []}
        for sg in groups:
            rules = []
            for permission in sg.get("IpPermissions", []):
                protocol = permission.get("IpProtocol", "all")
                from_port = permission.get("FromPort")
                for rng in permission.get("IpRanges", []):
                    rules.append({
                        "protocol": protocol,
                        "port": from_port,
                        "source": rng.get("CidrIp")
                    })
            result["security_groups"].append({
                "id": sg["GroupId"],
                "name": sg.get("GroupName", sg["GroupId"]),
                "rules": rules
            })
        return result
    return await asyncio.to_thread(collect)
