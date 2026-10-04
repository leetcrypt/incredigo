import subprocess, time, sys, boto3
from botocore.config import Config
from botocore.exceptions import ClientError

EP="http://127.0.0.1:5000"
srv=subprocess.Popen(["/home/ubuntu/moto-venv/bin/moto_server","-p","5000"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)
def iam(k=None,s=None):
    return boto3.client("iam",endpoint_url=EP,region_name="us-east-1",
        aws_access_key_id=k or "admin",aws_secret_access_key=s or "admin")
def sts(k,s):
    return boto3.client("sts",endpoint_url=EP,region_name="us-east-1",
        aws_access_key_id=k,aws_secret_access_key=s)
try:
    a=iam()
    a.create_user(UserName="labapp")
    ak=a.create_access_key(UserName="labapp")["AccessKey"]
    oid,osec=ak["AccessKeyId"],ak["SecretAccessKey"]
    print("seed key:",oid)

    # Q1: CreateAccessKey WITHOUT UserName, signed by the seed key
    try:
        nk=iam(oid,osec).create_access_key()["AccessKey"]
        print("Q1 create-without-username: OK ->",nk["AccessKeyId"])
        nid,nsec=nk["AccessKeyId"],nk["SecretAccessKey"]
    except ClientError as e:
        print("Q1 create-without-username: FAIL", e.response["Error"]["Code"], e.response["Error"]["Message"][:80])
        nid=nsec=None

    # Q2: GetCallerIdentity with seed key
    try:
        ci=sts(oid,osec).get_caller_identity()
        print("Q2 sts seed:", ci.get("Arn"))
    except ClientError as e:
        print("Q2 sts seed FAIL", e.response["Error"]["Code"])

    # Q3: DeleteAccessKey WITHOUT UserName (delete seed itself), signed by seed
    try:
        iam(oid,osec).delete_access_key(AccessKeyId=oid)
        print("Q3 delete-without-username (self): OK")
    except ClientError as e:
        print("Q3 delete-without-username: FAIL", e.response["Error"]["Code"], e.response["Error"]["Message"][:80])

    # Q4: after deleting seed, does it still authenticate to STS / IAM?
    try:
        ci=sts(oid,osec).get_caller_identity()
        print("Q4 sts old-after-delete: STILL WORKS", ci.get("Arn"))
    except ClientError as e:
        print("Q4 sts old-after-delete: rejected", e.response["Error"]["Code"])

    # Q5: list access keys (admin) — is old gone, new present?
    keys=[k["AccessKeyId"] for k in iam().list_access_keys(UserName="labapp")["AccessKeyMetadata"]]
    print("Q5 list after delete:", keys, "| old-present:", oid in keys, "| new-present:", nid in keys if nid else "n/a")
finally:
    srv.terminate()
