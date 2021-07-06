# log processing script

import boto3
import botocore
import json
import gzip
import routing_aware_dns_resolver as dns_resolver
from datetime import date

# sample 1 in 1000 certificates
# single thread with 10 second timeout per domain
BUCKET_NAME = "letsencryptdata"
LOG_FILE = "ra-data-dc1-11.log.gz" # f'issuance.log.den-{date.today().strftime("%y%m%d")}.gz'
LOCAL_LOG_FILE = "local.log.gz"
CRED_PROFILE = "dns_res"
RES_FILE = "dns_resolver_results.log"
JSON_TAG = "JSON="
MAX_COUNT = 10000


def read_log_from_bucket(session):
    print(f'reading log from bucket {BUCKET_NAME}')
    s3 = session.resource('s3')
    bucket = s3.Bucket(BUCKET_NAME)

    try:
        bucket.download_file(LOG_FILE, LOCAL_LOG_FILE)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == '404':
            # think of some notification mechanism to put here
            print(f'The object {LOG_FILE} does not exist')
        else:
            print(f'Download failed')
            raise e


def parse():

    cert_url_dict = {}

    with gzip.open(LOCAL_LOG_FILE) as f:
        for line in f:
            if len(cert_url_dict) >= MAX_COUNT:
                break
            l = line.decode()
            cert_log = json.loads(l[l.index(JSON_TAG)+len(JSON_TAG):])
            urls = list(cert_log['Authorizations'].keys())
            id_code = cert_log['ID']
            if id_code not in cert_url_dict: # many duplicate lines in logs
                cert_url_dict[id_code] = urls

    print(f'Found {len(cert_url_dict)} unique log entries')
    return cert_url_dict


def resolve_dns(cert_url_dict):

    with open(RES_FILE, "a") as f:
        for id_, urls in cert_url_dict.items():
            res_json = {}
            res_json['ID'] = id_
            lookups = [dns_resolver.performFullLookupForName(_) for _ in urls]
            lookup_json = {urls[i]: lookups[i] for i in range(len(urls))}
            res_json['Authorization_lookups'] = lookup_json
            f.write(f'{res_json}\n')


# one certificate per line: multiple domains
# easier to  certificate-level stats
# send output email 

def process_daily_log():

    session = boto3.Session(profile_name=CRED_PROFILE)
    read_log_from_bucket(session)
    certs = parse()
    resolve_dns(certs)
    print('Successfuly performed DNS lookups')
    return 0