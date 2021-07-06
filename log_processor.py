# log processing script

import boto3
import botocore
import json
import gzip
import routing_aware_dns_resolver as dns_resolver
from datetime import date
import time
import sys
import logging

# sample 1 in 1000 certificates
# single thread with 10 second timeout per domain
TODAY = date.today().strftime("%Y%m%d")
BUCKET_NAME = "letsencryptdata"
LOG_FILE = f'issuance.log.den-{TODAY}.gz'
LOCAL_LOG_FILE = "local.log.gz"
CRED_PROFILE = "dns_res"
RES_FILE = f"lookup-results-{TODAY}.txt"
LOGGER_FILE = f"log-{TODAY}.log"
JSON_TAG = "JSON="
MAX_COUNT = 10

logging.basicConfig(filename=LOGGER_FILE, level=logging.DEBUG)


def read_log_from_bucket(session, log_file):
    logging.info(f'Reading log from bucket {BUCKET_NAME}')

    start = time.time()
    s3 = session.resource('s3')
    bucket = s3.Bucket(BUCKET_NAME)

    try:
        bucket.download_file(log_file, LOCAL_LOG_FILE)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == '404':
            # think of some notification mechanism to put here
            logging.error(f'The object {log_file} does not exist in bucket {BUCKET_NAME}')
        else:
            logging.error(f'Download of {log_file} failed')
            raise e

    end = time.time()
    logging.info(f'Took {(end - start):.4f} sec. to download log from S3')


def parse():

    cert_url_dict = {}

    start = time.time()
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

    stop = time.time()
    logging.info(f'Took {(stop - start):.4f} sec. to read log file ({len(cert_url_dict)} unique entries parsed for resolving).')
    return cert_url_dict


def resolve_dns(cert_url_dict):

    with open(RES_FILE, "a") as f:

        succ_timer = 0.
        failed_timer = 0.
        logging.debug('Starting lookups!')
        results = []
        succ_lookups = 0
        failed_lookups = 0
        for id_, urls in cert_url_dict.items():
            start = time.time()
            res_json = {}
            res_json['ID'] = id_
            lookups = []
            for url in urls:
                start = time.time()
                try:
                    lookup = dns_resolver.performFullLookupForName(url)
                    end = time.time()
                    succ_timer += (end - start)
                    succ_lookups += 1
                    lookups.append(lookup)
                except Exception as e:
                    end = time.time()
                    failed_timer += (end - start)
                    failed_lookups += 1
                    logging.debug(f'Failed to resolve domain {url} for ID {id_}: {str(e)}')
                    lookups.append(str(e))

            lookup_json = {urls[i]: lookups[i] for i in range(len(urls))}
            res_json['Authorization_lookups'] = lookup_json
            results.append(res_json)
            f.write(f'{res_json}\n')
    lookup_timer = succ_timer + failed_timer    
    logging.info(f'Total time: {lookup_timer:.4f} sec. performing lookups for {len(cert_url_dict)} certs.')
    logging.info(f'Total of {succ_lookups} successful ({succ_timer:.3f} sec.) and {failed_lookups} ({failed_timer:.3f} sec.) failed lookups.')
    return results


# one certificate per line: multiple domains (easier for certificate-level stats)
# send output email 

def process_daily_log(args):

    if len(args) > 1:
        log_file = sys.argv[1]
    else:
        log_file = LOG_FILE
    logging.info(f'Performing lookups for log file {log_file}')
    session = boto3.Session(profile_name=CRED_PROFILE)
    read_log_from_bucket(session, log_file)
    certs = parse()
    lookup_res = resolve_dns(certs)
    logging.info('Successfuly performed DNS lookups')
    return 0


if __name__ == '__main__':

    start = time.time()
    result = process_daily_log(sys.argv)
    end = time.time()
    logging.info(f'Total of {(end - start):.4f} sec. to download, process, and resolve daily log.')