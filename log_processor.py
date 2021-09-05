# log processing script

import boto3
import botocore
import json
import gzip
import routing_aware_dns_resolver as dns_resolver
import linecache
from datetime import date
import time
import sys
import logging
import multiprocessing
import os
from threading import Lock

# sample 1 in 1000 certificates
# single thread with 10 second timeout per domain
TODAY = date.today().strftime("%Y%m%d")
DATA_BUCKET_NAME = "letsencryptdata"
RES_BUCKET_NAME = "letsencryptdnsresults"
LOG_FILE = "retry-issuance.log.den-20210507.gz" # f'issuance.log.den-{TODAY}.gz'
LOCAL_LOG_FILE = "local.log.test.gz"
CRED_PROFILE = "dns_res"
RES_FILE = f"lookup-results-{TODAY}.txt"
FULL_LKUP_FILE = f"lookups-archive-{TODAY}.gz"
LOGGER_FILE = f"log-{TODAY}.log"
JSON_TAG = "JSON="
MAX_COUNT = 2000
NUM_REPEAT_LKUPS = 3

logging.basicConfig(filename=LOGGER_FILE, level=logging.DEBUG)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('s3transfer').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)

counter = multiprocessing.Value('i', 0)
looked_up_cert_ids = {}
cert_lock = Lock()


def add_cert_to_dict(cert_id, pid):
    cert_lock.acquire()
    try:
        looked_up_cert_ids[cert_id] = pid
    finally:
        cert_lock.release()


def read_log_from_bucket(session, log_file):
    logging.info(f'Reading log from bucket {DATA_BUCKET_NAME}')

    start = time.time()
    s3 = session.resource('s3')
    bucket = s3.Bucket(DATA_BUCKET_NAME)

    try:
        bucket.download_file(log_file, LOCAL_LOG_FILE)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == '404':
            # TODO: implement some notification mechanism to put here
            logging.error(f'The object {log_file} does not exist in bucket {DATA_BUCKET_NAME}')
        else:
            logging.error(f'Download of {log_file} failed')
            raise e

    end = time.time()
    logging.info(f'Took {(end - start):.4f} sec. to download log from S3')


def process_file(name):
    
    pass


'''Returns a dictionary (cert ID: URLs) of max size cert_count.
'''
def parse(cert_count):

    cert_url_dict = {}

    start = time.time()
    with gzip.open(LOCAL_LOG_FILE) as f:
        # linecount = sum(1 for line in f)
        for line in f:
            if len(cert_url_dict) >= cert_count:
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


# extract dictionary values from perform full lookup for name
# two separate log files: one for statistics, one for full lookups
# add the backup resolver results as well
def resolve_dns(cert_url_dict):

    start1 = time.time()
    with open(RES_FILE, "a") as f, gzip.open(FULL_LKUP_FILE, "wb") as f2:

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
                url_lkups = []
                for i in range(NUM_REPEAT_LKUPS):
                    try:
                        lookup = dns_resolver.perform_full_name_lookup(url)
                        end = time.time()
                        succ_timer += (end - start)
                        succ_lookups += 1
                        url_lkups.append(lookup)
                        # lookups.append(lookup)
                    except Exception as e:
                        end = time.time()
                        failed_timer += (end - start)
                        failed_lookups += 1
                        logging.debug(f'Failed to resolve domain {url} for ID {id_}: {str(e)}')
                        url_lkups.append(str(e))
                        # lookups.append(str(e))
                lookups.append(url_lkups)
            lookup_json = {}
            full_lkups = {}
            for i in range(len(urls)):
                url_lkup = lookups[i] # contains N lookups for the given URL (checking for path dependence)
                ipv4_lkup = [_.pop("lookup_ipv4") if isinstance(_, dict) else _ for _ in url_lkup]
                ipv6_lkup = [_.pop("lookup_ipv6") if isinstance(_, dict) else _ for _ in url_lkup]
                lookup_json[urls[i]] = url_lkups
                full_lkups[urls[i]] = (ipv4_lkup, ipv6_lkup)
            # lookup_json = {urls[i]: lookups[i] for i in range(len(urls))}
            res_json['lookups'] = lookup_json
            # results.append(res_json)
            res_json2 = {}
            res_json2['ID'] = id_
            res_json2['lookups'] = full_lkups
            f.write(f'{res_json}\n')
            f2.write(f'{res_json2}\n'.encode())
    lookup_timer = succ_timer + failed_timer    
    logging.info(f'Total time: {lookup_timer:.4f} sec. performing lookups for {len(cert_url_dict)} certs.')
    logging.info(f'Total of {succ_lookups} successful ({succ_timer:.3f} sec.) and {failed_lookups} ({failed_timer:.3f} sec.) failed lookups.')
    end1 = time.time()
    print(f'Total lookup time: {(end1 - start1):.4f} sec')
    return results


# multithreading steps:
# 1. read all certs to a dict
# 2. worker thread performs lookups
# 3. worker thread writes lookup results to log

def do_cert_lookup(cert):
    pass
    

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
    certs = parse(MAX_COUNT)
    lookup_res = resolve_dns(certs)
    logging.info('Successfuly performed DNS lookups')
    return 0


def worker(in_q, out_q):
    # in_q: contains certificates that need to be looked up
    # out_q: contains lookup results
    name = os.getpid()
    while True:
        item_cert = in_q.get()
        if item_cert is None:
            print(f'Worker {name} exiting: queue empty')
            
        lookup = resolve_dns(item_cert)


def listener(write_q):
    # listens for lookup messages on the queue and writes to file
    global counter
    pass


if __name__ == '__main__':

    start = time.time()
    result = process_daily_log(sys.argv)
    end = time.time()
    logging.info(f'Total of {(end - start):.4f} sec. to download, process, and resolve daily log.')