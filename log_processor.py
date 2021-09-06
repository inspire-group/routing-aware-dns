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
import multiprocessing as mp
import os

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
MAX_COUNT = 10
NUM_REPEAT_LKUPS = 3

logging.basicConfig(filename=LOGGER_FILE, level=logging.DEBUG)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('s3transfer').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)


def read_log_from_bucket(session, log_file):
    logging.info(f'Reading log from bucket {DATA_BUCKET_NAME}')
    print(f'Reading log from bucket {DATA_BUCKET_NAME}')

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
    logging.info(f'Downloaded log from S3 in {(end - start):.4f} seconds.')


def write_logs_to_bucket(session):

    start = time.time()
    print(f'writing logs to bucket')
    s3 = session.resource('s3')
    result_bucket = s3.Bucket(RES_BUCKET_NAME)
    region = session.region_name
    key_prfx = TODAY + "/" + region + "/"

    result_bucket.upload_file(RES_FILE, key_prfx + "lookups_summary.txt")
    result_bucket.upload_file(FULL_LKUP_FILE, key_prfx + "full_lookups_archive.gz")

    end = time.time()
    logging.info(f'Copied lookup result files to S3 bucket {RES_BUCKET_NAME} in {(end - start):.4f} seconds.')

    return 0


'''Returns a dictionary (cert ID: URLs) of max size cert_count.
'''
def parse(manager, cert_count):

    out_q = manager.Queue()
    certs_seen = set()
    start = time.time()
    with gzip.open(LOCAL_LOG_FILE) as f:
        # linecount = sum(1 for line in f)
        for line in f:
            if len(certs_seen) >= cert_count:
                break
            l = line.decode()
            cert_log = json.loads(l[l.index(JSON_TAG)+len(JSON_TAG):])
            urls = list(cert_log['Authorizations'].keys())
            id_code = cert_log['ID']
            if id_code not in certs_seen: # many duplicate lines in logs
                certs_seen.add(id_code)
                out_q.put((id_code, urls))

    stop = time.time()
    logging.info(f'Parsed {len(certs_seen)} unique certs from log in {(stop - start):.4f} seconds.')
    return out_q


# multithreading steps:
# 1. read all certs to a dict
# 2. worker thread performs lookups
# 3. worker thread writes lookup results to log

# one certificate per line: multiple domains (easier for certificate-level stats)
# send output email 

def process_daily_log(args):

    if len(args) > 1:
        log_file = sys.argv[1]
    else:
        log_file = LOG_FILE

    print(f'Performing lookups for log file {log_file}')
    logging.info(f'Performing lookups for log file {log_file}')
    session = boto3.Session(profile_name=CRED_PROFILE)
    m = mp.Manager()  # TODO: enable multiprocessing with a flag

    read_log_from_bucket(session, log_file)
    certs = parse(m, MAX_COUNT)
    lookup_res = resolve_dns(m, certs)
    write_logs_to_bucket(session)
    logging.info('Successfuly logged DNS lookups.')
    return 0


def get_lookups(id_, urls):

    successful = 0
    failed = 0
    lookups = []
    for url in urls:
        domain_lookups = []
        for iter in range(NUM_REPEAT_LKUPS):
            try:
                lookup = dns_resolver.perform_full_name_lookup(url)
                domain_lookups.append(lookup)
                successful += 1
            except Exception as e:
                print(f'Failed to resolve domain {url} for ID {id_}: {str(e)}')
                logging.debug(f'Failed to resolve domain {url} for ID {id_}: {str(e)}')
                domain_lookups.append(str(e))
                failed += 1
            
        lookups.append(domain_lookups)

    summary = {}
    full_lkups = {}
    for i in range(len(lookups)):
        url_lkup = lookups[i]
        ipv4_lkup = [_.pop("lookup_ipv4") if isinstance(_, dict) else _ for _ in url_lkup]
        ipv6_lkup = [_.pop("lookup_ipv6") if isinstance(_, dict) else _ for _ in url_lkup]
        summary[urls[i]] = url_lkup
        full_lkups[urls[i]] = (ipv4_lkup, ipv6_lkup)

    lookup_result = {"ID": id_, "summary": summary, "full": full_lkups}
    return (lookup_result, successful, failed)


def worker(in_q, out_q):
    # in_q: contains certificates that need to be looked up
    # out_q: contains lookup results
    name = os.getpid()
    successful = 0
    failed = 0
    start = time.time()
    lookups_done = []
    print('in worker thread')
    while True:
        cert = in_q.get()
        if cert is None:
            print(f'Worker {name} exiting: queue empty')
            break
        cert_id, cert_urls = cert
        lookup, succ_lkup, fail_lkup = get_lookups(cert_id, cert_urls)
        successful += succ_lkup
        failed += fail_lkup
        out_q.put(lookup)
        lookups_done.append(lookup)
        in_q.task_done()
    end = time.time()
    print(f'Time for {name} to perform {successful + failed} lookups: {(end-start):.4f} sec.')
    return (successful, failed)


def listener(write_q):
    # listens for lookup messages on the queue and writes to file
    with open(RES_FILE, "a") as f, gzip.open(FULL_LKUP_FILE, "wb") as f2:
        finished = False
        while not finished:
            print('listening...')
            msg = write_q.get()
            if msg == 'end': # all done!
                f.close()
                finished = True
                write_q.task_done()
                # break
            else:
                lookup = msg
                stats = {"ID": lookup["ID"], "summary": lookup["summary"]}
                full_graph = {"ID": lookup["ID"], "full": lookup["full"]}
                f.write(str(stats) + '\n')
                f.flush()
                f2.write((str(full_graph) + '\n').encode())
                f2.flush()             
                write_q.task_done()


def resolve_dns(manager, cert_q):

    print('starting resolve dns')
    start = time.time()
    lookup_q = manager.Queue()

    max_proc = mp.cpu_count() + 2

    pool = mp.Pool(max_proc)

    watcher = pool.apply_async(listener, (lookup_q,))
    num_tasks = 10  # roughly do 10 lookups a task

    for i in range(num_tasks):
        cert_q.put(None)  # sentinel

    jobs = [pool.apply_async(worker, (cert_q, lookup_q)) for _ in range(num_tasks)]

    all_lookups = []
    for job in jobs:
        all_lookups.append(job.get())

    lookups_success, lookups_failed = [sum(i) for i in zip(*all_lookups)]

    lookup_q.put('end')
    pool.close()
    pool.join()
    end = time.time()
    tot = lookups_success + lookups_failed

    logging.info(f'Lookups completed: {lookups_success} successful {lookups_failed} failed')
    logging.info(f'{tot} lookups completed in {(end-start):.4f} seconds.')

    print(f'All the lookups done: {lookups_success} successful {lookups_failed} failed')
    print(f'Time for all tasks to finish ({MAX_COUNT} lkups): {(end-start):.4f}')
    return all_lookups


if __name__ == '__main__':

    start = time.time()
    result = process_daily_log(sys.argv)
    end = time.time()
    logging.info(f'Total of {(end - start):.4f} sec. to download, process, and resolve daily log.')