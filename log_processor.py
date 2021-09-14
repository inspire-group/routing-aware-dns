# log processing script

import boto3
import botocore
import json
import gzip
import routing_aware_dns_resolver as dns_resolver
import linecache
from datetime import date, datetime
import time
import sys
import logging
import multiprocessing as mp
import os
from pathlib import Path

# sample 1 in 1000 certificates
# single thread with 10 second timeout per domain
TODAY = date.today().strftime("%Y%m%d")
DATA_BUCKET_NAME = "letsencryptdata"
RES_BUCKET_NAME = "letsencryptdnsresults"
LOG_FOLDER = "le_logs/"
LOG_FILE = "den-issuance.log-20210830.gz"  # f'issuance.log.den-{TODAY}.gz'
CRED_PROFILE = "dns_res"
LOOKUP_FOLDER = "lookup_results/"
RES_FILE = f"lookup-results-{TODAY}.txt"
FULL_LKUP_FILE = f"lookups-archive-{TODAY}.gz"
LOGGER_FILE = f"log-{TODAY}.log"
JSON_TAG = "JSON="
MAX_COUNT = 10000
NUM_REPEAT_LKUPS = 10
NUM_TASKS = 10

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
        if not Path(LOG_FOLDER + log_file).is_file():
            bucket.download_file(log_file, LOG_FOLDER + log_file)
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
def parse(log_file, cert_count, manager=None):

    out_q = manager.Queue()
    certs_seen = set()
    start = time.time()
    with gzip.open(LOG_FOLDER + log_file) as f:
        # linecount = sum(1 for line in f)
        for line in f:
            if len(certs_seen) >= cert_count:
                break
            l = line.decode()
            le_ts = l[:l.index(" ")]
            cert_log = json.loads(l[l.index(JSON_TAG)+len(JSON_TAG):])
            urls = list(cert_log['Authorizations'].keys())
            id_code = cert_log['ID']
            if id_code not in certs_seen:  # sometimes duplicate lines in logs
                certs_seen.add(id_code)
                out_q.put((id_code, urls, le_ts))

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
    session = boto3.Session()
    m = mp.Manager()  # TODO: enable multiprocessing with a flag

    read_log_from_bucket(session, log_file)
    certs = parse(log_file, MAX_COUNT, m)
    lookup_res = resolve_dns(m, certs)
    write_logs_to_bucket(session)
    logging.info('Successfuly logged DNS lookups.')
    return 0


def get_lookups(id_, urls):

    successful = 0
    failed = 0

    summary = {}
    full_lkups = {}
    for url in urls:
        domain_full_lookups = []
        domain_smry = []
        for iter in range(NUM_REPEAT_LKUPS):
            lookup_ts = str(datetime.now().astimezone())
            try:
                lookup = dns_resolver.perform_full_name_lookup(url)
                ipv4_lkup = lookup.pop("lookup_ipv4")
                ipv6_lkup = lookup.pop("lookup_ipv6")
                domain_full_lookups.append((lookup_ts, ipv4_lkup, ipv6_lkup))
                domain_smry.append((lookup_ts, lookup))
                successful += 1
            except Exception as e:
                # print(f'Failed to resolve domain {url} for ID {id_}: {str(e)}')
                logging.debug(f'Failed to resolve domain {url} for ID {id_}: {str(e)}')
                domain_full_lookups.append((lookup_ts, str(e)))
                domain_smry.append((lookup_ts, str(e)))
                failed += 1
            
        summary[url] = domain_smry
        full_lkups[url] = domain_full_lookups

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
        cert_id, cert_urls, le_ts = cert
        lookup, succ_lkup, fail_lkup = get_lookups(cert_id, cert_urls)
        successful += succ_lkup
        failed += fail_lkup
        out_q.put((lookup, le_ts))
        lookups_done.append(lookup)
        in_q.task_done()
    end = time.time()
    print(f'Time for {name} to perform {successful + failed} lookups: {(end-start):.4f} sec.')
    return (successful, failed)


def listener(write_q):
    # listens for lookup messages on the queue and writes to file
    counter = 0
    with open(RES_FILE, "a") as f, gzip.open(FULL_LKUP_FILE, "wb") as f2:
        finished = False
        while not finished:
            print('listening...')
            msg = write_q.get()
            if msg == 'end':  # all done!
                f.close()
                finished = True
                write_q.task_done()
            else:
                lookup, le_ts = msg
                stats = {"ID": lookup["ID"], "le_ts": le_ts, "summary": lookup["summary"]}
                for d in stats["summary"]:
                    attempt = stats["summary"][d]
                    for a in attempt:
                        lookup_ipv4 = a[1]["backup_resolver_resp_ipv4"]
                        lookup_ipv6 = a[1]["backup_resolver_resp_ipv6"]
                        a[1]["backup_resolver_resp_ipv4"] = str(lookup_ipv4)
                        a[1]["backup_resolver_resp_ipv6"] = str(lookup_ipv6)
                full_graph = {"ID": lookup["ID"], "le_ts": le_ts, "full": lookup["full"]}
                f.write(json.dumps(stats) + '\n')
                f.flush()
                f2.write((str(full_graph) + '\n').encode())
                f2.flush()
                counter += 1
                write_q.task_done()
                if (counter % 10) == 0:
                    print(f'Recorded {counter} cert lookups so far.')


def resolve_dns(manager, cert_q):

    print('starting resolve dns')
    start = time.time()
    lookup_q = manager.Queue()

    max_proc = mp.cpu_count() + 2

    pool = mp.Pool(max_proc)

    watcher = pool.apply_async(listener, (lookup_q,))
    num_tasks = NUM_TASKS  # divide lookups into 10 tasks

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