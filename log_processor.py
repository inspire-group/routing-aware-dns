# log processing script

import boto3
import botocore
from datetime import date, datetime
import gzip
import json
import linecache
import multiprocessing as mp
import os
from pathlib import Path
import pickle
from random import Random
import routing_aware_dns_resolver as dns_resolver
import sys
import time
import logging

# sample 1 in 1000 certificates
# single thread with 10 second timeout per domain
TODAY = date.today().strftime("%Y%m%d")
DATA_BUCKET_NAME = "letsencryptdata"
RES_BUCKET_NAME = "letsencryptdnsresults"
LOG_FOLDER = "le_logs/"
LOG_FILE = "den-issuance.log-20210829.gz"  # f'issuance.log.den-{TODAY}.gz'
LOOKUP_FOLDER = "lookup_results/"
RES_FILE = f"lookup-results-{TODAY}.txt"
FULL_LKUP_FILE = f"lookups-archive-{TODAY}.gz"
LOGGER_FILE = f"log-{TODAY}.log"
JSON_TAG = "JSON="
MAX_COUNT = 10000
NUM_REPEAT_LKUPS = 10

logging.basicConfig(filename=LOGGER_FILE,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')
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
        if not Path(log_file).is_file():
            bucket.download_file(log_file, log_file)
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


'''Returns a list of (cert ID, [domains], le_ts) tuples of length cert_count.
'''
def parse(log_file, cert_count):

    out_q = []
    certs_seen = set()
    start = time.time()

    num_lines = sum(1 for line in gzip.open(log_file))
    # use ordinal date as seed to coordinate samples across servers
    dateseed = date.today().toordinal()
    rand_gen = Random(Random(dateseed).random())
    rand_line_sample = rand_gen.sample(range(num_lines), cert_count)

    print(f'sampling lines {rand_line_sample} from the file (total number of lines: {num_lines}')
    with gzip.open(log_file) as f:
        line_ctr = 0
        for line in f:
            if line_ctr in rand_line_sample:
            # if len(certs_seen) >= cert_count:
            #     break
                l = line.decode()
                le_ts = l[:l.index(" ")]
                cert_log = json.loads(l[l.index(JSON_TAG)+len(JSON_TAG):])
                urls = list(cert_log['Authorizations'].keys())
                id_code = cert_log['ID']
                if id_code not in certs_seen:  # sometimes duplicate lines in logs
                    certs_seen.add(id_code)
                    out_q.append((id_code, urls, le_ts))
            line_ctr += 1

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
    certs = parse(log_file, MAX_COUNT)
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
            start = datetime.now()
            lookup_ts = str(start.astimezone())
            try:
                lookup = dns_resolver.perform_full_name_lookup(url)
                end = datetime.now()
                ipv4_lkup = lookup.pop("lookup_ipv4")
                ipv6_lkup = lookup.pop("lookup_ipv6")
                backup_resp_ipv4 = lookup.pop("backup_resolver_resp_ipv4")
                backup_resp_ipv6 = lookup.pop("backup_resolver_resp_ipv6")
                domain_full_lookups.append((lookup_ts, 
                                            ipv4_lkup, 
                                            ipv6_lkup, 
                                            backup_resp_ipv4, 
                                            backup_resp_ipv6))
                domain_smry.append((lookup_ts, lookup))
                successful += 1
                exec_time = end - start
                logging.debug(f'Completed a lookup for domain {url} (cert ID {id_}) in {exec_time.seconds}.{exec_time.microseconds} seconds.')
            except Exception as e:
                end = datetime.now()
                exec_time = end - start
                logging.debug(f'Failed to resolve domain {url} for ID {id_}: {str(e)} (took {exec_time.seconds}.{exec_time.microseconds} seconds.)')
                domain_full_lookups.append((lookup_ts, str(e)))
                domain_smry.append((lookup_ts, str(e)))
                failed += 1
            
        summary[url] = domain_smry
        full_lkups[url] = domain_full_lookups

    lookup_result = {"ID": id_, "summary": summary, "full": full_lkups}
    return (lookup_result, successful, failed)


def worker(in_q, out_q):
    # in_q: list of certificates that need to be looked up
    # out_q: threadsafe queue to contain lookup results
    name = os.getpid()
    successful = 0
    failed = 0
    start = time.time()
    lookups_done = []
    for cert in in_q:
        cert_id, cert_urls, le_ts = cert
        lookup, succ_lkup, fail_lkup = get_lookups(cert_id, cert_urls)
        successful += succ_lkup
        failed += fail_lkup
        out_q.put((lookup, le_ts))
        lookups_done.append(lookup)
        print(f'Worker {name} completed a lookup')
    end = time.time()
    print(f'Time for {name} to perform {successful + failed} lookups: {(end-start):.4f} sec.')
    return (successful, failed)


def listener(write_q):
    # listens for lookup messages on the queue and writes to file
    counter = 0
    with open(RES_FILE, "a") as lookup_f, gzip.open(FULL_LKUP_FILE, "wb") as archive_f:
        finished = False
        while not finished:
            print('listening...')
            msg = write_q.get()
            if msg == 'end':  # all done!
                lookup_f.close()
                archive_f.close()
                finished = True
                write_q.task_done()
            else:
                lookup, le_ts = msg
                stats = {"ID": lookup["ID"], "le_ts": le_ts, "summary": lookup["summary"]}
                full_graph = {"ID": lookup["ID"], "le_ts": le_ts, "full": lookup["full"]}
                lookup_f.write(json.dumps(stats) + '\n')
                lookup_f.flush()
                pickle.dump(full_graph, archive_f, pickle.HIGHEST_PROTOCOL)
                archive_f.flush()
                counter += 1
                write_q.task_done()
                if (counter % 10) == 0:
                    print(f'Recorded {counter} cert lookups so far.')


def split(a, n):
    k, m = divmod(len(a), n)
    return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))


def resolve_dns(manager, cert_q):

    start = time.time()

    max_proc = mp.cpu_count() + 2

    pool = mp.Pool(max_proc)
    lookup_q = manager.Queue()

    num_writers = 1
    num_workers = max_proc - num_writers

    watcher = pool.apply_async(listener, (lookup_q,))

    cert_chunks = list(split(cert_q, num_workers))
    jobs = [pool.apply_async(worker, (cert_chunks[w], lookup_q)) for w in range(num_workers)]

    all_lookups = []
    for job in jobs:
        all_lookups.append(job.get())

    lookups_success, lookups_failed = [sum(i) for i in zip(*all_lookups)]

    lookup_q.put('end')
    watcher.get()

    pool.close()
    pool.join()
    end = time.time()
    tot = lookups_success + lookups_failed

    logging.info(f'Cert lookups completed: {lookups_success} successful {lookups_failed} failed')
    logging.info(f'{tot} cert lookups completed in {(end-start):.4f} seconds.')

    print(f'All the lookups done: {lookups_success} successful {lookups_failed} failed')
    print(f'Time for all tasks to finish ({MAX_COUNT} certificate lookups): {(end-start):.4f}')
    return all_lookups


if __name__ == '__main__':

    start = time.time()
    result = process_daily_log(sys.argv)
    end = time.time()
    logging.info(f'Total of {(end - start):.4f} sec. to download, process, and resolve daily log.')