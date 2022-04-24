# log processing script

import boto3
import botocore
from datetime import date, datetime
import gzip
import lz4.frame
import json
import multiprocessing as mp
import os
from pathlib import Path
import pickle
from random import Random
import time
import logging
import argparse
import requests
import more_itertools as mit
import routing_aware_dns_resolver_async as dns_resolver

TODAY = date.today().strftime("%Y%m%d")
DATA_BUCKET_NAME = "letsencryptdata"
RES_BUCKET_NAME = "letsencryptdnsresults"
LOG_FILE = f"den-issuance.log-{TODAY}.gz"
RES_FILE = f"lookup-results-{TODAY}.txt"
FULL_LKUP_FILE = f"lookups-archive-{TODAY}.gz"
LOGGER_FILE = f"log-{TODAY}.log"
JSON_TAG = "JSON="
MAX_COUNT = 10000
RTYPE_LKUPS = {"A": 10, "AAAA": 10, "SOA": 1}

logging.basicConfig(filename=LOGGER_FILE,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    level=logging.DEBUG,
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
logging.getLogger('s3transfer').setLevel(logging.CRITICAL)
logging.getLogger('urllib3').setLevel(logging.CRITICAL)
logging.getLogger('asyncio').setLevel(logging.WARNING)


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


def gz_compress(f_nm, compr_f_nm):
    f_in = open(f_nm, 'rb')
    f_out = gzip.open(compr_f_nm, 'wb')
    f_out.writelines(f_in)
    f_out.close()
    f_in.close()    


def write_logs_to_bucket(session, log_file, part):

    start = time.time()
    print(f'writing logs to bucket')
    s3 = session.resource('s3')
    result_bucket = s3.Bucket(RES_BUCKET_NAME)
    region = session.region_name
    resp_json = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document").json()
    region = resp_json.get('region')
    le_log_date = log_file[log_file.index("-") + 1:]
    key_prfx = le_log_date + "/" + region + "/"

    gz_compress(RES_FILE, "lookups_summary.gz")
    result_bucket.upload_file("lookups_summary.gz", key_prfx + f"lookups_summary_part{part}.gz",
                              ExtraArgs={'ACL': 'bucket-owner-full-control'})

    result_bucket.upload_file(FULL_LKUP_FILE, key_prfx + f"full_lookups_archive_part{part}.gz",
                              ExtraArgs={'ACL': 'bucket-owner-full-control'})

    end = time.time()
    logging.info(f'Copied lookup result files to S3 bucket {RES_BUCKET_NAME} in {(end - start):.4f} seconds.')

    compr_log = "logfile_" + TODAY + "_part" + str(part) + ".log"
    gz_compress(LOGGER_FILE, compr_log)
    result_bucket.upload_file(compr_log, key_prfx + compr_log, 
                              ExtraArgs={'ACL': 'bucket-owner-full-control'})
    return 0


'''Returns a list of (cert ID, [domains], le_ts) tuples of length cert_count.
'''
def parse(log_file, cert_count, rand_seed, partition):

    out_q = []
    certs_seen = set()
    start = time.time()

    part, num_part = partition

    num_lines = sum(1 for line in lz4.frame.open(log_file))
    # use ordinal date as seed to coordinate samples across servers
    rand_gen = Random(Random(rand_seed).random())
    rand_line_sample = rand_gen.sample(range(num_lines), cert_count)
    rand_sample_seg = list(mit.divide(num_part, rand_line_sample)[part])

    with lz4.frame.open(log_file) as f:
        line_ctr = 0
        for line in f:
            if line_ctr in rand_sample_seg:
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

    log_file = args.log_file
    num_certs = args.num
    seed = args.seed
    part = args.partition
    num_part = args.num_partitions

    logging.info(f'Performing {num_certs} lookups for log file {log_file} using seed {seed} for partition {part} of {num_part}')
    session = boto3.Session(profile_name='dns_res')
    m = mp.Manager()  # TODO: enable multiprocessing with a flag

    read_log_from_bucket(session, log_file)
    certs = parse(log_file, num_certs, seed, (part, num_part))
    lookup_res = resolve_dns(m, certs)

    if not args.no_upload:
        print('Upload flag set to false; lookup results local only')
    else:
        write_logs_to_bucket(session, log_file, part)

    return 0


def get_lookups(id_, urls, soa_enabled=False):

    start_exec = time.time()
    successful = 0
    failed = 0

    summary = {}
    full_lkups = {}

    wc_skipped = []
    for url in urls:

        if "*" in url:  # check for and skip wildcard domains
            wc_skipped.append(url)
        else:

            lookups = dns_resolver.lookup_full_name_batched(url, RTYPE_LKUPS)

            domain_full_lookups = {}
            domain_smry = {}
            for rec_type in lookups:
                summ_accum = []
                full_accum = []
                fail_ct = 0
                succ_ct = 0
                for each_lookup in lookups[rec_type]:
                    archive_lookup = {}
                    archive_lookup["ts"] = each_lookup["ts"]
                    if "backup_error_msg" in each_lookup:
                        archive_lookup["backup_error_msg"] = each_lookup["backup_error_msg"]
                        fail_ct += 1
                    else:
                        archive_lookup["backup_resp"] = each_lookup.pop("backup_resp")
                        succ_ct += 1
                    if "error_msg" in each_lookup:
                        archive_lookup["error_msg"] = each_lookup["error_msg"]
                        fail_ct += 1
                    else:
                        archive_lookup["full_lookup"] = each_lookup.pop("full_lookup")
                        succ_ct += 1
                    full_accum.append(archive_lookup)
                    summ_accum.append(each_lookup)
                successful += succ_ct
                failed += fail_ct
                print(f'{fail_ct} failed for domain {url} rtype {rec_type}')
                domain_smry[rec_type] = summ_accum
                domain_full_lookups[rec_type] = full_accum
                
            summary[url] = domain_smry

            full_lkups[url] = domain_full_lookups

    lookup_result = {"ID": id_, 
                     "summary": summary, 
                     "full": full_lkups, 
                     "wildcards_skipped": wc_skipped}
    end_exec = time.time()
    return (lookup_result, successful, failed)


def worker(in_q, out_q):
    # in_q: list of certificates that need to be looked up
    # out_q: threadsafe queue to contain lookup results
    name = os.getpid()
    successful = 0
    failed = 0
    start = time.time()
    for cert in in_q:
        cert_id, cert_urls, le_ts = cert
        lookup, succ_lkup, fail_lkup = get_lookups(cert_id, cert_urls)
        successful += succ_lkup
        failed += fail_lkup
        out_q.put((lookup, le_ts))
    end = time.time()
    print(f'Time for {name} to perform {successful + failed} lookups: {(end-start):.4f} sec.')
    return (successful, failed)


def listener(write_q):
    # listens for lookup messages on the queue and writes to file
    counter = 0

    wr_start = time.time()
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
                stats = {"ID": lookup["ID"], "le_ts": le_ts, 
                         "summary": lookup["summary"],
                         "wildcards_skipped": lookup["wildcards_skipped"]}
                full_graph = {"ID": lookup["ID"], "le_ts": le_ts, 
                              "full": lookup["full"]}
                lookup_f.write(json.dumps(stats) + '\n')
                lookup_f.flush()
                pickle.dump(full_graph, archive_f, pickle.HIGHEST_PROTOCOL)
                archive_f.flush()
                counter += 1
                write_q.task_done()
                if (counter % 10) == 0:
                    wr_interim = time.time()
                    print(f'Recorded {counter} cert lookups so far in {(wr_interim - wr_start):.4f} sec.')


def split(a, n):
    k, m = divmod(len(a), n)
    return (a[i*k+min(i, m):(i+1)*k+min(i+1, m)] for i in range(n))


def resolve_dns(manager, cert_q):

    start = time.time()

    max_proc = mp.cpu_count() + 1

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
    print(f'Time for all tasks to finish ({len(cert_q)} certificate lookups): {(end-start):.4f}')
    return all_lookups


if __name__ == '__main__':

    start = time.time()

    parser = argparse.ArgumentParser(description="Daily Let's Encrypt lookup process")
    parser.add_argument("log_file", metavar="file_name", type=str,
                        help="Name of the log file to perform lookups on.")
    parser.add_argument("-n", "--num", type=int, default=MAX_COUNT, 
                        help="Number of certs to look up.")
    parser.add_argument("-np", "--num-partitions", type=int, default=2,
                        help="Number of instances lookups are divided across.")
    parser.add_argument("-p", "--partition", type=int, default=0,
                        help="Partition number for this process.")
    parser.add_argument("-s", "--seed", type=int, default=date.today().toordinal(),
                        help="Random seed for sampling certs.")
    parser.add_argument("--no-upload", action='store_false',
                        help="Upload lookup results to AWS S3 bucket.")
    args = parser.parse_args()

    result = process_daily_log(args)
    end = time.time()
    logging.info(f'Total of {(end - start):.4f} sec. to download, process, and resolve daily log.')