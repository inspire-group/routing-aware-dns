#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##################################################


# log processing script
import os
os.environ['PYTHONASYNCIODEBUG'] = '1'
from datetime import date, datetime
import gzip
import json
import os
from pathlib import Path
import pickle
from random import Random
import time
import logging
import argparse
import routing_aware_dns_resolver_async as dns_resolver

TODAY = date.today().strftime("%Y%m%d")
DATA_BUCKET_NAME = "usenix23-artifact-data"
LOG_FILE = f"data/domains_random_samp.txt"
RES_FILE = f"output/lookup-results-{TODAY}.txt"
FULL_LKUP_FILE = f"output/lookups-archive-{TODAY}.gz"
LOGGER_FILE = f"output/log-{TODAY}.log"
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


def gz_compress(f_nm, compr_f_nm):
    f_in = open(f_nm, 'rb')
    f_out = gzip.open(compr_f_nm, 'wb')
    f_out.writelines(f_in)
    f_out.close()
    f_in.close()    


def parse(log_file):

    out_q = []
    certs_seen = set()
    start = time.time()

    with open(log_file) as f:
        for line in f:
            out_q.append(line)

    stop = time.time()
    logging.info(f'Parsed {len(out_q)} unique certs from log in {(stop - start):.4f} seconds.')
    return out_q

# multithreading steps:
# 1. read all certs to a dict
# 2. worker thread performs lookups
# 3. worker thread writes lookup results to log

# one certificate per line: multiple domains (easier for certificate-level stats)
# send output email 

def process_daily_log(args):

    log_file = args.domains
    logging.info(f'Performing lookups for domains file {log_file}')

    certs = parse(log_file)
    lookup_res = resolve_dns(certs)

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


def worker(line):
    # in_q: list of certificates that need to be looked up
    # out_q: threadsafe queue to contain lookup results
    splitLine = line.strip().split(",")
    if len(splitLine) < 2:
        return ((),[],[])
    le_ts = splitLine[0]
    url = splitLine[1]
    start = time.time()
    lookup, successful, failed = get_lookups(1, [url])
    end = time.time()
    print(f'Time to perform {successful + failed} lookups: {(end-start):.4f} sec.')
    return ((lookup, le_ts), successful, failed)


def write_output(msg, lookup_f, archive_f):

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


def resolve_dns(cert_q):

    start = time.time()

    lookups_success = 0
    lookups_failed = 0
    with open(RES_FILE, "a") as lookup_f, gzip.open(FULL_LKUP_FILE, "wb") as archive_f:
        for cert in cert_q:
            lookup, succ, fail = worker(cert)
            write_output(lookup, lookup_f, archive_f)
            lookups_success += succ
            lookups_failed += fail

    end = time.time()
    tot = lookups_success + lookups_failed

    logging.info(f'Cert lookups completed: {lookups_success} successful {lookups_failed} failed')
    logging.info(f'{tot} cert lookups completed in {(end-start):.4f} seconds.')

    print(f'All the lookups done: {lookups_success} successful {lookups_failed} failed')
    print(f'Time for all tasks to finish ({len(cert_q)} certificate lookups): {(end-start):.4f}')


if __name__ == '__main__':

    start = time.time()

    parser = argparse.ArgumentParser(description="Let's Encrypt lookup process")
    parser.add_argument("-d", "--domains", default="data/domains_random_samp_small.txt", metavar="file_name", type=str,
                        help="Name of the domains_random_samp file to perform lookups on.")
    args = parser.parse_args()

    result = process_daily_log(args)
    end = time.time()
    logging.info(f'Total of {(end - start):.4f} sec. to download, process, and resolve daily log.')