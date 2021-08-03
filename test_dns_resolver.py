#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import datetime
import time
from routing_aware_dns_resolver import *

today = datetime.datetime.now()


def parse_args():
    parser = argparse.ArgumentParser()
    # Domain list csv file.
    parser.add_argument("-d", "--domains",
                        default="./le-domains.csv")
    parser.add_argument("-e", "--errors",
                        default=f"./errors-{today.year}-{today.month}-{today.day} {today.hour}-{today.minute}-{today.second}.log")
    parser.add_argument("-r", "--results",
                        default=f"./results-{today.year}-{today.month}-{today.day} {today.hour}-{today.minute}-{today.second}.log")
    parser.add_argument("-l", "--latencies",
                        default=f"./latencies-{today.year}-{today.month}-{today.day} {today.hour}-{today.minute}-{today.second}.log")
    return parser.parse_args()

resultsFileName = None
def writeResult(result):
  with open(resultsFileName, "a") as f:
    f.write(result)
    f.write("\n")


errorFileName = None
def writeError(e):
  with open(errorFileName, "a") as f:
    f.write(e)
    f.write("\n")


latencyFileName = None
def writeLatency(l):
  with open(latencyFileName, "a") as f:
    f.write(l)
    f.write("\n")


lookupLatencies = []
errors = []



def main(args):
  global resultsFileName, errorFileName, latencyFileName
  resultsFileName = args.results
  errorFileName = args.errors
  latencyFileName = args.latencies
  domainsResolved = 0
  for line in open(args.domains):
    sline = line.strip()
    if sline == "":
      continue
    splitLine = sline.split(",")
    domain = ""
    if len(splitLine) > 1:
      domain = splitLine[1]
    else:
      domain = splitLine[0]
    try:
      startTime = time.time()
      result = performFullLookupForName(domain)
      endTime = time.time()
      latency = endTime - startTime
      writeResult(f"Domain: {domain}, result: {result}")
      writeLatency(f"Domain: {domain}, latency: {latency}")
    except ValueError as v:
      writeError(f"Domain: {domain}, value error: {v}")
    except Exception as e:
      writeError(f"Domain: {domain}, other error: {e}")
    domainsResolved += 1
    print(f"Domains resolved: {domainsResolved}")


if __name__ == '__main__':
    main(parse_args())
