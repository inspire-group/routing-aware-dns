#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import datetime
import time
from routing_aware_dns_resolver import *
import matplotlib.pyplot as plt
import json
from ip_set_statistics import mle_and_unbiased_k

def parse_args():
    parser = argparse.ArgumentParser()
    # Domain list csv file.
    parser.add_argument("-l", "--results",
                        default="./results.log")
    return parser.parse_args()





def main(args):
  domainIPCounts = [] # This is a list of tuples each of the form (d, s,n), i.e., domain, set size , ip count
  lastDomain = ""
  lastDomainTotalIPCount = 0
  lastDomainIPSetList = []
  for line in open(args.results):
    sline = line.strip()
    if sline == "":
      continue
    splitLine = sline.split(", result: ")

    domain = splitLine[0]
    #print(domain)
    if lastDomain != domain:
      #This is the case where we need to process results
      sUnion = set()
      for s in lastDomainIPSetList:
        sUnion = sUnion.union(s)
      nonDeterministic = False
      for s in lastDomainIPSetList:
        if s != sUnion and len(s) > 0:
          nonDeterministic = True
      if nonDeterministic:
        domainIPCounts.append((lastDomain, sUnion, lastDomainTotalIPCount))
      lastDomain = domain
      lastDomainTotalIPCount = 0
      lastDomainIPSetList = []


    result = splitLine[1]
    result = result.replace("(", "[")
    result = result.replace(")", "]")

    result = result.replace("'", "\"")
    result = result.replace("F", "f")
    result = result.replace("T", "t")
    resultObject = None
    try:
      resultObject = json.loads(result)
    except Exception as e:
      print(e)
      print(result)
      exit()
    ipv4list = resultObject[0]
    lastDomainTotalIPCount += len(ipv4list)
    lastDomainIPSetList.append(set(ipv4list))
  domainsWithNondeterministicDNS = 0
  Ns = []
  Ss = []
  utilizations = []
  for d, sset, n in domainIPCounts:
    if n < 10:
      # Exclude domains without 10 samples
      continue
    s = len(sset)
    domainsWithNondeterministicDNS += 1
    utilizations.append(s/n)
    if s/n > .15:
      #print(f"d: {d}, s: {s}, n: {n}, sset: {sset}")
      mle_k, _ = mle_and_unbiased_k(s, n)
      if mle_k != s:
        print(f"d: {d}, mle k: {mle_k}, greater than s: {s}, n: {n}, sset: {sset}")
      else:
        pass
        #print(f"d: {d}, s: {s}, n: {n}, sset: {sset}")
    Ns.append(n)
    Ss.append(s)
  Ns.sort()
  Ss.sort()
  utilizations.sort()
  #plt.plot([x/len(utilizations) for x in range(len(utilizations))],utilizations, label="Utilization fraction")
  plt.plot(range(len(utilizations)),utilizations, label="Utilization fraction")
  #plt.plot(range(len(Ns)),Ns, label="Ns (total IP addresses obtained)")
  #plt.plot(range(len(Ss)),Ss, label="Ss (IP set sizes)")
  plt.grid()
  plt.legend()
  #plt.show()


if __name__ == '__main__':
    main(parse_args())
