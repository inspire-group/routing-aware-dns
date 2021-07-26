#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import datetime
import time
from routing_aware_dns_resolver import *
import matplotlib.pyplot as plt
import json


def parse_args():
    parser = argparse.ArgumentParser()
    # Domain list csv file.
    parser.add_argument("-l", "--results",
                        default="./results.log")
    return parser.parse_args()





def main(args):
  results = []
  domainsResolved = 0
  matchedBackupv4Count = 0
  matchedBackupv6Count = 0
  fullGraphv4Count = 0
  fullGraphv6Count = 0
  pathDependantv4Count = 0
  pathDependantv6Count = 0
  hadIPv4 = 0
  hadIPv6 = 0
  missingIPv4ButHadAtBackup = 0
  missingIPv6ButHadAtBackup = 0
  for line in open(args.results):
    sline = line.strip()
    if sline == "":
      continue
    splitLine = sline.split(", result: ")
    result = splitLine[1]
    result = result.replace("(", "[")
    result = result.replace(")", "]")

    result = result.replace("'", "\"")
    result = result.replace("F", "f")
    result = result.replace("T", "t")
    try:
      resultObject = json.loads(result)
    except Exception as e:
      print(e)
      print(result)

    splitResult = result.split(",")
    matchedBackupv4 = resultObject[4]
    matchedBackupv6 = resultObject[5]
    fullGraphv4 = resultObject[6]
    fullGraphv6 = resultObject[7]
    pathDependantv4 = resultObject[8]
    pathDependantv6 = resultObject[9]
    if matchedBackupv4 == True:
      matchedBackupv4Count += 1
    if matchedBackupv6 == True:
      matchedBackupv6Count += 1
    if fullGraphv4 == True:
      fullGraphv4Count += 1
    if fullGraphv6 == True:
      fullGraphv6Count += 1
    if pathDependantv4 == True:
      pathDependantv4Count += 1
    if pathDependantv6 == True:
      pathDependantv6Count += 1


    if len(resultObject[0]) != 0:
      hadIPv4 += 1
    if len(resultObject[1]) != 0:
      hadIPv6 += 1
    if len(resultObject[0]) == 0 and matchedBackupv4 == False:
      missingIPv4ButHadAtBackup += 1
    if len(resultObject[1]) == 0 and matchedBackupv6 == False:
      missingIPv6ButHadAtBackup += 1
  print(f"matched backup v4: {matchedBackupv4Count}, v6: {matchedBackupv6Count}, full graph v4: {fullGraphv4Count}, full graph v6: {fullGraphv6Count}, had IPv4: {hadIPv4}, had IPv6: {hadIPv6}, missing v4 different from backup: {missingIPv4ButHadAtBackup}, missing v6 different from backup: {missingIPv6ButHadAtBackup}, path dependant v4: {pathDependantv4Count}, path dependant v6: {pathDependantv6Count}")

    


if __name__ == '__main__':
    main(parse_args())
