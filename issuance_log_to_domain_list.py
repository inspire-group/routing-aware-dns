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
  parser.add_argument("-l", "--log",
                      default="./issuance.log.den-20210508.log")
  return parser.parse_args()





def main(args):
  for line in open(args.log):
    sline = line.strip()
    if sline == "":
      continue
    jsonString = sline.split("JSON=")[1]
    jsonObject = json.loads(jsonString)
    auths = jsonObject["Authorizations"]
    for domain in auths:
      if domain.startswith("*."):
        # Strip wildcards.
        print(domain[2:])
      else:
        print(domain)
    


if __name__ == '__main__':
  main(parse_args())
