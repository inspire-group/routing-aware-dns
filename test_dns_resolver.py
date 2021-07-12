#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
from routing_aware_dns_resolver import *

def parse_args():
    parser = argparse.ArgumentParser()
    # Domain list csv file.
    parser.add_argument("-d", "--domains",
                        default="./top-1m.csv")
    return parser.parse_args()



def main(args):
  for line in open(args.domains):
    sline = line.strip()
    if sline == "":
      continue
    splitLine = sline.split(",")
    domain = splitLine[1]
    print(domain)
    try:
      print(performFullLookupForName(domain))
    except ValueError as v:
      print("Error: " + str(v))


if __name__ == '__main__':
    main(parse_args())
