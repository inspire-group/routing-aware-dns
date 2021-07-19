#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import datetime
import time
from routing_aware_dns_resolver import *
import matplotlib.pyplot as plt
import numpy

def parse_args():
    parser = argparse.ArgumentParser()
    # Domain list csv file.
    parser.add_argument("-l", "--latencies",
                        default="./latencies.log")
    return parser.parse_args()





def main(args):
  latencies = []
  domainsResolved = 0
  for line in open(args.latencies):
    sline = line.strip()
    if sline == "":
      continue
    splitLine = sline.split(", latency: ")
    latency = splitLine[1]
    latencies.append(float(latency))
  latencies.sort()
  print(f"Average latency: {sum(latencies) / len(latencies)}")
  print(f"Median latency: {latencies[int(len(latencies) / 2)]}")
  cdf = [float(x) / len(latencies) for x in range(len(latencies))]
  plt.plot(latencies, cdf)
  plt.xlabel("Latency (seconds)")
  plt.ylabel('CDF')
  ax = plt.gca()
  ax.set_xticks(numpy.arange(0, 20, 1))
  plt.xlim([0, 20])
  ax.set_yticks(numpy.arange(0, 1., .1))
  plt.grid()
  plt.show()

    


if __name__ == '__main__':
    main(parse_args())
