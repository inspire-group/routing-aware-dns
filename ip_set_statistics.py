#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import datetime
import time
from routing_aware_dns_resolver import *
import matplotlib.pyplot as plt
import json
from scipy.special import comb
from numpy.random import choice

def parse_args():
    parser = argparse.ArgumentParser()
    # Domain list csv file.
    parser.add_argument("-k", "--kmax",
                        default="1000")
    parser.add_argument("-v", "--k_val",
                        default="30")
    parser.add_argument("-s", "--ip_set_size",
                        default="10")
    parser.add_argument("-n", "--sample_count",
                        default="10")
    parser.add_argument("-m", "--mode",
                        default="mle")
    return parser.parse_args()



def mle_and_unbiased_k(s, n, kmax=1000):
  pks = [0] * (kmax + 1) # allow kmax to be a valid list index.
  # K cannot be less than the observed ip set size and cannot be more than kmax.
  for k in range(s, kmax + 1):
    pks[k] = comb(k, s) * 1/float(k ** n)
  maxP = 0
  maxk = 0
  pTotal = 0
  for k, pk in enumerate(pks):
    pTotal += pk
    if pk > maxP:
      maxP = pk
      maxk = k

  fiftiethPercentile = pTotal / 2
  pTotal = 0
  unbaisedK = 0
  for k, pk in enumerate(pks):
    pTotal += pk
    if pTotal >= fiftiethPercentile:
      unbaisedK = k
      break
  #plt.plot(range(len(pks)), pks)
  #plt.show()
  return (maxk, unbaisedK)

# Code the verify the mle k algorithm is sane.
def sample(setSize, sampleSize):
  sample = choice(setSize, size=sampleSize)
  return len(set(sample))



def main(args):
  if args.mode == "mle":
    print(mle_and_unbiased_k(int(args.ip_set_size), int(args.sample_count), int(args.kmax)))
  else:
    print(sample(int(args.k_val), int(args.sample_count)))


if __name__ == '__main__':
    main(parse_args())
