#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##################################################


import argparse
import json
import sys
import traceback
import itertools

def parse_args():
    parser = argparse.ArgumentParser()
    # The lookups summary file.
    parser.add_argument("-c", "--certs_csv_1",
                        default="./certs-1.csv")
    parser.add_argument("-d", "--certs_csv_2",
                        default="./certs-2.csv")
    parser.add_argument("-m", "--match_domains",
                        default=False, action='store_const', const=True)
    return parser.parse_args()

class DomainMismatchError(Exception):
	pass

def mergeLines(sline1, sline2):
	splitLine1 = sline1.strip().split(",")
	splitLine2 = sline2.strip().split(",")
	if splitLine1[0] != splitLine2[0]:
		raise DomainMismatchError
	outLine = splitLine1
	outLine.extend(splitLine2[1:])
	return ",".join(outLine)

def main(args):
	if args.match_domains:
		csv1Dict = {}
		for line in open(args.certs_csv_1):
			sline = line.strip()
			domain = sline.split(",")[0]
			csv1Dict[domain] = sline
		for line in open(args.certs_csv_2):
			sline = line.strip()
			domain = sline.split(",")[0]
			if domain in csv1Dict:
				print(mergeLines(sline, csv1Dict[domain]))
				del csv1Dict[domain] # remove the domain so we have a list of unused lines.
			else:
				print(sline)
		for unusedLine in csv1Dict.values():
			print(unusedLine)
	else:
		for line1, line2 in itertools.zip_longest(open(args.certs_csv_1), open(args.certs_csv_2)):
			try:
				if line1 == None:
					print(line2,end='')
					continue
				if line2 == None:
					print(line1, end='')
					continue
				try:
					#print(f"file combo {args.certs_csv_1} and {args.certs_csv_2}", file=sys.stderr)
					#print(line1, file=sys.stderr)
					#print(line2, file=sys.stderr)
					#print(mergeLines(line1.strip(), line2.strip()), file=sys.stderr)
					#exit()
					print(mergeLines(line1.strip(), line2.strip()))
				except DomainMismatchError as d:
					print(f"Domain mismatch: {line1.strip()} and {line2.strip()} in file combo {args.certs_csv_1} and {args.certs_csv_2}", file=sys.stderr)
					exit()
					continue
			except KeyboardInterrupt as i:
				raise i
			except Exception as e:
				print(f"Failed line load on zipped line combo: {line1}, {line2}", file=sys.stderr)
				traceback.print_exc(file=sys.stderr)

if __name__ == '__main__':
    main(parse_args())
