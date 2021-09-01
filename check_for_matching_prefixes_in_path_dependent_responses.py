#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import time
import json
import traceback
from routing_aware_dns_resolver import *
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/topology-simulator")
from ip_lookups import *



def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--results",
                        default="./results.log")
    parser.add_argument("-o", "--ocid_file",
                        default="./origin-class-ids.csv")
    return parser.parse_args()

def mapAcrossLists(f, listList):
	res = []
	for l in listList:
		lMapped = []
		for item in l:
			try:
				lMapped.append(f(item))
			except Exception as e:
				# soft fail code
				lMapped.append(None)
		
		res.append(lMapped)
	return res

def compareListsOfResponses(listList):
	firstSet = set(listList[0])
	fullList = []
	for l in listList:
		fullList.extend(l)
	fullSet = set(fullList)
	return (firstSet, fullSet)

def main(args):
	routesObject = loadRoutesObjectFromOriginClassIDsFile(args.ocid_file)
	ocidObject = loadOCIDObjectFromOriginClassIDsFile(args.ocid_file)
	lastDomain = ""
	additionalIPsInAdditonalLookups = 0
	additionalPrefixesInAdditionalLookups = 0
	additionalOCIDsInAdditionalLookups = 0
	additionalOriginsInAdditionalLookups = 0
	domainsProcessed = 0

	#ipCountDict = {}
	#originASCountDict = {}
	#ocidCountDict = {}
	ipv4ListList = []
	for line in open(args.results):
		sline = line.strip()
		if sline == "":
			continue
		domain = sline.split("Domain: ")[1].split(",")[0]
		if lastDomain == "":
			lastDomain = domain
		if domain != lastDomain:
			# Process results.
			
			firstIPSet, fullIPSet = compareListsOfResponses(ipv4ListList)
			if len(fullIPSet) > len(firstIPSet):
				additionalIPsInAdditonalLookups += 1

			prefixListList = mapAcrossLists(lambda ip: lookupASRoutesObject(ip, routesObject)[0], ipv4ListList)
			firstPrefixSet, fullPrefixSet = compareListsOfResponses(prefixListList)

			if len(fullPrefixSet) > len(firstPrefixSet):
				additionalPrefixesInAdditionalLookups += 1

			ocidListList = mapAcrossLists(lambda ip: ocidObject[lookupASRoutesObject(ip, routesObject)[0]], ipv4ListList)
			firstOCIDSet, fullOCIDSet = compareListsOfResponses(ocidListList)

			if len(fullOCIDSet) > len(firstOCIDSet):
				additionalOCIDsInAdditionalLookups += 1

			originListList = mapAcrossLists(lambda ip: lookupASRoutesObject(ip, routesObject)[1], ipv4ListList)
			firstOriginSet, fullOriginSet = compareListsOfResponses(originListList)

			if len(fullOriginSet) > len(firstOriginSet):
				additionalOriginsInAdditionalLookups += 1
				print(f"Additional origins for domain: {domain}")
			domainsProcessed += 1
			lastDomain = domain
			ipv4ListList = []

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
		ipv4List = resultObject[0]
		ipv4ListList.append(ipv4List)
	print(f"Domains processed: {domainsProcessed}, additional IPs in additional lookups: {additionalIPsInAdditonalLookups}, additional prefixes in additional lookups: {additionalPrefixesInAdditionalLookups}, additional OCIDs in additional lookups: {additionalOCIDsInAdditionalLookups}, additionalOriginsInAdditionalLookups: {additionalOriginsInAdditionalLookups}")





if __name__ == '__main__':
    main(parse_args())
