#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##################################################


import argparse
import json
import sys
import traceback

def parse_args():
    parser = argparse.ArgumentParser()
    # The lookups summary file.
    parser.add_argument("-s", "--lookups_summary_file",
                        default="./lookups_summary.txt")
    parser.add_argument("-r", "--repetitive_lookups",
                        default=str(sys.maxsize))
    parser.add_argument("-v", "--vantage_point", default="") # In the default case, we can extract the vp name from the filename.
    return parser.parse_args()


def main(args):
	vantagePoint = args.vantage_point
	if vantagePoint == "":
		vantagePoint = args.lookups_summary_file.split("/")[-2]
	repetative_lookup_count = int(args.repetitive_lookups)
	for line in open(args.lookups_summary_file):
		sline = line.strip()
		if sline == "":
			continue
		try:
			summary_object = json.loads(line)["summary"]
			for domain in sorted(summary_object.keys()): # sorting the keys might be overkill, but in theory a dict makes no gaurantee of iteration order.
				if domain == "soa_serial" or domain == "backup_soa_serial": # Ignore soa info since it is not a domain.
					continue
				domain_target_dns_ips = set()
				domain_target_a_ips = set()
				domain_target_dns_ips_v6 = set()
				domain_target_aaaa_ips = set()
				lookups = summary_object[domain]
				# This is where the old and new formats diverge.
				if isinstance(lookups, dict):
					# We are in the new format.
					aLookups = lookups['A']
					if len(aLookups) > repetative_lookup_count:
						aLookups = aLookups[:repetative_lookup_count]
					for aLookup in aLookups:
						if 'error_msg' in aLookup:
							continue # Skip over lookup errors.
						domain_target_a_ips = domain_target_a_ips.union(set(aLookup["records"]))
						domain_target_dns_ips = domain_target_dns_ips.union(set(aLookup["lookup_dns_ipv4"]))
						domain_target_dns_ips_v6 = domain_target_dns_ips_v6.union(set(aLookup["lookup_dns_ipv6"]))
					
					aaaaLookups = lookups['AAAA']
					if len(aaaaLookups) > repetative_lookup_count:
						aaaaLookups = aaaaLookups[:repetative_lookup_count]
					for aaaaLookup in aaaaLookups:
						if 'error_msg' in aaaaLookup:
							continue # Skip over lookup errors.
						domain_target_aaaa_ips = domain_target_aaaa_ips.union(set(aaaaLookup["records"]))
						domain_target_dns_ips = domain_target_dns_ips.union(set(aaaaLookup["lookup_dns_ipv4"]))
						domain_target_dns_ips_v6 = domain_target_dns_ips_v6.union(set(aaaaLookup["lookup_dns_ipv6"]))
				else:
					# We are in the old format.
					if len(lookups) > repetative_lookup_count:
						lookups = lookups[:repetative_lookup_count]
					for lookup in lookups:
						lookup_info = lookup[1] # The first element is the timestamp, so we want to lookup info in element 2.
						if isinstance(lookup_info, str): # This is the case where the lookup is an error, we should continue.
							continue
						domain_target_a_ips = domain_target_a_ips.union(set(lookup_info["a_records"][0]))
						domain_target_dns_ips = domain_target_dns_ips.union(set(lookup_info["dns_targ_ipv4"]))
						domain_target_aaaa_ips = domain_target_aaaa_ips.union(set(lookup_info["aaaa_records"][0]))
						domain_target_dns_ips_v6 = domain_target_dns_ips_v6.union(set(lookup_info["dns_targ_ipv6"]))
				print(f"{domain},{vantagePoint},{' '.join(domain_target_a_ips)},{' '.join(domain_target_aaaa_ips)},{' '.join(domain_target_dns_ips)},{' '.join(domain_target_dns_ips_v6)}")



		except KeyboardInterrupt as i:
			raise i
		except Exception as e:
			print(f"Failed line load on line: {line}", file=sys.stderr)
			traceback.print_exc(file=sys.stderr)
			




if __name__ == '__main__':
    main(parse_args())
