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
    return parser.parse_args()


def main(args):
	repetative_lookup_count = int(args.repetitive_lookups)
	for line in open(args.lookups_summary_file):
		sline = line.strip()
		if sline == "":
			continue
		try:
			summary_object = json.loads(line)["summary"]
			for domain in summary_object:
				domain_target_ips = set()
				domain_target_ips_v6 = set()
				lookups = summary_object[domain]
				if len(lookups) > repetative_lookup_count:
					lookups = lookups[:repetative_lookup_count]
				for lookup in lookups:
					lookup_info = lookup[1] # The first element is the timestamp, so we want to lookup info in element 2.
					if isinstance(lookup_info, str): # This is the case where the lookup is an error, we should continue.
						continue
					domain_target_ips = domain_target_ips.union(set(lookup_info["a_records"]))
					domain_target_ips = domain_target_ips.union(set(lookup_info["dns_targ_ipv4"]))
					domain_target_ips_v6 = domain_target_ips_v6.union(set(lookup_info["aaaa_records"]))
					domain_target_ips_v6 = domain_target_ips_v6.union(set(lookup_info["dns_targ_ipv6"]))
				print(f"{domain},{' '.join(domain_target_ips)},{' '.join(domain_target_ips_v6)}")



		except KeyboardInterrupt as i:
			raise i
		except Exception as e:
			print(f"Failed line load on line: {line}", file=sys.stderr)
			traceback.print_exc(file=sys.stderr)
			




if __name__ == '__main__':
    main(parse_args())
