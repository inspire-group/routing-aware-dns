import ast
import gzip
import ipaddress
import json
import pickle
import re
import urllib.request
from bs4 import BeautifulSoup
from os import listdir, makedirs
from os.path import isfile, isdir, join, exists
from collections import Counter

HOME_DIR = "/home/gcimaszewski"
RES_DIR = join(HOME_DIR, "dns_research")
DATA_DIR = join(RES_DIR, "final_paper_data")
DNS_LOOKUPS_DIR = join(DATA_DIR, "dns_lookups_parsed_final")
SIM_DIR = join(RES_DIR, "simul_files")
RIB_DIR = join(SIM_DIR, "ribfiles_2022-03-15")

all_regions = ['ap-northeast-1', 'ap-southeast-1', 'eu-central-1',
               'eu-west-3', 'us-east-2', 'us-west-2']

ROVISTA_DATA_URL = "https://rovista.netsecurelab.org/data/overview.json"

vp_prov_mapping = {'gcp_asia_northeast1': 'ap-northeast-1', 
                   'gcp_asia_southeast1': 'ap-southeast-1', 
                   'gcp_europe_west2': 'eu-west-3', 
                   'gcp_northamerica_northeast2': 'us-east-2', 
                   'gcp_us_east4': 'us-east-2', 
                   'gcp_us_west1': 'us-west-2', 
                   'ec2_ap_northeast_1': 'ap-northeast-1', 
                   'ec2_ap_south_1': 'ap-southeast-1', 
                   'ec2_ap_southeast_1': 'ap-southeast-1', 
                   'ec2_eu_central_1': 'eu-central-1', 
                   'ec2_eu_north_1': 'eu-central-1', 
                   'ec2_eu_west_3': 'eu-west-3', 
                   'ec2_sa_east_1': 'us-east-2', 
                   'ec2_us_east_2': 'us-east-2', 
                   'ec2_us_west_2': 'us-west-2', 
                   'azure_japan_east_tokyo': 'ap-northeast-1', 
                   'azure_us_east_2': 'us-east-2', 
                   'azure_west_europe': 'eu-central-1', 
                   'azure_germany_west_central': 'eu-central-1', 
                   'le_via_west': 'us-west-2'}


loc_vp_mapping = {'ap-northeast-1': ['gcp_asia_northeast1', 'ec2_ap_northeast_1', 'azure_japan_east_tokyo'], 
                  'ap-southeast-1': ['gcp_asia_southeast1', 'ec2_ap_south_1', 'ec2_ap_southeast_1'], 
                  'eu-west-3': ['gcp_europe_west2', 'ec2_eu_west_3'], 
                  'us-east-2': ['gcp_northamerica_northeast2', 'gcp_us_east4', 'ec2_sa_east_1', 'ec2_us_east_2', 'azure_us_east_2'], 
                  'us-west-2': ['gcp_us_west1', 'ec2_us_west_2', 'le_via_west'], 
                  'eu-central-1': ['ec2_eu_central_1', 'ec2_eu_north_1', 'azure_west_europe', 'azure_germany_west_central']}


def get_domain_ocid_map(lookup_map, ip_prfx_map):
    domain_ocid_map = {}
    for dmn, rmap in lookup_map.items():
        d_submap = {}
        for rgn, lookups in rmap.items():
            a_ips = lookups[0]
            ns_ips = lookups[2]
            a_ocids = set()
            ns_ocids = set()
            for a_ip in a_ips:
                if len(a_ip) > 0 and ip_prfx_map['webserver'][a_ip] is not None:
                    prfx, ocid = ip_prfx_map['webserver'][a_ip]
                    a_ocids.add(ocid)
            for ns_ip in ns_ips:
                if len(ns_ip) > 0 and ip_prfx_map['dns'][ns_ip] is not None:
                    prfx, ocid = ip_prfx_map['dns'][ns_ip]
                    ns_ocids.add(ocid)
            d_submap[rgn] = (a_ocids, ns_ocids)
        domain_ocid_map[dmn] = d_submap
    return domain_ocid_map


def get_rov_secured_paths(domain_ocid_map, ocid_path_map):
    domain_rov_path_map = {}
    for dmn, rmap in domain_ocid_map.items():
        d_submap = {}
        for rgn, ocids in rmap.items():
            a_ocids, ns_ocids = ocids
            for vp in loc_vp_mapping[rgn]:
                a_paths = []
                ns_paths = []
                for ocid in a_ocids:
                    if ocid in ocid_path_map and vp in ocid_path_map[ocid]:
                        a_paths.append(ocid_path_map[ocid][vp])
                for ocid in ns_ocids:
                    if ocid in ocid_path_map and vp in ocid_path_map[ocid]:  
                        ns_paths.append(ocid_path_map[ocid][vp])
                d_submap[vp] = (a_paths, ns_paths)                     
        domain_rov_path_map[dmn] = d_submap
    return domain_rov_path_map

# RoVISTA dataset summary:
# 28858 ASes in total
# 23658 (82%) of ASes perform no ROV
# 3629 ASes very likely to perform ROV (ratio = 1.0)

# parses RoVISTA raw data to generate mapping
# ASN: ratio of ROV filtering
def get_as_rov_ratio_map(rovista):

    as_rov_map = {}
    for entry in rovista:
        button = BeautifulSoup(entry['asn']).find_all('button')
        asn = re.match('my\(([0-9]+)\)', button[0].get('onclick')).groups()[0]
        as_rov_map[asn] = entry['ratio']
    return as_rov_map


def get_rovista_data():

    with urllib.request.urlopen(ROVISTA_DATA_URL) as url:
        data = json.load(url)
    return data 


# map: AS a: bool (True if AS a performs ROV or every neighbor of a performs ROV)
# i.e., whether or not AS a will propagate hidden subprefix hijack
def calc_rov_propagation(rov_as_map, topo):

    as_hh_map = {}
    # label all ASes surely performing ROV
    for asn, rov_filt_ratio in rov_as_map.items():
        if rov_filt_ratio >= 0.99:
            as_hh_map[asn] = True
    label_as_stack = [asn for asn, (custs, peers, provs) in topo.items() if 
                     all(
                        [all([a in as_hh_map and as_hh_map[a] for a in custs]),
                         all([a in as_hh_map and as_hh_map[a] for a in peers]),
                         all([a in as_hh_map and as_hh_map[a] for a in provs]),
                         asn not in as_hh_map]
                        )]
    print(f'Init can assign: {len(label_as_stack)}')
    while len(label_as_stack) > 0:
        can_assign, label_as_stack = label_as_stack[:], []
        for asn in can_assign:
            as_hh_map[asn] = True
        print(f'Labeled {len(can_assign)} more ASes; total of {len(as_hh_map)} ASes labeled')
        prop = [asn for asn, (custs, peers, provs) in topo.items() if 
                all(
                    [all([a in as_hh_map and as_hh_map[a] for a in custs]),
                     all([a in as_hh_map and as_hh_map[a] for a in peers]),
                     all([a in as_hh_map and as_hh_map[a] for a in provs]),
                     asn not in as_hh_map]
                    )]
        label_as_stack.extend(prop)

    # everything else: not protected by ROV
    for asn in topo:
        if asn not in as_hh_map:
            as_hh_map[asn] = False

    return as_hh_map


def parse_ocid_paths(out_f, ocid_path_map={}):

    counter = 0
    with open(out_f) as f:
        for line in f:
            ocid, res, all_paths = line.rstrip().split(';')
            paths = all_paths.split('|')
            ocid_vp_map = {}
            if len(all_paths) > 0:
                for path in paths:
                    path_hops = ast.literal_eval(path)[-1].split(" ")
                    vp = path_hops[0]
                    ocid_vp_map[vp] = path_hops[1:]
            ocid_path_map[ocid] = ocid_vp_map
            counter += 1

    # return ocid_path_map


def calc_path_hh(path_str, rov_map):

    flags = []
    for hop in path_str:
        if hop in rov_map:
            flags.append(rov_map[hop])
        else:
            flags.append(False)
    return all(flags)


# def calc_pathwise_hh(path_str, rov_map):

#     path = ""
#     has_rov = False
#     can_hh = False
#     for hop in path[1:]:
#         if rov_map[hop]:
#             has_rov = True
#         elif has_rov and not rov_map[hop]:
#             can_hh = True
#     return can_hh


def load_routinator_f(fpath=join(RES_DIR, "routinator-2022-09-15.csv")):

    roa_map = {}
    with open(fpath) as f:
        next(f)  # header line
        for line in f:
            asn_, prfx, maxlen, anchor = line.rstrip().split(',')
            asn_parsed = asn_.replace('AS', '')
            net = ipaddress.ip_network(prfx)
            if net in roa_map:
                roa_map[net].append((asn_parsed, maxlen, anchor))
            else:
                roa_map[net] = [(asn_parsed, maxlen, anchor)]
    return roa_map


def get_from_maxlen(routinator_map):
    routes_set = set()
    longer = []
    for prfx, vvrps in routinator_map.items():
        for vvrp in vvrps:
            maxlen_attr = int(vvrp[1])
            if maxlen_attr > prfx.prefixlen:
                longer.append(prfx)
            for plen in range(maxlen_attr - prfx.prefixlen):
                try:
                    routes_set.update(prfx.subnets(prefixlen_diff=plen))
                except ValueError:
                    print(prfx)
                    print(vvrps)
                    print(prfx.prefixlen)
                    print(maxlen_attr)
                    return
    return routes_set, longer


def parse_daily_certs_file(f):

    dns_map = {}
    with open(f) as f_rd:
        for line in f_rd:
            spl = line.rstrip().split(',')
            dmn = spl[0]
            dmn_map = {}
            for rg_idx in range((len(spl) - 1) // 5):
                s = (rg_idx * 5) + 1
                rgn, a_tg, aaaa_tg, dns_tg, dns_aaaa_tg = spl[s: s + 5]
                dmn_map[rgn] = (sorted(a_tg.split(" ")),
                                sorted(aaaa_tg.split(" ")),
                                sorted(dns_tg.split(" ")),
                                sorted(dns_aaaa_tg.split(" ")))
            dns_map[dmn] = dmn_map
    return dns_map


def get_ocid_prfx_list(ocid_map):

    prfxs = []
    for prfx, ocid in ocid_map.items():
        prfxs.append(prfx)
    return sorted(prfxs, key=lambda x: x.prefixlen, reverse=True)


def load_ocid_map(fpath=join(RIB_DIR, 'origin-class-ids-2022-03-15.csv')):

    ocid_map = {}
    with open(fpath) as f:
        for line in f:
            idx1 = line.find(':')
            idx2 = line.rfind(':')
            ocid_ = line[:idx1]
            prfx_ls = ast.literal_eval(line[idx1+1:idx2])
            upstream = ast.literal_eval(line[idx2+1:])
            origin_ases = set([route[0][0] for route in upstream])
            for p in prfx_ls:
                p_net = ipaddress.ip_network(p)
                ocid_map[p_net] = (ocid_, origin_ases)

    return ocid_map 


def get_max_prfx(ip_, prfxs):

    ip_obj = ipaddress.ip_address(ip_)
    for net in prfxs:
        if ip_obj in net:
            return net

# takes a list of IPs
def check_if_subprefix_immune(dmn_targip_map):
    
    for dmn in dmn_targip_map:
        for rgn in all_regions:
            targ_ips = dmn_targip_map[dmn][rgn]
            vuln = []
            for ip_ in targ_ips:
                net_ = ipaddress.ip_network(ip_)


def make_ip_prfx_cache(dmap, prfxs):

    ip_prfx_map = {}
    for dmn, rgn_map in dmap.items():
        for rgn, targ_ips in rgn_map.items():
            a_targs = targ_ips[0]
            dns_a_targs = targ_ips[2]
            for ip in a_targs + dns_a_targs:
                if ip not in ip_prfx_map and ip != '':
                    ip_prfx_map[ip] = get_max_prfx(ip, prfxs)
    return ip_prfx_map


def parse_apnic_rov(url_):
    data = urllib.request.urlopen(url_).read()


def parse_manrs_list(fpath):
    asns_all = []
    asns_rov = []
    with open(fpath) as f:
        next(f)
        for line in f:
            org, areas, asns, actn1, actn2, actn3, actn4 = re.split(r',(?=")', line)
            asns_all.append(asns.split(','))
            if actn1 == "\"1\"":
                asns_rov.append(asns.split(','))
    return asns_all, asns_rov


def map_domain_targ_prfx(dns_map, all_ip_prfx_map):
    # with gzip.open('global_ip_prefix_map.pkl') as f:
    #     all_ip_prfx_map = pickle.load(f)
    res_map = {}
    missing = []
    for dmn, rmap in dns_map.items():
        dmn_submap = {}
        for rgn, ips in rmap.items():
            a_targ = ips[0]
            dns_targ = ips[2]
            a_targ_prfx = set()
            dns_targ_prfx = set()
            for ip in a_targ:
                if len(ip) > 0:
                    prfx_lookup = all_ip_prfx_map['webserver'][rgn][ip]
                    if len(prfx_lookup) > 0:
                        a_targ_prfx.add(max_prfx_len(prfx_lookup))
                    else:
                        missing.append(ip)
            for ip in dns_targ:
                if len(ip) > 0:
                    prfx_lookup = all_ip_prfx_map['dns'][rgn][ip]
                    if len(prfx_lookup) > 0:
                        dns_targ_prfx.add(max_prfx_len(prfx_lookup))
                    else:
                        missing.append(ip)
            dmn_submap[rgn] = (list(a_targ_prfx), list(dns_targ_prfx))
        res_map[dmn] = dmn_submap
    return res_map, missing


def max_prfx_len(prfxs):
    return max(prfxs, key=lambda x: int(x[0][x[0].index('/')+1:]))


def get_prefixlen(net_str):
    return int(net_str[net_str.index('/') + 1:])


def filter_24_prfxs(dns_map):
    filt_map = {}
    for dmn, rgn_map in dns_map.items():
        dmn_map = {}
        for rgn, (a_ips, dns_ips) in rgn_map.items():
            a_sub24 = [_ for _ in a_ips if get_prefixlen(_[0]) < 24]
            dns_sub24 = [_ for _ in dns_ips if get_prefixlen(_[0]) < 24]
            dmn_map[rgn] = (a_sub24, dns_sub24)
        filt_map[dmn] = dmn_map
    return filt_map


# unique_ips = {'dns': set(), 'webserver': set()}

def validate_rvp(prfx, roas, routinator_map):

    has_valid_roa = False
    for roa in roas:
        origin, maxlen, anch = routinator_map[roa]
        if (ipaddress.ip_network(prfx).prefixlen <= int(maxlen)) and \
           (ipaddress.ip_network(prfx).prefixlen >= roa.prefixlen):
            has_valid_roa = True
    return has_valid_roa


def get_matching_roas(prfx, roas, routinator_map, origins):

    valid_roas = []
    for roa_prfx in roas:
        for vrp in routinator_map[roa_prfx]:
            roa_origin, roa_maxlen, roa_anch = vrp
            if roa_origin in origins and \
               (prfx.prefixlen >= roa_prfx.prefixlen) and \
               (prfx.prefixlen <= int(roa_maxlen)):
                valid_roas.append((roa_prfx, roa_origin, roa_maxlen, roa_anch))
    return valid_roas


def can_subprfx_hijack_dmap(dmap, prfx_roa_map, routinator_map, ocid_map, maxct=100):
    safe_domains = {r: set() for r in all_regions}
    bad_domains = {r: set() for r in all_regions}
    domains_bad_maxlen = {r: set() for r in all_regions}
    domains_no_roa = {r: set() for r in all_regions}
    maxcount = maxct
    for idx, (domain, rmap) in enumerate(dmap.items()):
        if (idx % 1000) == 0: print(f'Done with {idx} so far')
        if idx >= maxcount:
            break
        for rgn, (a_ips, dns_ips) in rmap.items():
            a_filt = [_[0] for _ in a_ips if get_prefixlen(_[0]) < 24]
            dns_filt = [_[0] for _ in dns_ips if get_prefixlen(_[0]) < 24]
            targ_filt = a_filt + dns_filt

            can_subprfx_hijack = False
            p_idx = 0
            while p_idx < len(targ_filt) and not can_subprfx_hijack:
                prfx = targ_filt[p_idx]
                prfx_net = ipaddress.ip_network(prfx)
                origins = ocid_map[prfx_net][1]
                if prfx in prfx_roa_map:
                    roas = prfx_roa_map[prfx]
                else:
                    roas = [_ for _ in routinator_map if _.overlaps(prfx_net)]
                    prfx_roa_map[prfx] = roas
                
                valid_roas = get_matching_roas(prfx, roas, routinator_map, origins)
                if len(valid_roas) == 0:
                    domains_no_roa[rgn].add(domain)
                    can_subprfx_hijack = True
                for roa in valid_roas:
                    prfx, origin, maxlen, anchor = roa
                    if int(maxlen) > prfx_net.prefixlen:
                        domains_bad_maxlen[rgn].add(domain)
                        can_subprfx_hijack = True
                        break
                p_idx += 1
            if can_subprfx_hijack:
                bad_domains[rgn].add(domain)
            else:
                safe_domains[rgn].add(domain)

    return safe_domains, bad_domains, domains_no_roa, domains_bad_maxlen


def can_subprfx_hijack(dmap, ips_to_note):
    res_map = {}
    # safe_domains = {r: set() for r in all_regions}
    # bad_domains = {r: set() for r in all_regions}
    # domains_bad_maxlen = {r: set() for r in all_regions}
    # domains_no_roa = {r: set() for r in all_regions}
    for domain, ips in dmap.items():

        a_ips, dns_ips = ips

        a_all24 = all([_ in ips_to_note['on_24orlonger_prfx'] for _ in a_ips])
        a_allroa = all([_ in ips_to_note['have_valid_roa'] for _ in a_ips])
        a_allroa_goodlen = all([_ in ips_to_note['have_valid_roa'] and 
                                _ not in ips_to_note['roa_wrong_maxlen'] for _ in a_ips])
        a_noroa = all([_ not in ips_to_note['have_valid_roa'] for _ in a_ips]) and\
                     (len(a_ips) > 0)
        a_badmaxlen = any([_ in ips_to_note['roa_wrong_maxlen'] for _ in a_ips])
        a_safe = all([((_ in ips_to_note['on_24orlonger_prfx']) or 
                       (_ in ips_to_note['have_valid_roa'] and _ not in ips_to_note['roa_wrong_maxlen']))
                     for _ in a_ips])

        ns_all24 = all([_ in ips_to_note['on_24orlonger_prfx'] for _ in dns_ips])
        ns_allroa = all([_ in ips_to_note['have_valid_roa'] for _ in dns_ips])
        ns_allroa_goodlen = all([_ in ips_to_note['have_valid_roa'] and 
                                _ not in ips_to_note['roa_wrong_maxlen'] for _ in dns_ips])
        ns_noroa = all([_ not in ips_to_note['have_valid_roa'] for _ in dns_ips]) and\
                      (len(dns_ips) > 0)
        ns_badmaxlen = any([_ in ips_to_note['roa_wrong_maxlen'] for _ in dns_ips])
        ns_safe = all([((_ in ips_to_note['on_24orlonger_prfx']) or 
                       (_ in ips_to_note['have_valid_roa'] and _ not in ips_to_note['roa_wrong_maxlen']))
                       for _ in dns_ips])

        res_map[domain] = {'webserver': (len(a_ips), a_all24, a_allroa, a_allroa_goodlen, a_noroa, a_badmaxlen, a_safe) , 
                           'dns': (len(dns_ips), ns_all24, ns_allroa, ns_allroa_goodlen, ns_noroa, ns_badmaxlen, ns_safe)}

    return res_map