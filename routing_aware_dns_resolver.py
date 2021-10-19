import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import dns.exception
import random
import time
import sys
import os
from collections import namedtuple


def l2d(ns_list):
    d = {}
    for k, v4, v6 in ns_list:
        d[k] = (v4, v6)
    return d


def d2l(ns_dict):
    res = []
    for k, (v4, v6) in ns_dict.items():
        res.append((k, v4, v6))
    return res


ROOT_SERVER_IP_LIST = [
                      ("a.root-servers.net.", ["198.41.0.4"], ["2001:503:ba3e::2:30"]),
                      ("b.root-servers.net.", ["199.9.14.201"], ["2001:500:200::b"]),
                      ("c.root-servers.net.", ["192.33.4.12"], ["2001:500:2::c"]),
                      ("d.root-servers.net.", ["199.7.91.13"], ["2001:500:2d::d"]),
                      ("e.root-servers.net.", ["192.203.230.10"], ["2001:500:a8::e"]),
                      ("f.root-servers.net.", ["192.5.5.241"], ["2001:500:2f::f"]),
                      ("g.root-servers.net.", ["192.112.36.4"], ["2001:500:12::d0d"]),
                      ("h.root-servers.net.", ["198.97.190.53"], ["2001:500:1::53"]),
                      ("i.root-servers.net.", ["192.36.148.17"], ["2001:7fe::53"]),
                      ("j.root-servers.net.", ["192.58.128.30"], ["2001:503:c27::2:30"]),
                      ("k.root-servers.net.", ["193.0.14.129"], ["2001:7fd::1"]),
                      ("l.root-servers.net.", ["199.7.83.42"], ["2001:500:9f::42"]),
                      ("m.root-servers.net.", ["202.12.27.33"], ["2001:dc3::35"])
                      ]

ROOT_SERVER_IP_DICT = l2d(ROOT_SERVER_IP_LIST)

BACKUP_RESOLVER_IP_LIST = ["127.0.0.1"]#["8.8.8.8"]
DEFAULT_REC_LIM = 30
DEFAULT_CNAME_CHAIN_LIM = 8

DNSResChain = namedtuple("DNSResChain", ["ns_chain", "full_ns_chain", 
                                         "zonelist", "dnssec_chain", 
                                         "answer_rrset"])


def get_hostname_addr(name):
    return get_hostname_addr_from_res_chain(lookup_a_rec(name))
  

def get_hostname_addr_from_res_chain(res_chain):

    answer_rrset = res_chain[-1].answer_rrset
    answer_rr = random.choice(answer_rrset)
    try:
        return answer_rr.address
    except AttributeError:
        raise ValueError("The given result chain does not have a valid address. May be a lookup for the wrong record type.", res_chain)


def get_all_hostname_addr(name):
    return get_all_hostname_addr_from_res_chain(lookup_a_rec(name))
  

def get_all_hostname_addr_from_res_chain(res_chain):
    if res_chain is None or len(res_chain) == 0:
        return []
    answer_rrset = res_chain[-1].answer_rrset
    res = []
    try:
        for answer_rr in answer_rrset:
            res.append(answer_rr.address)
        return (res, answer_rrset.ttl)
    except AttributeError:
        raise ValueError("The given result chain does not have a valid address. May be a lookup for the wrong record type.", res_chain)


def lookup_a_rec(name):
    return lookup_name(name, dns.rdatatype.A)


def lookup_name(name, record_type, rec_limit=10, res_all_glueless=True, 
                master_timeout=10):
    return lookup_name_rec(name, record_type, rec_limit, res_all_glueless, 
                           master_timeout)


def lookup_name_rec(name, record, cname_chain_count, res_all_glueless, 
                    master_timeout):
    return lookup_name_rec_cached(name, record, cname_chain_count, {}, 
                                  res_all_glueless, master_timeout, 
                                  time.time())


def lookup_name_rec_cached(name, record, cname_chain_count, cache, 
                           res_all_glueless, master_timeout, qry_start_time):
    return lookup_name_with_full_recursion(name, record, 
                                           cname_chain_count, cache, 
                                           master_timeout, qry_start_time,
                                           res_all_glueless)

# also log TTL in DNS record
# we can use VA log IP address, also timestamp
def lookup_name_backup(name, record, master_timeout, qry_start_time):

    backup_resolver = dns.resolver.Resolver()
    backup_resolver.timeout = master_timeout
    backup_resolver.lifetime = master_timeout
    backup_resolver.nameservers = BACKUP_RESOLVER_IP_LIST  # Use localhost (unbound) as backup resolver.

    try:
        if time.time() - qry_start_time > master_timeout:
            raise ValueError("MasterTimeout for domain {} in backup resolver lookup.".format(name))
        resp = backup_resolver.resolve(name, record).response
        return resp
    except dns.resolver.NoNameservers as ns_error:
        if "answered SERVFAIL" in ns_error.msg:
            raise ValueError(f"SERVFAIL for domain {name}. Likely invalid DNSSEC.")
        else:
            raise
    except dns.resolver.NXDOMAIN as nxdomain_error:
        raise ValueError(f"NXDOMAIN for domain {name} in record type {record}.")
    except dns.resolver.NoAnswer as noanswer_error:
        raise ValueError(f"NoAnswer for domain {name} in record type {record}.")
    except dns.exception.Timeout as timeout_error:
        raise ValueError(f"MasterTimeout for domain {name} in backup resolver lookup.")


def get_dnssec_chain_count(lookup_res):
    check = True
    count = 0
    for level in lookup_res.dnssec_chain:
        count += (check and level)
        check &= level
    return count


def perform_ip_lookup(name, cache, rec_limit, master_timeout, qry_start_time,
                      res_all_glueless):
    '''Returns: (list[DNSResChain], list[DNSResChain])'''
    # Try the IPv4 lookup
    lookupv4 = lookup_name_rec_helper(name, dns.rdatatype.A, cache, 
                                      master_timeout, qry_start_time,
                                      rec_limit, res_all_glueless)
    try:
        lookupv6 = lookup_name_rec_helper(name, dns.rdatatype.AAAA, cache, 
                                          master_timeout, qry_start_time,
                                          rec_limit, res_all_glueless)
    except Exception:
        # If the IPv6 lookup fails, we can simply put none and keep the nameserver record in place.
        lookupv6 = None
    return (lookupv4, lookupv6)


def get_ip_from_lookup(res):
    if len(res) == 0:
        return None
    if isinstance(res[-1], DNSResChain):
        return get_hostname_addr_from_res_chain(res)
    else:
        return random.choice(res)  # assuming res is a list of strings


def query_nameserver(name, record, ns_list, cache, rec_depth, master_timeout, qry_start_time,
                     max_count=1):

    failed_ns_dict = {}

    ns_to_choose = l2d(ns_list)  
    valid_ns = []

    shuffled_keys = list(ns_to_choose.keys()) 
    random.shuffle(shuffled_keys)  # randomize ns choice
    c = 0
    for ns_name in shuffled_keys:

        ip_or_lookup, ip_or_lookupv6 = ns_to_choose[ns_name]
        if ip_or_lookup is None:
            # If there is a cyclic dependency, do not use record.
            if (ns_name, dns.rdatatype.A) in cache and cache[(ns_name, dns.rdatatype.A)] is None:
                # Case where there is a cycle in the dependency graph and the nameserver chosen is already being resolved.
                failed_ns_dict[ns_name] = "Cyclic"
            # Try a glueless lookup. If failed, do not use nameserver.
            else:
                try:
                    ns_lookups = perform_ip_lookup(ns_name, cache, rec_depth - 1,
                        master_timeout, qry_start_time, True)
                    ns_to_choose[ns_name] = ns_lookups
                    ip_or_lookup, ip_or_lookupv6 = ns_lookups
                except ValueError:
                    failed_ns_dict[ns_name] = "Glueless lookup failed"

        if ip_or_lookup is not None and len(ip_or_lookup) != 0:
            msg = dns.message.make_query(name, record, want_dnssec=True)
            try:
                ns_ip = get_ip_from_lookup(ip_or_lookup)
                (resp, is_tcp) = dns.query.udp_with_fallback(msg, ns_ip,
                    timeout=4, source=None, ignore_trailing=True)
                if len(resp.answer) == 0 and len(resp.authority) == 0:
                    failed_ns_dict[ns_name] = "No answer or authority"
                else:
                    valid_ns.append((ns_name, ip_or_lookup, ip_or_lookupv6, resp))
                    c += 1
                    if c >= max_count:
                        break
            except dns.exception.Timeout:
                failed_ns_dict[ns_name] = "Timeout"

    if len(valid_ns) == 0:
        raise ValueError(f"NoNameservers for domain {name}")

    else:
        return (ns_to_choose, valid_ns)


def lookup_name_rec_helper(name, record, cache, 
                           master_timeout, qry_start_time,
                           rec_limit=DEFAULT_REC_LIM,
                           res_all_glueless=True,
                           cname_chain_count=DEFAULT_CNAME_CHAIN_LIM, 
                           full_ns_list=ROOT_SERVER_IP_LIST.copy(),
                           resolve_full_graph=False):

    start = time.time()

    if (name, record) in cache:
        if cache[(name, record)] is None:
            raise ValueError("Cyclic name dependency not caught.")
        else:
            return cache[(name, record)]

    init_ns_chain = []
    init_full_ns_chain = []
    init_zonelist = ["."]
    init_dnssec_chain = [True]
    init_lkup = DNSResChain(init_ns_chain, init_full_ns_chain, init_zonelist, 
                            init_dnssec_chain, None)
    stack = [(init_lkup, full_ns_list.copy())]

    # Insert a lookup in progress token in the cache.
    cache[(name, record)] = None

    lookup_results = []
    while len(stack) > 0:
        # first step: choose a nameserver to query for the first level record
        # store on stack: (dnslookup result obj, stack of nameservers to search)
        lookup_res, ns_to_search = stack.pop()

        time_elapsed = time.time() - qry_start_time
        if (time_elapsed > master_timeout):
            raise ValueError(f'MasterTimeout for domain {name} after {time_elapsed:.4f} seconds')
        full_ns_lvl, valid_ns_with_resp = query_nameserver(name, record, 
                                              ns_to_search, cache, rec_limit, 
                                              master_timeout, qry_start_time,
                                              max_count=1)
        full_ns = d2l(full_ns_lvl)

        for (ns_name, ns, _, resp) in valid_ns_with_resp:

            has_dnssec = any([_.rdtype == dns.rdatatype.DS for _ in resp.authority])
            new_dnssec_chain = lookup_res.dnssec_chain + [has_dnssec]

            # new_ns_chain = lookup_res.ns_chain + [(ns_name, ns)]
            new_ns_chain = lookup_res.ns_chain + [(ns_name, get_ip_from_lookup(ns))]
            new_full_ns_chain = lookup_res.full_ns_chain + [full_ns]

            # logic for cname/A/AAAA records
            if len(resp.answer) > 0:
                answer_rrset_list = [_ for _ in resp.answer if _.rdtype == record]
                answer_cname_rrset = [_ for _ in resp.answer if _.rdtype == dns.rdatatype.CNAME]
                is_cname = (len(answer_rrset_list) == 0) and (len(answer_cname_rrset) > 0)

                if not is_cname and len(answer_rrset_list) == 0:
                    raise ValueError("NoAnswer and different response from backup resolver for domain {}".format(name))

                answer_rrset = answer_rrset_list[0] if not is_cname else answer_cname_rrset[0]

                if is_cname:
                    if cname_chain_count == 0:
                        raise ValueError("CNAME chain too long.")
                    else:
                        cname_lkup = []
                        res = DNSResChain(new_ns_chain, new_full_ns_chain, 
                                          lookup_res.zonelist, new_dnssec_chain,
                                          answer_rrset)
                        cname_lkup.append(res)

                        for ans in answer_rrset:
                            root_lookup = lookup_name_rec_helper(ans.target.to_text(), record,
                                cache,
                                master_timeout, qry_start_time,
                                cname_chain_count=cname_chain_count - 1, res_all_glueless=res_all_glueless)
                            cname_lkup.extend(root_lookup)
                        cache[(name, record)] = cname_lkup
                        lookup_results.extend(cname_lkup)
                else:
                    res = DNSResChain(new_ns_chain, new_full_ns_chain, lookup_res.zonelist, new_dnssec_chain, answer_rrset)
                    cache[(name, record)] = [res]
                    lookup_results.append(res)
    
            # logic for authority records
            else:
                ns_rr_sets = [a for a in resp.authority if a.rdtype == dns.rdatatype.NS]
                if len(ns_rr_sets) == 0:
                    # print(resp.to_text())
                    # print([a.to_text() for a in resp.answer])
                    # print([a.to_text() for a in resp.authority])
                    # print([a.to_text() for a in resp.additional])
                    raise ValueError(f"NoAnswer and different response from backup resolver for domain {name}.")
                
                ns_group = ns_rr_sets[0]  # This line is not actually choice of nameserver. There should only be one rr set with NS record types, we are simply selecting it.

                new_zonelist = lookup_res.zonelist + [ns_group.name]

                # Iterate over start of authorities (e.g., com., edu.)
                all_ns_list = [ns.target.to_text() for ns in ns_group]
                glued_ns_ip_dict = {}
                for g in resp.additional:
                    if ((g.rdtype == dns.rdatatype.A) or (g.rdtype == dns.rdatatype.AAAA)) and g.name.to_text() in all_ns_list:
                        # Iterate through listed addresses in the DNS response.
                        for ns_addr in g:
                            # If the nameserver is already in not already in the list of glued servers, add it with a blank IPv6 record.
                            if g.name.to_text() not in glued_ns_ip_dict:
                                addr_v4 = [ns_addr.address] if (g.rdtype == dns.rdatatype.A) else []
                                addr_v6 = [ns_addr.address] if (g.rdtype == dns.rdatatype.AAAA) else []
                                glued_ns_ip_dict[g.name.to_text()] = (addr_v4, addr_v6)
                            else:
                                # Else it might already be listed with an IPv6 record, iterate through the list, find the index and update the IPv4 record.
                                (ipv4, ipv6) = glued_ns_ip_dict[g.name.to_text()]
                                if g.rdtype == dns.rdatatype.A:
                                    addr_v4.append(ns_addr.address)
                                elif g.rdtype == dns.rdatatype.AAAA:
                                    addr_v6.append(ns_addr.address)
                                glued_ns_ip_dict[g.name.to_text()] = (addr_v4, addr_v6)

                glueless_ns_list = [_ for _ in all_ns_list if _ not in glued_ns_ip_dict]
                glueless_ns_ip_dict = {}

                if res_all_glueless:
                    for glueless_ns in glueless_ns_list:
                        if (glueless_ns, dns.rdatatype.A) in cache and cache[(glueless_ns, dns.rdatatype.A)] is None:
                            # This is the case where the glueless server is a cyclic dependency. Do not resolve this glueless server as it will cause a loop.
                            glueless_ns_ip_dict[glueless_ns] = (None, None)
                        else:
                            try:
                                # Try the IPv4 lookup.
                                lookupv4, lookupv6 = perform_ip_lookup(glueless_ns, cache, rec_limit - 1, master_timeout,  qry_start_time, res_all_glueless)
                                glueless_ns_ip_dict[glueless_ns] = (lookupv4, lookupv6)
                            except Exception:
                                # If the IPv4 lookup fails, this is a busted nameserver and we should put in a no lookup result. Do not try IPv6 lookup since we cannot query it. I do not believe the nameserver selection code properly handles a glueless server with only an IPv6 lookup.
                                glueless_ns_ip_dict[glueless_ns] = (None, None)
                else:
                    glueless_ns_ip_dict.update([(_, (None, None)) for _ in glueless_ns_list])
                
                new_ns_level = d2l(glued_ns_ip_dict) + d2l(glueless_ns_ip_dict)
                interm_res = DNSResChain(new_ns_chain, new_full_ns_chain, new_zonelist,
                                         new_dnssec_chain, resp)

                stack.append((interm_res, new_ns_level))

    end = time.time()
    # print(f'Total of {end - start:.4f} seconds to resolve {name}.')
    return lookup_results


def lookup_name_with_full_recursion(name, record, cname_chain_count, 
                                    cache, 
                                    master_timeout, qry_start_time,
                                    res_all_glueless):

    # print(f"lookup for name {name} with record {record} and cache {cache.keys()}")
    backup_res_resp = lookup_name_backup(name, record, master_timeout, 
                                         qry_start_time)

    lookups = lookup_name_rec_helper(name, record, {}, master_timeout, 
                                     qry_start_time)

    is_path_dependent = all([_.answer_rrset != lookups[0].answer_rrset for _ in lookups])

    results = []
    for lkup in lookups:
        results.append(lkup)

    matches_backup = (backup_res_resp.answer[0] == lookups[-1].answer_rrset)

    return (results, matches_backup, backup_res_resp)


def get_full_dns_target_ip_list(lookup_result):

    ip_list = []
    ipv6_list = []

    for cname_lkup in lookup_result:
        dnssec_count = get_dnssec_chain_count(cname_lkup) # cname_lkup.dnssec_count
        full_ns_lists = cname_lkup.full_ns_chain
        for zone_idx in range(dnssec_count, len(full_ns_lists)):
            all_ns_list = full_ns_lists[zone_idx]
            for ns_name, ns_ip_lkup, ns_ip_lkupv6 in all_ns_list:
                if ns_ip_lkup is not None and len(ns_ip_lkup) > 0 and isinstance(ns_ip_lkup[0], str): # These lines will have to be updated to support multiple glued A records properly.
                    ip_list.extend(ns_ip_lkup)
                elif ns_ip_lkup is not None:
                    trgt_ipv4, trgt_ipv6 = get_full_dns_target_ip_list(ns_ip_lkup)
                    ip_list.extend(trgt_ipv4)
                    ipv6_list.extend(trgt_ipv6)
                    ip_list.extend(get_all_hostname_addr_from_res_chain(ns_ip_lkup)[0])

                if ns_ip_lkupv6 is not None and len(ns_ip_lkupv6) > 0 and isinstance(ns_ip_lkupv6[0], str): # These lines will have to be updated to support multiple glued AAAA records properly.
                    ipv6_list.extend(ns_ip_lkupv6)
                elif ns_ip_lkupv6 is not None:
                    trgt_ipv4, trgt_ipv6 = get_full_dns_target_ip_list(ns_ip_lkupv6)
                    ip_list.extend(trgt_ipv4)
                    ipv6_list.extend(trgt_ipv6)
                    ipv6_list.extend(get_all_hostname_addr_from_res_chain(ns_ip_lkupv6)[0])
              
    return (list(set(ip_list)), list(set(ipv6_list)))


# Returns full list of IPs that could be hijacked.
# Used to calculate attack viability probability.
# Deprecated: AAAA records need to be looked up separately to support IPv6.
def get_full_targ_ip_list(name, record, include_a_recs):
    if include_a_recs:
        if record != dns.rdatatype.A:
            raise ValueError("Requested inclusion of A records in target IP list but query was for other record type.", record)
        lookup_res = lookup_name(name, record)
        (res, resv6) = get_full_dns_target_ip_list(lookup_res)
        res.extend(get_all_hostname_addr_from_res_chain(lookup_res)[0])
        return (list(set(res)), resv6)
    else:
        return get_full_dns_target_ip_list(lookup_name(name, record))


# Returns list of hijackable IPs that the resolver actually contacted.
# Used to calculate false positive rates.
def get_partial_dns_targ_ip_list(lookup_res):
    ip_list = []
    for cname_lkup in lookup_res:
        dnssec_count = get_dnssec_chain_count(cname_lkup) # cname_lookup.dnssec_count
        nserver_list = cname_lkup.ns_chain
        for zone_idx in range(dnssec_count, len(nserver_list)):
            (ns_name, ns_ip) = nserver_list[zone_idx]
            ip_list.append(ns_ip)
    return (ip_list, [])


def get_targ_partial_ip_list(name, record, include_a_rec):

    if include_a_rec:
        if record != dns.rdatatype.A:
            raise ValueError("Requested inclusion of A records in target IP list but query was for other record type.", record)
        lookup_res = lookup_name(name, record)
        (res, resv6) = get_partial_dns_targ_ip_list(lookup_res)
        res.append(get_hostname_addr_from_res_chain(lookup_res))
        return (res, resv6)
    else:
        return get_partial_dns_targ_ip_list(lookup_name(name, record))


def perform_full_name_lookup(name):
    lookup_dict = {}
    a_records = []
    aaaa_records = []
    a_ttl = 0
    aaaa_ttl = 0

    dns_targ_ipv4 = []
    dns_targ_ipv6 = []

    backup_resp_ipv4 = None
    backup_resp_ipv6 = None
    backup_resp_a_records = []
    backup_resp_a_ttl = 0
    backup_resp_aaaa_records = []
    backup_resp_aaaa_ttl = 0

    match_backup_resv4 = False
    match_backup_resv6 = False

    lookup4_dns_ipv4 = []
    lookup4_dns_ipv6 = []
    lookup6_dns_ipv4 = []
    lookup6_dns_ipv6 = []

    full_graphv4 = False
    full_graphv6 = False

    lookupv4 = None
    lookupv6 = None

    try:
        lookupv4, match_backup_resv4, backup_resp_ipv4 = lookup_name(name, dns.rdatatype.A)
        backup_resp_a_records = [_.address for _ in backup_resp_ipv4.answer[0]]
        backup_resp_a_ttl = backup_resp_ipv4.answer[0].ttl
        a_records, a_ttl = get_all_hostname_addr_from_res_chain(lookupv4)
        (lookup4_dns_ipv4, lookup4_dns_ipv6) = get_full_dns_target_ip_list(lookupv4)
        full_graphv4 = True
    except ValueError as lookup_error:
        if "NoAnswer" in str(lookup_error):
            # This case covers domains that have only an IPv6. 
            # These are not really errors since the domains are valid, but there is not associated IPv4 lookup data.
            if "different response from backup resolver" not in str(lookup_error):
                match_backup_resv4 = True
            full_graphv4 = True
        elif "MasterTimeout" in str(lookup_error):
            # This is the case where a timeout is reached, 
            # to attempt to get a valid lookup, we can redo the lookup with resolve all gleuless as false.
            try:
                lookupv4, match_backup_resv4, backup_resp_ipv4 = lookup_name(name, dns.rdatatype.A, res_all_glueless=False)
                backup_resp_a_records = [_.address for _ in backup_resp_ipv4.answer[0]]
                backup_resp_a_ttl = backup_resp_ipv4.answer[0].ttl
                a_records, a_ttl = get_all_hostname_addr_from_res_chain(lookupv4)
                (lookup4_dns_ipv4, lookup4_dns_ipv6) = get_full_dns_target_ip_list(lookupv4)
            except ValueError as lookup_error2:
                if "NoAnswer" in str(lookup_error2):
                    if "different response from backup resolver" not in str(lookup_error2):
                        match_backup_resv4 = True
                else:
                    raise lookup_error2
        else:
            # This is the case where the calling script needs to handle the error.
            raise lookup_error

    try:
        lookupv6, match_backup_resv6, backup_resp_ipv6 = lookup_name(name, dns.rdatatype.AAAA)
        backup_resp_aaaa_records = [_.address for _ in backup_resp_ipv6.answer[0]]
        backup_resp_aaaa_ttl = backup_resp_ipv6.answer[0].ttl
        aaaa_records, aaaa_ttl = get_all_hostname_addr_from_res_chain(lookupv6)
        (lookup6_dns_ipv4, lookup6_dns_ipv6) = get_full_dns_target_ip_list(lookupv6)
        full_graphv6 = True
    except ValueError as lookup_error:
        if "NoAnswer" in str(lookup_error) or "NXDOMAIN" in str(lookup_error):
            # Case for domains that have only an IPv4.
            # These are not really errors since the domains are valid.
            if "different response from backup resolver" not in str(lookup_error):
                match_backup_resv6 = True
            full_graphv6 = True
        elif "MasterTimeout" in str(lookup_error):
            # Case where a timeout is reached
            # to attempt to get a valid lookup, we can redo the lookup with resolve all glueless as false.
            try:
                lookupv6, match_backup_resv6, backup_resp_ipv6 = lookup_name(name, dns.rdatatype.AAAA, res_all_glueless=False)
                backup_resp_aaaa_records = [_.address for _ in backup_resp_ipv6.answer[0]]
                backup_resp_aaaa_ttl = backup_resp_ipv6.answer[0].ttl
                aaaa_records, aaaa_ttl = get_all_hostname_addr_from_res_chain(lookupv6)
                (lookup6_dns_ipv4, lookup6_dns_ipv6) = get_full_dns_target_ip_list(lookupv6)
            except ValueError as lookup_error2:
                if "NoAnswer" in str(lookup_error2):
                    if "different response from backup resolver" not in str(lookup_error2):
                        match_backup_resv6 = True
                else:
                    raise lookup_error2
        else:
            raise lookup_error

    dns_targ_ipv4 = list(set(lookup4_dns_ipv4).union(set(lookup6_dns_ipv4)))
    dns_targ_ipv6 = list(set(lookup4_dns_ipv6).union(set(lookup6_dns_ipv6)))
  
    lookup_dict["a_records"] = a_records, a_ttl
    lookup_dict["aaaa_records"] = aaaa_records, aaaa_ttl
    lookup_dict["dns_targ_ipv4"] = dns_targ_ipv4
    lookup_dict["dns_targ_ipv6"] = dns_targ_ipv6
    lookup_dict["match_backup_resv4"] = match_backup_resv4
    lookup_dict["match_backup_resv6"] = match_backup_resv6
    lookup_dict["backup_resolver_resp_ipv4"] = backup_resp_ipv4
    lookup_dict["backup_resolver_resp_ipv6"] = backup_resp_ipv6
    lookup_dict["backup_resolver_a_records"] = backup_resp_a_records, backup_resp_a_ttl
    lookup_dict["backup_resolver_aaaa_records"] = backup_resp_aaaa_records, backup_resp_aaaa_ttl
    lookup_dict["is_full_graphv4"] = full_graphv4
    lookup_dict["is_full_graphv6"] = full_graphv6
    lookup_dict["lookup_ipv4"] = lookupv4
    lookup_dict["lookup_ipv6"] = lookupv6

    return lookup_dict


if __name__ == "__main__":
    domain = sys.argv[1]
    print(get_all_hostname_addr(domain))


# For now, All Let's Encrypt validation methods involve contacting and resolving an A record.
# For no good reason, ietf.org is a glueless DNS lookup. It is not supported.
#print(get_full_targ_ip_list("live.com", dns.rdatatype.A, False))
#print(get_all_hostname_addr("yahoo.com"))

#print(get_hostname_addr_from_res_chain(lookup_a_rec("www.amazon.com")))
#print([str(mx) for mx in lookup_name("yahoo.com", dns.rdatatype.MX)[0][5]])

#print([str(caa) for caa in lookup_name("google.com", dns.rdatatype.CAA)[0][5]])  
#print(lookup_a_rec("rogieoj49.fortynine.axc.nl"))
#print(get_full_targ_ip_list("www.ietf.org", dns.rdatatype.A, False))
#print(get_targ_partial_ip_list("www.amazon.com", dns.rdatatype.A, False))
