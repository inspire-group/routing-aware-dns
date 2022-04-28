import copy
import datetime
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.asyncresolver
import dns.resolver
import dns.rcode
import dns.rdatatype
import dns.exception
import dns.asyncquery
import asyncio
import random
import time
import sys
from collections import namedtuple


class DNSLookup:

    def __init__(self, iter_lookup, backup_lookup, rec_type):
        self.lookup = iter_lookup
        self.backup_lookup = backup_lookup
        self.record_type = rec_type

    def matches_backup(self):
        if (self.lookup is None and self.backup_lookup is not None) or (self.lookup is not None and self.backup_lookup is None):
            return False
        elif (self.lookup is None and self.backup_lookup is None):
            return True
        else:
            return (self.backup_lookup.answer[0] == self.lookup[-1].answer_rrset)

    def get_ip_addrs(self):
        return []

    def get_backup_ip_addrs(self):
        addr_list = []
        ttl = 0
        if self.backup_lookup is not None:
            answer_rrs = filt(self.backup_lookup.answer, self.record_type)
            ans = answer_rrs[-1]
            addr_list =[_.address for _ in ans]
            ttl = ans.ttl
        return addr_list, ttl


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

BACKUP_RESOLVER_IP_LIST = ["127.0.0.1"]
DEFAULT_REC_LIM = 30
DEFAULT_CNAME_CHAIN_LIM = 8
LOOKUP_TIME_LMT = 10

DNSResChain = namedtuple("DNSResChain", ["ns_chain", "full_ns_chain", 
                                         "zonelist", "dnssec_chain", 
                                         "answer_rrset"])


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
    res = []
    ttl = 0
    if res_chain is not None and len(res_chain) > 0:
        try:
            answer_rrset = res_chain[-1].answer_rrset
            for ans in answer_rrset:
                res.append(ans.address)
            ttl = answer_rrset.ttl
        except AttributeError:
            raise ValueError("The given result chain does not have a valid address. Maybe a lookup for the wrong record type.", res_chain)
    return res, ttl


def filt(ls, select_type):
    return [_ for _ in ls if _.rdtype == select_type]


def lookup_a_rec(name):
    return lookup_name(name, dns.rdatatype.A)


class BackupResolverError(Exception):

    def __init__(self, message):
        self.message = message


async def lookup_backup_async(name, record, master_timeout=10):

    backup_resolver = dns.asyncresolver.Resolver()
    backup_resolver.timeout = master_timeout
    backup_resolver.lifetime = master_timeout
    backup_resolver.nameservers = BACKUP_RESOLVER_IP_LIST  # Use localhost (unbound) as backup resolver.

    try:
        resp = (await backup_resolver.resolve(name, record)).response
        return resp
    except dns.resolver.NoNameservers as ns_error:
        if "answered SERVFAIL" in ns_error.msg:
            raise BackupResolverError(f"SERVFAIL for domain {name}. Likely invalid DNSSEC.")
        else:
            raise BackupResolverError(f"NoNameservers for domain {name}: {ns_error.msg}")
    except dns.resolver.NXDOMAIN:
        raise BackupResolverError(f"NXDOMAIN for domain {name} in record type {record}.")
    except dns.resolver.NoAnswer:
        raise BackupResolverError(f"NoAnswer for domain {name} in record type {record}.")
    except dns.exception.Timeout:
        raise BackupResolverError(f"MasterTimeout for domain {name} in backup resolver lookup.")


def get_dnssec_chain_count(lookup_res):
    check = True
    count = 0
    for level in lookup_res.dnssec_chain:
        count += (check and level)
        check &= level
    return count


async def perform_ip_lookup(name, cache, rec_limit, res_all_glueless):
    '''Returns: (list[DNSResChain], list[DNSResChain])'''

    lookupv4 = await lookup_name_rec_helper(name, dns.rdatatype.A, cache, 
                                            rec_limit, res_all_glueless)
    try:
        lookupv6 = await lookup_name_rec_helper(name, dns.rdatatype.AAAA,
                                                cache, rec_limit,
                                                res_all_glueless)
    except Exception:
        lookupv6 = None
    return (lookupv4, lookupv6)


def get_ip_from_lookup(res):
    if len(res) == 0:
        return None
    elif isinstance(res[-1], DNSResChain):
        return get_hostname_addr_from_res_chain(res)
    else:
        return random.choice(res)  # assuming res is a list of strings


async def send_dns_msg(name, rec_type, ns):
    msg = dns.message.make_query(name, rec_type, want_dnssec=True)
    cor = dns.asyncquery.udp_with_fallback(msg, ns, timeout=1, ignore_trailing=True)
    resp, is_tcp = await cor
    return resp


async def query_nameserver_async(name, record, ns_list, cache, rec_depth, max_count=1):

    failed_ns_dict = {}

    ns_to_choose = l2d(ns_list)  
    valid_ns = []

    start = time.time()
    network_accum_time = 0

    shuffled_keys = list(ns_to_choose.keys()) 
    random.shuffle(shuffled_keys)  # randomize ns choice

    for ns_name in shuffled_keys:

        ip_or_lookup, ip_or_lookupv6 = ns_to_choose[ns_name]

        if ip_or_lookup is None:
            # If there is a cyclic dependency, do not use record.
            if (ns_name, dns.rdatatype.A) in cache and cache[(ns_name, dns.rdatatype.A)] is None:
                failed_ns_dict[ns_name] = "Cyclic"
            # Try a glueless lookup. If failed, do not use nameserver.
            else:
                try:
                    ns_lookups = await perform_ip_lookup(ns_name, cache,
                                                         rec_depth - 1, True)
                    ns_to_choose[ns_name] = ns_lookups
                    ip_or_lookup, ip_or_lookupv6 = ns_lookups
                except ValueError:
                    failed_ns_dict[ns_name] = "Glueless lookup failed"

        if ip_or_lookup is not None and len(ip_or_lookup) != 0:
            try:
                ns_ip = get_ip_from_lookup(ip_or_lookup)
                network_timer_start = time.time()
                resp = await send_dns_msg(name, record, ns_ip)
                network_timer_end = time.time()
                network_accum_time += (network_timer_end - network_timer_start)
                if len(resp.answer) == 0 and len(resp.authority) == 0:
                    failed_ns_dict[ns_name] = "No answer or authority"
                else:
                    valid_ns.append((ns_name, ip_or_lookup, ip_or_lookupv6, resp))
                    break
            except dns.exception.Timeout:
                failed_ns_dict[ns_name] = "Timeout"

    if len(valid_ns) == 0:
        raise ValueError(f"NoNameservers for domain {name}")

    else:
        end = time.time()
        perc_network_time = network_accum_time / (end - start)
        # print(f'Percent time spent in network in query_nameserver_async: {perc_network_time:.4f} ({network_accum_time:.4f} seconds)')
        return (ns_to_choose, valid_ns)


async def lookup_name_rec_helper(name, record, cache, 
                           rec_limit=DEFAULT_REC_LIM,
                           res_all_glueless=True,
                           cname_chain_count=DEFAULT_CNAME_CHAIN_LIM, 
                           full_ns_list=ROOT_SERVER_IP_LIST.copy()):

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
    ns_query_timer_accum = 0
    max_tree_depth = 10
    while len(stack) > 0 and max_tree_depth > 0:
        # first step: choose a nameserver to query for the first level record
        # store on stack: (dnslookup result obj, stack of nameservers to search)
        lookup_res, ns_to_search = stack.pop()
        
        ns_query_start = time.time()
        full_ns_lvl, valid_ns_with_resp = await query_nameserver_async(name, record,
                                              ns_to_search, cache, rec_limit)
        ns_query_end = time.time()
        ns_query_timer_accum += (ns_query_end - ns_query_start)
        full_ns = d2l(full_ns_lvl)

        for (ns_name, ns, _, resp) in valid_ns_with_resp:

            new_dnssec_chain = lookup_res.dnssec_chain[:]
            if len(filt(resp.authority, dns.rdatatype.NS)) > 0:
                new_dnssec_chain.append(any(filt(resp.authority, dns.rdatatype.DS)))

            new_ns_chain = lookup_res.ns_chain + [(ns_name, get_ip_from_lookup(ns))]
            new_full_ns_chain = lookup_res.full_ns_chain + [full_ns]

            # for cname/A/AAAA records
            if len(resp.answer) > 0:
                answer_rrset_list = filt(resp.answer, record)
                answer_cname_rrset = filt(resp.answer, dns.rdatatype.CNAME)
                is_cname = (len(answer_rrset_list) == 0) and (len(answer_cname_rrset) > 0)

                if not is_cname and len(answer_rrset_list) == 0:
                    err_code = dns.rcode.to_text(dns.rcode.from_flags(int(resp.flags) , resp.ednsflags))
                    raise ValueError(f"NoAnswer (and possibly different response from backup resolver) for domain {name}; error code {err_code}")

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
                            root_lookup = await lookup_name_rec_helper(ans.target.to_text(), record,
                                cache,
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
                    err_code = dns.rcode.to_text(dns.rcode.from_flags(int(resp.flags) , resp.ednsflags))
                    raise ValueError(f"NoAnswer (and possibly different response from backup resolver) for domain {name}; error code {err_code}")
                
                ns_group = ns_rr_sets[0]

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
                                lookupv4, lookupv6 = await perform_ip_lookup(glueless_ns, cache, rec_limit - 1, res_all_glueless)
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
                max_tree_depth -= 1

    end = time.time()
    # perc_ns_query_time = ns_query_timer_accum / (end - start)
    # print(f'Spent {perc_ns_query_time:.4f} time ({ns_query_timer_accum:.4f}) in querying nameservers.')
    # print(f'Total of {end - start:.4f} seconds to resolve {name}.')
    return lookup_results


async def full_lookup_with_timelimit(name, record, cache, timeout):

    cache_dupl = copy.deepcopy(cache)
    tasks = []
    try:
        try:
            print(f'starting glued lookup for {name} {record}')
            is_full_graph = True
            lookup = await lookup_name_rec_helper(name, record, cache, res_all_glueless=True)
            is_full_graph = True
            return (lookup, is_full_graph)

        except dns.exception.Timeout:
            print(f'retrying with glueless for {name} {record}')
            is_full_graph = False
            glueless_lookup = await lookup_name_rec_helper(name, record, cache_dupl, res_all_glueless=False)
            return (glueless_lookup, is_full_graph)

    except Exception as e:
        raise e
        exceptions = [t.exception() for t in tasks if not t.cancelled() and t.exception()]
        if len(exceptions) > 0:
            raise exceptions[-1]
        else:  # case of a second timeout error
            raise e


async def lookup_name_rec_cached(name, record, cname_chain_count, 
                                 cache, res_all_glueless):

    ts = datetime.datetime.now().astimezone()
    backup_lookup = lookup_backup_async(name, record)
    full_lookup = full_lookup_with_timelimit(name, record, cache, LOOKUP_TIME_LMT)

    return ts, await asyncio.gather(backup_lookup, full_lookup, return_exceptions=True)


def get_full_dns_target_ip_list(lookup_result):

    ip_list = []
    ipv6_list = []

    for cname_lkup in lookup_result:
        dnssec_count = get_dnssec_chain_count(cname_lkup)
        full_ns_lists = cname_lkup.full_ns_chain
        for zone_idx in range(dnssec_count, len(full_ns_lists)):
            all_ns_list = full_ns_lists[zone_idx]
            for ns_name, ns_ip_lkup, ns_ip_lkupv6 in all_ns_list:
                if ns_ip_lkup is not None and len(ns_ip_lkup) > 0 and isinstance(ns_ip_lkup[0], str): # These lines will have to be updated to support multiple glued A records properly.
                    ip_list.extend(ns_ip_lkup)
                elif ns_ip_lkup is not None and len(ns_ip_lkup) > 0:
                    trgt_ipv4, trgt_ipv6 = get_full_dns_target_ip_list(ns_ip_lkup)
                    ip_list.extend(trgt_ipv4)
                    ipv6_list.extend(trgt_ipv6)
                    ip_list.extend(get_all_hostname_addr_from_res_chain(ns_ip_lkup)[0])

                if ns_ip_lkupv6 is not None and len(ns_ip_lkupv6) > 0 and isinstance(ns_ip_lkupv6[0], str): # These lines will have to be updated to support multiple glued AAAA records properly.
                    ipv6_list.extend(ns_ip_lkupv6)
                elif ns_ip_lkupv6 is not None and len(ns_ip_lkupv6) > 0:
                    trgt_ipv4, trgt_ipv6 = get_full_dns_target_ip_list(ns_ip_lkupv6)
                    ip_list.extend(trgt_ipv4)
                    ipv6_list.extend(trgt_ipv6)
                    ipv6_list.extend(get_all_hostname_addr_from_res_chain(ns_ip_lkupv6)[0])
              
    return (list(set(ip_list)), list(set(ipv6_list)))


async def lookup_name(name, record_type, rec_limit=10, res_all_glueless=True):
    return await lookup_name_rec_cached(name, record_type, rec_limit, {}, res_all_glueless)


async def collector(name, rec_type_dict, res_all_glueless=True):

    jobs = []
    rtypes = list(rec_type_dict.keys())
    for rtype in rtypes:
        reps = rec_type_dict[rtype]
        tasks = [lookup_name(name, dns.rdatatype.from_text(rtype), res_all_glueless=res_all_glueless) for _ in range(reps)]
        jobs.extend(tasks)
    res = await asyncio.gather(*jobs, return_exceptions=True)
    repack = {}
    idx = 0
    for i, rtype in enumerate(rtypes):
        reps = rec_type_dict[rtype]
        lookups = res[idx: idx + reps]
        repack[rtype] = lookups
        idx += reps
    return repack


def format_lookup_json(lookup, name, rtype):

    ts, (backup_lookup, iter_lookup) = lookup

    lookup_json = {}
    lookup_json["ts"] = str(ts)

    if isinstance(backup_lookup, BackupResolverError):
        lookup_json["match_backup"] = True
        lookup_json["backup_error_msg"] = type(backup_lookup).__name__ + ": " + str(backup_lookup)

    else:
        lookup_json["backup_resp"] = backup_lookup
        if (rtype == dns.rdatatype.A) or (rtype == dns.rdatatype.AAAA):
            lookup_obj = DNSLookup(None, backup_lookup, rtype)
            backup_resp_records, backup_resp_ttl = lookup_obj.get_backup_ip_addrs()
            lookup_json["backup_resp_records"] = backup_resp_records
            lookup_json["backup_resp_ttl"] = backup_resp_ttl
        elif (rtype == dns.rdatatype.SOA):
            ans_rrset = filt(backup_lookup.answer, dns.rdatatype.SOA)[0]
            lookup_json["backup_resp_serial"] = [_.serial for _ in ans_rrset]
            lookup_json["backup_resp_ttl"] = ans_rrset.ttl
            lookup_json["backup_resp_mname"] = [str(_.mname) for _ in ans_rrset]

    if isinstance(iter_lookup, Exception) or isinstance(iter_lookup, asyncio.CancelledError):
        exc_msg = ": " + str(iter_lookup) if len(str(iter_lookup)) > 0 else ""
        lookup_json["error_msg"] = type(iter_lookup).__name__ + exc_msg
    else:
        full_lookup, full_graph = iter_lookup
        lookup_json["full_lookup"] = full_lookup
        lookup_json["full_graph"] = full_graph
        if (rtype == dns.rdatatype.A) or (rtype == dns.rdatatype.AAAA):
            records, ttl = get_all_hostname_addr_from_res_chain(full_lookup)
            (lookup_dns_ipv4, lookup_dns_ipv6) = get_full_dns_target_ip_list(full_lookup)
            lookup_json["records"] = records
            lookup_json["ttl"] = ttl
            lookup_json["lookup_dns_ipv4"] = lookup_dns_ipv4
            lookup_json["lookup_dns_ipv6"] = lookup_dns_ipv6
        elif (rtype == dns.rdatatype.SOA):
            ans_rrset = full_lookup[-1].answer_rrset
            lookup_json["serial"] = [_.serial for _ in ans_rrset]
            lookup_json["ttl"] = ans_rrset.ttl
            lookup_json["mname"] = [str(_.mname) for _ in ans_rrset]

    return lookup_json


def lookup_full_name_batched(name, record_types_with_rtries):
    start = time.perf_counter()

    ret_d = {}
    ret = asyncio.run(collector(name, record_types_with_rtries))
    for k, v in ret.items():
        ls = []
        for l in v:
            ls.append(format_lookup_json(l, name, dns.rdatatype.from_text(k)))
        ret_d[k] = ls

    elapsed = time.perf_counter() - start
    print(f'Total time elapsed: {elapsed: .4f} seconds.')

    return ret_d


if __name__ == "__main__":
    domain = sys.argv[1]
    print(get_all_hostname_addr(domain))
