import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import dns.message
import dns.exception
import random
import time
import sys


ROOT_SERVER_IP_LIST = [
                              ("a.root-servers.net.", "198.41.0.4", "2001:503:ba3e::2:30"), 
                              ("b.root-servers.net.", "199.9.14.201", "2001:500:200::b"), 
                              ("c.root-servers.net.", "192.33.4.12", "2001:500:2::c"), 
                              ("d.root-servers.net.", "199.7.91.13", "2001:500:2d::d"), 
                              ("e.root-servers.net.", "192.203.230.10", "2001:500:a8::e"), 
                              ("f.root-servers.net.", "192.5.5.241", "2001:500:2f::f"), 
                              ("g.root-servers.net.", "192.112.36.4", "2001:500:12::d0d"), 
                              ("h.root-servers.net.", "198.97.190.53", "2001:500:1::53"), 
                              ("i.root-servers.net.", "192.36.148.17", "2001:7fe::53"), 
                              ("j.root-servers.net.", "192.58.128.30", "2001:503:c27::2:30"), 
                              ("k.root-servers.net.", "193.0.14.129", "2001:7fd::1"), 
                              ("l.root-servers.net.", "199.7.83.42", "2001:500:9f::42"), 
                              ("m.root-servers.net.", "202.12.27.33", "2001:dc3::35")]

GOOGLE_DNS_SERVER_IP_LIST = ["8.8.8.8"]


def checkMatchedBackupResolver(res_chain):
    return res_chain[-1][4]


# def getAddressForHostname(name):
def get_hostname_addr(name):
    return get_hostname_addr_from_res_chain(lookup_a_rec(name))
  

# def getAddressForHostnameFromResultChain(res_chain):
def get_hostname_addr_from_res_chain(res_chain):

    answer_rr_set = res_chain[-1][5]
    for i in answer_rr_set:
        print(f'Element of the rr set: {i} (of type {type(i)})')
    answer_rr = random.choice(answer_rr_set)
    try:
        return answer_rr.address
    except AttributeError:
        raise ValueError("The given result chain does not have a valid address. May be a lookup for the wrong record type.", res_chain)


def getAllAddressesForHostname(name):
    return getAllAddressesForHostnameFromResultChain(lookup_a_rec(name))
  

def getAllAddressesForHostnameFromResultChain(res_chain):
    answer_rr_set = res_chain[-1][5]
    res = []
    try:
        for answer_rr in answer_rr_set:
            res.append(answer_rr.address)
        return res
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
                                           res_all_glueless, 30, 
                                           master_timeout, qry_start_time)


def lookup_name_backup(name, record, master_timeout, qry_start_time):

    backup_resolver = dns.resolver.Resolver()
    backup_resolver.timeout = master_timeout
    backup_resolver.lifetime = master_timeout
    backup_resolver.nameservers = GOOGLE_DNS_SERVER_IP_LIST  # Use Google DNS as backup resolver.

    try:
        if time.time() - qry_start_time > master_timeout:
            raise ValueError("MasterTimeout for domain {}.".format(name))
        resp = backup_resolver.resolve(name, record).response
        answer = resp.answer
        return (resp, answer)
    except dns.resolver.NoNameservers as nsError:
        if "answered SERVFAIL" in nsError.msg:
            raise ValueError(f"SERVFAIL for domain {name}. Likely invalid DNSSEC.")
        else:
            raise
    except dns.resolver.NXDOMAIN as nsError:
        raise ValueError(f"NXDOMAIN for domain {name} in record type {record}.")
    except dns.resolver.NoAnswer as nsError:
        raise ValueError(f"NoAnswer for domain {name} in record type {record}.")
    except dns.exception.Timeout as nsError:
        raise ValueError(f"MasterTimeout for domain {name}.")


def lookup_name_with_full_recursion(name, record, cname_chain_count, 
                                    cache, res_all_glueless, 
                                    rec_limit, master_timeout, qry_start_time):

    #print(f"lookup for name {name} with record {record} and cache {cache.keys()}")
    if rec_limit < 0:
        raise ValueError("Recursed too much when performing query for domain {}.".format(name))
    
    if (name, record) in cache:
        if cache[(name, record)] is None:
            raise ValueError("Cyclic name dependency not caught.")
        else:
            entry = cache[(name, record)]
            return cache[(name, record)]

    # Insert a lookup in progress token in the cache.
    cache[(name, record)] = None

    backupResolverResponse, backupResolverAnswer = lookup_name_backup(name, record, master_timeout, qry_start_time)
  
    ns_list = []
    full_ns_list = []
    zonelist = ["."]
    ns_name = ""
    nameserver = ""
    all_ns_lookup_ip_list = ROOT_SERVER_IP_LIST[:]
    dnssec_count = 1  # assume root servers are DNSSEC enabled
    dnssec_trust_chain = True
    dnssec_valid = True

    while True:
        failed_ns_idx_list = []
        response = ""
        while True:

            failed_nmsrvr_idx = [idx for (idx, _) in failed_ns_idx_list]
            valid_idx = [_ for _ in range(len(all_ns_lookup_ip_list)) if _ not in failed_nmsrvr_idx]

            if len(valid_idx) == 0:
                raise ValueError(f"NoNameservers for domain {name}")
            ns_idx = random.choice(valid_idx)
            (ns_name, ipOrLookup, ipOrLookupv6) = all_ns_lookup_ip_list[ns_idx]
            if isinstance(ipOrLookup, str):
                nameserver = ipOrLookup
            elif ipOrLookup is None:
                # If there is a cyclic dependency, do not use record.
                if (ns_name, dns.rdatatype.A) in cache and cache[(ns_name, dns.rdatatype.A)] is None:
                    # Case where there is a cycle in the dependency graph and the nameserver chosen is already being resolved.
                    failed_ns_idx_list.append((ns_idx, "Cyclic"))
                    continue
                # Try a glueless lookup. If failed, do not use nameserver.
                try:
                    nsLookup = lookup_name_with_full_recursion(ns_name, dns.rdatatype.A, 8, cache, res_all_glueless, rec_limit - 1, master_timeout, qry_start_time)
                    # Try the ipv6 lookup for recording purposes. If it fails, we can still use the ns but, leave the V6 info blank.
                    try:
                        nsLookupv6 = lookup_name_with_full_recursion(ns_name, dns.rdatatype.AAAA, 8, cache, res_all_glueless, rec_limit - 1, master_timeout, qry_start_time)
                    except Exception:
                        # No action needs to be taken if the ipv6 lookup of a glueless fails. Simply soft fail and continue with the IPv4 lookup.
                        nsLookupv6 = None
                    all_ns_lookup_ip_list[ns_idx] = (ns_name, nsLookup, nsLookupv6)
                    nameserver = get_hostname_addr_from_res_chain(nsLookup)
                except ValueError:
                    failed_ns_idx_list.append((ns_idx, "Glueless lookup failed"))
                    continue
            else:
                nameserver = get_hostname_addr_from_res_chain(ipOrLookup)
            message = dns.message.make_query(name, record, want_dnssec=True)
            try:
                if time.time() - qry_start_time > master_timeout:
                    raise ValueError("MasterTimeout for domain {}.".format(name))
                # Returns a (dns.message.Message, tcp) tuple where tcp is True if and only if TCP was used. 
                (response, tcp) = dns.query.udp_with_fallback(message, nameserver, timeout=4, source=None, ignore_trailing=True)
            except dns.exception.Timeout:
                failed_ns_idx_list.append((ns_idx, "Timeout"))
                continue
            if len(response.answer) == 0 and len(response.authority) == 0:
                failed_ns_idx_list.append((ns_idx, "No answer or authority"))
                continue
            break
        full_ns_list.append(all_ns_lookup_ip_list[:])
        ns_list.append((ns_name, nameserver))
        if dnssec_trust_chain:
            nextLevelDNSSEC = any([_.rdtype == dns.rdatatype.DS for _ in response.authority])
            if nextLevelDNSSEC:
                dnssec_count += 1
            else:
                dnssec_trust_chain = False

        if response.answer != []:
            # Some name servers will put DNSSEC info before the answer. It is important to actually check the rdtypes.
            answerRRSetList = [a for a in response.answer if a.rdtype == record]
            is_cname = False

            if len(answerRRSetList) == 0:
                answerRRSetList = [a for a in response.answer if a.rdtype == dns.rdatatype.CNAME]
                if len(answerRRSetList) == 0:
                    raise ValueError("NoAnswer and different response from backup resolver for domain {}".format(name))
                is_cname = True
            answerRRSet = answerRRSetList[0]

            if is_cname:
                if cname_chain_count == 0:
                    raise ValueError("CNAME chain too long.")
                else:
                    res = [(ns_list, full_ns_list, zonelist, dnssec_count, answerRRSet == backupResolverAnswer[0], answerRRSet)]
                    rec_lookup = lookup_name_rec_cached(random.choice(answerRRSet).target.to_text(), record, cname_chain_count - 1, cache, res_all_glueless, master_timeout, qry_start_time)
                    res.extend(rec_lookup)
                    cache[(name, record)] = res
                    return res
            res = [(ns_list, full_ns_list, zonelist, dnssec_count, answerRRSet == backupResolverAnswer[0], answerRRSet)]
            cache[(name, record)] = res
            return res
        else:
            ns_rr_sets = [a for a in response.authority if a.rdtype == dns.rdatatype.NS]
            all_ns_list = []
            if len(ns_rr_sets) == 0:
                print(response.to_text())
                print([a.to_text() for a in response.answer])
                print([a.to_text() for a in response.authority])
                print([a.to_text() for a in response.additional])
                raise ValueError(f"No NS records for domain {name}.")
            ns_group = ns_rr_sets[0]  # choice of nameserver

            zonelist.append(ns_group.name)

            # Iterate over start of authorities (e.g., com., edu.)
            for ns in ns_group:
                all_ns_list.append(ns.target.to_text())
            glueless_ns_list = all_ns_list[:]
            glued_ns_ip_dict = {}
            for g in response.additional:
                if (g.rdtype == dns.rdatatype.A) or (g.rdtype == dns.rdatatype.AAAA):
                    if g.name.to_text() in all_ns_list:
                        # If we found a glue record for a server, make sure it is removed from the glueless list.
                        if g.name.to_text() in glueless_ns_list:
                            glueless_ns_list.remove(g.name.to_text())
                        # Iterate through listed addresses in the DNS response.
                        for ns_addr in g:
                            # If the nameserver is already in not already in the list of glued servers, add it with a blank IPv6 record.
                            if g.name.to_text() not in glued_ns_ip_dict:
                                addr_v4 = ns_addr.address if (g.rdtype == dns.rdatatype.A) else None
                                addr_v6 = ns_addr.address if (g.rdtype == dns.rdatatype.AAAA) else None
                                glued_ns_ip_dict[g.name.to_text()] = (addr_v4, addr_v6)
                            else:
                                # Else it might already be listed with an IPv6 record, iterate through the list, find the index and update the IPv4 record.
                                (ipv4, ipv6) = glued_ns_ip_dict[g.name.to_text()]
                                addr_v4 = ns_addr.address if (g.rdtype == dns.rdatatype.A) else ipv4
                                addr_v6 = ns_addr.address if (g.rdtype == dns.rdatatype.AAAA) else ipv6
                                glued_ns_ip_dict[g.name.to_text()] = (addr_v4, addr_v6)

            glueless_ns_lookup_dict = {}
            if res_all_glueless:
                for glueless_ns in glueless_ns_list:
                    if (glueless_ns, dns.rdatatype.A) in cache and cache[(glueless_ns, dns.rdatatype.A)] is None:
                        # This is the case where the glueless server is a cyclic dependency. Do not resolve this glueless server as it will cause a loop.
                        glueless_ns_lookup_dict[glueless_ns] = (None, None)
                    else:
                        try:
                            # Try the IPv4 lookup.
                            lookupv4 = lookup_name_with_full_recursion(glueless_ns, dns.rdatatype.A, 8, cache, res_all_glueless, rec_limit - 1, master_timeout, qry_start_time)
                            try:
                                lookupv6 = lookup_name_with_full_recursion(glueless_ns, dns.rdatatype.AAAA, 8, cache, res_all_glueless, rec_limit - 1, master_timeout, qry_start_time)
                            except Exception:
                                # If the IPv6 lookup fails, we can simply put none and keep the nameserver record in place.
                                lookupv6 = None
                            glueless_ns_lookup_dict[glueless_ns] = (lookupv4, lookupv6)
                        except Exception:
                            # If the IPv4 lookup fails, this is a busted nameserver and we should put in a no lookup result. Do not try IPv6 lookup since we cannot query it. I do not believe the nameserver selection code properly handles a glueless server with only an IPv6 lookup.
                            glueless_ns_lookup_dict[glueless_ns] = (None, None)
            else:
                for glueless_ns in glueless_ns_list:
                    glueless_ns_lookup_dict[glueless_ns] = (None, None)
            all_ns_lookup_ip_list = [(k, v1, v2) for k, (v1, v2) in glued_ns_ip_dict.items()]
            all_ns_lookup_ip_list.extend([(k, v1, v2) for k, (v1, v2) in glueless_ns_lookup_dict.items()])


def getFullDNSTargetIPList(lookup_result):
    ipList = []
    ipv6List = []
    for cname_lookup in lookup_result:
        dnssec_count = cname_lookup[3]
        # completeNameServerLists = cnameLookup[1]
        full_ns_lists = cname_lookup[1]
        for zone_idx in range(dnssec_count, len(full_ns_lists)):
            completeNameServerList = full_ns_lists[zone_idx]
            for nsName, nsIPOrLookup, nsIPOrLookupV6 in completeNameServerList:
                if isinstance(nsIPOrLookup, str):
                    ipList.append(nsIPOrLookup)
                elif nsIPOrLookup is not None:
                    fullTargetIPList = getFullDNSTargetIPList(nsIPOrLookup)
                    ipList.extend(fullTargetIPList[0])
                    ipv6List.extend(fullTargetIPList[1])

                if isinstance(nsIPOrLookupV6, str):
                    ipv6List.append(nsIPOrLookupV6)
                elif nsIPOrLookupV6 is not None:
                    fullTargetIPList = getFullDNSTargetIPList(nsIPOrLookupV6)
                    ipList.extend(fullTargetIPList[0])
                    ipv6List.extend(fullTargetIPList[1])
              
    return (list(set(ipList)), list(set(ipv6List)))

# This is the full list of IPs that could be hijacked.
# Use this to calculate attack viability probability.
# This function is deprecated. AAAA records need to be looked up in another lookup to support IPv6.
def getFullTargetIPList(name, record, includeARecords):
    if includeARecords:
        if record != dns.rdatatype.A:
            raise ValueError("Requested inclusion of A records in target IP list but query was for other record type.", record)
        lookup_result = lookup_name(name, record)
        (res, resv6) = getFullDNSTargetIPList(lookup_result)
        res.extend(getAllAddressesForHostnameFromResultChain(lookup_result))
        return (list(set(res)), resv6)
    else:
        return getFullDNSTargetIPList(lookup_name(name, record))

#print(lookup_name("dnssec-failed.org", dns.rdatatype.A))
#print(lookup_a_rec("cs.princeton.edu"))

# This is the list of IPs that could be hijacked that the resolver actually contacted.
# Use this to calculate false positive rates.
def getPartialDNSTargetIPList(lookup_res):
    ip_list = []
    for cname_lookup in lookup_res:
        dnssec_count = cname_lookup[3]
        nserver_list = cname_lookup[0]
        for zoneIndex in range(dnssec_count, len(nserver_list)):
            (ns_name, ns_ip) = nserver_list[zoneIndex]
            ip_list.append(ns_ip)
    return (ip_list, [])


def getPartialTargetIPList(name, record, includeARecords):
    if includeARecords:
        if record != dns.rdatatype.A:
            raise ValueError("Requested inclusion of A records in target IP list but query was for other record type.", record)
        lookupResult = lookup_name(name, record)
        (res, resv6) = getPartialDNSTargetIPList(lookupResult)
        res.append(get_hostname_addr_from_res_chain(lookupResult))
        return (res, resv6)
    else:
        return getPartialDNSTargetIPList(lookup_name(name, record))


def performFullLookupForName(name):
    aRecords = []
    aaaaRecords = []
    DNSTargetIPsv4 = []
    DNSTargetIPsv6 = []
    matchedBackupResolverv4 = False
    matchedBackupResolverv6 = False
    lookup4DNSIPsv4 = []
    lookup4DNSIPsv6 = []
    lookup6DNSIPsv4 = []
    lookup6DNSIPsv6 = []
    fullGraphv4 = False
    fullGraphv6 = False
    try:
        lookupv4 = lookup_name(name, dns.rdatatype.A)
        aRecords = getAllAddressesForHostnameFromResultChain(lookupv4)
        (lookup4DNSIPsv4, lookup4DNSIPsv6) = getFullDNSTargetIPList(lookupv4)
        matchedBackupResolverv4 = checkMatchedBackupResolver(lookupv4)
        fullGraphv4 = True
    except ValueError as lookupError:
        if "NoAnswer" in str(lookupError):
            # This case covers domains that have only an IPv6. 
            # These are not really errors since the domains are valid, but there is not associated IPv4 lookup data.
            pass
        elif "MasterTimeout" in str(lookupError):
            # This is the case where a timeout is reached, 
            # to attempt to get a valid lookup, we can redo the lookup with resolve all gleuless as false.
            try:
                lookupv4 = lookup_name(name, dns.rdatatype.A, res_all_glueless=False)
                aRecords = getAllAddressesForHostnameFromResultChain(lookupv4)
                (lookup4DNSIPsv4, lookup4DNSIPsv6) = getFullDNSTargetIPList(lookupv4)
                matchedBackupResolverv4 = checkMatchedBackupResolver(lookupv4)
            except ValueError as lookupError2:
                if "NoAnswer" in str(lookupError2):
                    pass
                else:
                    raise lookupError2
        else:
        # This is the case where the calling script needs to handle the error.
            raise lookupError

    try:
        lookupv6 = lookup_name(name, dns.rdatatype.AAAA)
        aaaaRecords = getAllAddressesForHostnameFromResultChain(lookupv6)
        (lookup6DNSIPsv4, lookup6DNSIPsv6) = getFullDNSTargetIPList(lookupv6)
        matchedBackupResolverv6 = checkMatchedBackupResolver(lookupv6)
        fullGraphv6 = True
    except ValueError as lookupError:
        if "NoAnswer" in str(lookupError):
          # This case covers domains that have only an IPv4. 
          # These are not really errors since the domains are valid.
            pass
        elif "MasterTimeout" in str(lookupError):
        # This is the case where a timeout is reached, 
        # to attempt to get a valid lookup, we can redo the lookup with resolve all glueless as false.
            try:
                lookupv6 = lookup_name(name, dns.rdatatype.AAAA, res_all_glueless=False)
                aaaaRecords = getAllAddressesForHostnameFromResultChain(lookupv6)
                (lookup6DNSIPsv4, lookup6DNSIPsv6) = getFullDNSTargetIPList(lookupv6)
                matchedBackupResolverv6 = checkMatchedBackupResolver(lookupv6)
            except ValueError as lookupError2:
                if "NoAnswer" in str(lookupError2):
                    pass
                else:
                    raise lookupError2
        else:
            raise lookupError

    DNSTargetIPsv4 = list(set(lookup4DNSIPsv4).union(set(lookup6DNSIPsv4)))
    DNSTargetIPsv6 = list(set(lookup4DNSIPsv6).union(set(lookup6DNSIPsv6)))
  
    return (aRecords, aaaaRecords, DNSTargetIPsv4, DNSTargetIPsv6, 
            matchedBackupResolverv4, matchedBackupResolverv6, fullGraphv4, 
            fullGraphv6)


if __name__ == "__main__":
    domain = sys.argv[1]
    print(getAllAddressesForHostname(domain))


# For now, All Let's Encrypt validation methods involve contacting and resolving an A record.
# For no good reason, ietf.org is a glueless DNS lookup. It is not supported.
#print(getFullTargetIPList("live.com", dns.rdatatype.A, False))
#print(getAllAddressesForHostname("yahoo.com"))

#print(get_hostname_addr_from_res_chain(lookup_a_rec("www.amazon.com")))
#print([str(mx) for mx in lookup_name("yahoo.com", dns.rdatatype.MX)[0][5]])

#print([str(caa) for caa in lookup_name("google.com", dns.rdatatype.CAA)[0][5]])  
#print(lookup_a_rec("rogieoj49.fortynine.axc.nl"))
#print(getFullTargetIPList("www.ietf.org", dns.rdatatype.A, False))
#print(getPartialTargetIPList("www.amazon.com", dns.rdatatype.A, False))
