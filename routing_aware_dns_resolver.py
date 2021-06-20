

#from __future__ import print_function
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


def checkMatchedBackupResolver(resultChain):
  return resultChain[len(resultChain) - 1][4]

def getAddressForHostname(name):
  return getAddressForHostnameFromResultChain(lookupA(name))
  

def getAddressForHostnameFromResultChain(resultChain):
  answerRRSet = resultChain[len(resultChain) - 1][5]
  answerRR = random.choice(answerRRSet)
  address = ""
  try:
    address = answerRR.address
  except AttributeError:
    raise ValueError("The given result chain does not have a valid address. May be a lookup for the wrong record type.", resultChain)
  return address

def getAllAddressesForHostname(name):
  return getAllAddressesForHostnameFromResultChain(lookupA(name))
  

def getAllAddressesForHostnameFromResultChain(resultChain):
  answerRRSet = resultChain[len(resultChain) - 1][5]
  res = []
  try:
    for answerRR in answerRRSet:
      res.append(answerRR.address)
  except AttributeError:
    raise ValueError("The given result chain does not have a valid address. May be a lookup for the wrong record type.", resultChain)
  return res

def lookupA(name):
  return lookupName(name, dns.rdatatype.A)

def lookupName(name, record):
  return lookupNameRecursive(name, record, 8, False, 3)



listOfAllRootServersAndIPs = [("a.root-servers.net.", "198.41.0.4", "2001:503:ba3e::2:30"), 
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


def lookupNameRecursive(name, record, cnameChainsToFollow, resolveAllGlueless, masterTimeout):
  return lookupNameRecursiveWithCache(name, record, cnameChainsToFollow, {}, resolveAllGlueless, masterTimeout, time.time())

def lookupNameRecursiveWithCache(name, record, cnameChainsToFollow, cache, resolveAllGlueless, masterTimeout, queryStartTime):
  return lookupNameRecursiveWithFullRecursionLimit(name, record, cnameChainsToFollow, cache, resolveAllGlueless, 30, masterTimeout, queryStartTime)

def lookupNameRecursiveWithFullRecursionLimit(name, record, cnameChainsToFollow, cache, resolveAllGlueless, fullRecursionLimit, masterTimeout, queryStartTime):
  if (name, record) in cache:
    if cache[(name, record)]:
      raise ValueError("Cyclic name dependency not caught.")
    return cache[(name, record)]
  if fullRecursionLimit < 0:
    raise ValueError("Recursed too much when performing query for domain {}.".format(name))
  # Insert a lookup in progress token in the cache.
  cache[(name, record)] = None
  backupResolver = dns.resolver.Resolver()
  # Use local bind as backup resolver for DNSSEC validation.
  #backupResolver.nameservers = ["127.0.0.1"]
  backupResolver.timeout = 5
  backupResolver.lifetime = 5
  # USe Google DNS as backup resolver.

  backupResolver.nameservers = ["8.8.8.8"]
  backupResolverAnswer = None
  try:
    if time.time() - queryStartTime > masterTimeout:
      raise ValueError("MasterTimeout for domain {}.".format(name))
    backupResolverResponse = backupResolver.resolve(name, record).response
    backupResolverAnswer = backupResolverResponse.answer
  except dns.resolver.NoNameservers as nsError:
    if "answered SERVFAIL" in nsError.msg:
      raise ValueError("SERVFAIL for domain {}. Likely invalid DNSSEC.".format(name))
    else:
      raise
  except dns.resolver.NXDOMAIN as nsError:
    raise ValueError("NXDOMAIN for domain {} in record type {}.".format(name, record))
  except dns.resolver.NoAnswer as nsError:
    raise ValueError("NoAnswer for domain {} in record type {}.".format(name, record))
  

  nameServerList = []
  completeNameServerList = []
  zoneList = ["."]
  dnsSecCount = 1 # We assume root servers are DNSSEC enabled
  dnsSecTrustChain = True
  nameserverName = ""
  nameserver = ""
  listOfAllNameServersAndLookupsOrIPs = listOfAllRootServersAndIPs[:]
  dnsSecValid = True
  while True:
    listOfFailedNameserverIndexes = []
    response = ""
    while True:
      validIndexes = list(set(range(len(listOfAllNameServersAndLookupsOrIPs))) - set([index for (index, _) in listOfFailedNameserverIndexes]))
      if len(validIndexes) == 0:
        raise ValueError("NoNameservers for domain {}".format(name))
      nsIndex = random.choice(validIndexes)
      (nameserverName, ipOrLookup, ipOrLookupv6) = listOfAllNameServersAndLookupsOrIPs[nsIndex]
      if isinstance(ipOrLookup, str):
        nameserver = ipOrLookup
      elif ipOrLookup == None:
        if (nameserverName, dns.rdatatype.A) in cache and cache[(nameserverName, dns.rdatatype.A)] == None:
          # Case where there is a cycle in the dependency graph and the nameserver chosen is already being resolved.
          listOfFailedNameserverIndexes.append((nsIndex, "Cyclic"))
          continue
        nsLookup = lookupNameRecursiveWithFullRecursionLimit(nameserverName, dns.rdatatype.A, 8, cache, resolveAllGlueless, fullRecursionLimit - 1, masterTimeout, queryStartTime)
        nsLookupv6 = lookupNameRecursiveWithFullRecursionLimit(nameserverName, dns.rdatatype.AAAA, 8, cache, resolveAllGlueless, fullRecursionLimit - 1, masterTimeout, queryStartTime)
        listOfAllNameServersAndLookupsOrIPs[nsIndex] = (nameserverName, nsLookup, nsLookupv6)
        nameserver = getAddressForHostnameFromResultChain(nsLookup)
      else:
        nameserver = getAddressForHostnameFromResultChain(ipOrLookup)
      #print("chosen ns: {}".format(nameserverName))
      message = dns.message.make_query(name, record, want_dnssec=True)
      try:
        if time.time() - queryStartTime > masterTimeout:
          raise ValueError("MasterTimeout for domain {}.".format(name))
        (response, tcp) = dns.query.udp_with_fallback(message, nameserver, timeout=4, source=None, ignore_trailing=True)
      except dns.exception.Timeout:
        listOfFailedNameserverIndexes.append((nsIndex, "Timeout"))
        continue
      if len(response.answer) == 0 and len(response.authority) == 0:
        listOfFailedNameserverIndexes.append((nsIndex, "No answer or authority"))
        continue
      break
    completeNameServerList.append(listOfAllNameServersAndLookupsOrIPs[:])
    nameServerList.append((nameserverName, nameserver))
    if dnsSecTrustChain:
      nextLevelDNSSEC = False
      for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.DS:
          nextLevelDNSSEC = True
          break
      if nextLevelDNSSEC:
        dnsSecCount += 1
      else:
        dnsSecTrustChain = False
    #print(dir(response))
    #print(dir(response.answer))
    if response.answer != []:
      # Some name servers will put DNSSEC info before the answer. It is important to actually check the rdtypes.
      answerRRSetList = [a for a in response.answer if a.rdtype == record]
      cname = False

      if len(answerRRSetList) == 0:
        answerRRSetList = [a for a in response.answer if a.rdtype == dns.rdatatype.CNAME]
        if len(answerRRSetList) == 0:
          raise ValueError("NoAnswer and different response from backup resolver for domain {}".format(name))
        cname = True
      answerRRSet = answerRRSetList[0]

      if cname:
        if cnameChainsToFollow == 0:
          raise ValueError("CNAME chain too long.")
        else:
          res = [(nameServerList, completeNameServerList, zoneList, dnsSecCount, answerRRSet == backupResolverAnswer[0], answerRRSet)]
          res.extend(lookupNameRecursiveWithCache(random.choice(answerRRSet).target.to_text(), record, cnameChainsToFollow - 1, cache, resolveAllGlueless, masterTimeout, queryStartTime))
          cache[(name, record)] = res
          return res
      res = [(nameServerList, completeNameServerList, zoneList, dnsSecCount, answerRRSet == backupResolverAnswer[0], answerRRSet)]
      cache[(name, record)] = res
      return res
    else:
      resultingNameServersRRsets = [a for a in response.authority if a.rdtype == dns.rdatatype.NS]
      listOfAllNameServers = []
      if len(resultingNameServersRRsets) == 0:
        print(response.to_text())
        print([a.to_text() for a in response.answer])
        print([a.to_text() for a in response.authority])
        print([a.to_text() for a in response.additional])
        raise ValueError("No NS records for domain {}.".format(name))
      nsGroup = resultingNameServersRRsets[0]

      zoneList.append(nsGroup.name)

      # Iterate over start of authorities (e.g., com., edu.)
      for ns in nsGroup:
        listOfAllNameServers.append(ns.target.to_text())
      listOfGluelessNameServers = listOfAllNameServers[:]
      listOfGluedNameServersAndIPs = []
      for g in response.additional:
        if g.rdtype != dns.rdatatype.A and g.rdtype != dns.rdatatype.AAAA:
          continue
        # Treat the ipv4 and ipv6 case separately.
        if g.rdtype == dns.rdatatype.A:
          if g.name.to_text() in listOfAllNameServers:
            # If we found a glue record for a server, make sure it is removed from the glueless list.
            if g.name.to_text() in listOfGluelessNameServers:
              listOfGluelessNameServers.remove(g.name.to_text())
            # Iterate through listed addresses in the DNS response.
            for nsAddress in g:
              # If the nameserver is already in not already in the list of glued servers, add it with a blank IPv6 record.
              if g.name.to_text() not in [t[0] for t in listOfGluedNameServersAndIPs]:
                listOfGluedNameServersAndIPs.append((g.name.to_text(), nsAddress.address, None))
              else:
                # Else it might already be listed with an IPv6 record, iterate through the list, find the index and update the IPv4 record.
                for i in range(len(listOfGluedNameServersAndIPs)):
                  if listOfGluedNameServersAndIPs[i][0] == g.name.to_text():
                    (nsname, ipv4, ipv6) = listOfGluedNameServersAndIPs[i]
                    listOfGluedNameServersAndIPs[i] = (nsname, nsAddress.address, ipv6)
        elif g.rdtype == dns.rdatatype.AAAA:
          if g.name.to_text() in listOfAllNameServers:
            # If we found a glue record for a server, make sure it is removed from the glueless list.
            if g.name.to_text() in listOfGluelessNameServers:
              listOfGluelessNameServers.remove(g.name.to_text())
            # The above line could cause a glitch with a server that has a glued IPv6 but not IPv4 record. If we find a v6 glue record, we remove the server from the glueless list. However, the dns query code only sends to IPv4 addresses. So does a server with a glued v6 address count as glueless (since we need another lookup to query it) or glued (since we do have an IP for it and a production DNS environment could resolve it).
            # The above line lists servers with only v6 addresses as glued, but this will break later in the code that cannot currently handle a glued v6 record.
            # Iterate through listed addresses in the DNS response.
            for nsAddress in g:
              # If the nameserver is already in not already in the list of glued servers, add it with a blank IPv4 record.
              if g.name.to_text() not in [t[0] for t in listOfGluedNameServersAndIPs]:
                listOfGluedNameServersAndIPs.append((g.name.to_text(), None, nsAddress.address))
              else:
                # Else it might already be listed with an IPv6 record, iterate through the list, find the index and update the IPv4 record.
                for i in range(len(listOfGluedNameServersAndIPs)):
                  if listOfGluedNameServersAndIPs[i][0] == g.name.to_text():
                    (nsname, ipv4, ipv6) = listOfGluedNameServersAndIPs[i]
                    listOfGluedNameServersAndIPs[i] = (nsname, ipv4, nsAddress.address)

      #if len(listOfGluedNameServersAndIPs) == 0:
      #  print("Authoratative NS not found in glue records.")
      #  print("Glueless DNS not supported.")
      #  print("Authoratative NS list: \n{}".format(response.authority[0]))
      #  print("Glue record list: \n{}".format(response.additional))
      #  raise ValueError("No NS records could be resolved from the additional records. Possibly glueless DNS.", response.authority[0], response.additional)
      #print("Glueless servers")
      #print(listOfGluelessNameServers)
      listOfGluelessNameServersAndLookups = []
      if resolveAllGlueless:
        for gluelessNameServer in listOfGluelessNameServers:
          if (gluelessNameServer, dns.rdatatype.A) in cache and cache[(gluelessNameServer, dns.rdatatype.A)] == None:
            # This is the case where the gleuless server is a cyclic dependency. Do not resolve this glueless server as it will cause a loop.
            listOfGluelessNameServersAndLookups.append((gluelessNameServer, None, None))
          else:
            listOfGluelessNameServersAndLookups.append((gluelessNameServer, lookupNameRecursiveWithFullRecursionLimit(gluelessNameServer, dns.rdatatype.A, 8, cache, resolveAllGlueless, fullRecursionLimit - 1, masterTimeout, queryStartTime), lookupNameRecursiveWithFullRecursionLimit(gluelessNameServer, dns.rdatatype.AAAA, 8, cache, resolveAllGlueless, fullRecursionLimit - 1, masterTimeout, queryStartTime)))
      else:
        listOfGluelessNameServersAndLookups = [(gluelessNameServer, None, None) for gluelessNameServer in listOfGluelessNameServers]        
      listOfAllNameServersAndLookupsOrIPs = listOfGluedNameServersAndIPs[:]
      listOfAllNameServersAndLookupsOrIPs.extend(listOfGluelessNameServersAndLookups)

def getFullDNSTargetIPList(lookupResult):
  ipList = []
  ipv6List = []
  for cnameLookup in lookupResult:
    dnsSecCount = cnameLookup[3]
    completeNameServerLists = cnameLookup[1]
    for zoneIndex in range(dnsSecCount, len(completeNameServerLists)):
        completeNameServerList = completeNameServerLists[zoneIndex]
        for nsName, nsIPOrLookup, nsIPOrLookupV6 in completeNameServerList:
            if isinstance(nsIPOrLookup, str):
              ipList.append(nsIPOrLookup)
            elif nsIPOrLookup != None:
              fullTargetIPList = getFullDNSTargetIPList(nsIPOrLookup)
              ipList.extend(fullTargetIPList[0])
              ipv6List.extend(fullTargetIPList[1])

            if isinstance(nsIPOrLookupV6, str):
              ipv6List.append(nsIPOrLookupV6)
            elif nsIPOrLookupV6 != None:
              fullTargetIPList = getFullDNSTargetIPList(nsIPOrLookupV6)
              ipList.extend(fullTargetIPList[0])
              ipv6List.extend(fullTargetIPList[1])
              
  return (list(set(ipList)),list(set(ipv6List)))

# This is the full list of IPs that could be hijacked.
# Use this to calculate attack viability probability.
# This function is deprecated. AAAA recrods need to be looked up in another lookup to spport IPv6.
def getFullTargetIPList(name, record, includeARecords):
  if includeARecords:
    if record != dns.rdatatype.A:
      raise ValueError("Requested inclusion of A records in target IP list but query was for other record type.", record)
    lookupResult = lookupName(name, record)
    (res, resv6) = getFullDNSTargetIPList(lookupResult)
    res.extend(getAllAddressesForHostnameFromResultChain(lookupResult))
    return (list(set(res)),resv6)
  else:
    return getFullDNSTargetIPList(lookupName(name, record))

#print(lookupName("dnssec-failed.org", dns.rdatatype.A))
#print(lookupA("cs.princeton.edu"))

# This is the list of IPs that could be hijacked that the resolver actually contacted.
# Use this to calculate false positive rates.
def getPartialDNSTargetIPList(lookupResult):
  ipList = []
  for cnameLookup in lookupResult:
    dnsSecCount = cnameLookup[3]
    nameServerList = cnameLookup[0]
    for zoneIndex in range(dnsSecCount, len(nameServerList)):
        (nsName, nsIP) = nameServerList[zoneIndex]
        ipList.append(nsIP)
  return (ipList,[])


def getPartialTargetIPList(name, record, includeARecords):
  if includeARecords:
    if record != dns.rdatatype.A:
      raise ValueError("Requested inclusion of A records in target IP list but query was for other record type.", record)
    lookupResult = lookupName(name, record)
    (res, resv6) = getPartialDNSTargetIPList(lookupResult)
    res.append(getAddressForHostnameFromResultChain(lookupResult))
    return (res, resv6)
  else:
    return getPartialDNSTargetIPList(lookupName(name, record))

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
  try:
    lookupv4 = lookupName(name, dns.rdatatype.A)
    aRecords = getAllAddressesForHostnameFromResultChain(lookupv4)
    (lookup4DNSIPsv4, lookup4DNSIPsv6) = getFullDNSTargetIPList(lookupv4)
    matchedBackupResolverv4 = checkMatchedBackupResolver(lookupv4)
  except ValueError as lookupError:
    if "NoAnswer" not in str(lookupError):
      raise lookupError
    else:
      # This case covers domains that have only an IPv6. These are not really errors since the domains are valid, but there is not associated IPv4 lookup data.
      pass
      #print("No answer error")

  try:
    lookupv6 = lookupName(name, dns.rdatatype.AAAA)
    aaaaRecords = getAllAddressesForHostnameFromResultChain(lookupv6)
    (lookup6DNSIPsv4, lookup6DNSIPsv6) = getFullDNSTargetIPList(lookupv6)
    matchedBackupResolverv6 = checkMatchedBackupResolver(lookupv6)
  except ValueError as lookupError:
    if "NoAnswer" not in str(lookupError):
      raise lookupError
    else:
      # This case covers domains that have only an IPv4. These are not really errors since the domains are valid.
      pass
      #print("No answer error")

  DNSTargetIPsv4 = list(set(lookup4DNSIPsv4).union(set(lookup6DNSIPsv4)))
  DNSTargetIPsv6 = list(set(lookup4DNSIPsv6).union(set(lookup6DNSIPsv6)))
  
  return (aRecords, aaaaRecords, DNSTargetIPsv4, DNSTargetIPsv6, matchedBackupResolverv4, matchedBackupResolverv6)


if __name__ == "__main__":
  domain = sys.argv[1]
  print(getAllAddressesForHostname(domain))


# For now, All Let's Encrypt validation methods involve contacting and resolving an A record.
# For no good reason, ietf.org is a glueless DNS lookup. It is not supported.
#print(getFullTargetIPList("live.com", dns.rdatatype.A, False))
#print(getAllAddressesForHostname("yahoo.com"))

#print(getAddressForHostnameFromResultChain(lookupA("www.amazon.com")))
#print([str(mx) for mx in lookupName("yahoo.com", dns.rdatatype.MX)[0][5]])

#print([str(caa) for caa in lookupName("google.com", dns.rdatatype.CAA)[0][5]])  
#print(lookupA("rogieoj49.fortynine.axc.nl"))
#print(getFullTargetIPList("www.ietf.org", dns.rdatatype.A, False))
#print(getPartialTargetIPList("www.amazon.com", dns.rdatatype.A, False))
