

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

# Errors to handle.
# List index out of range:
#  Exception in thread Thread-2:
#  Traceback (most recent call last):
#    File "/usr/local/Cellar/python@2/2.7.14_3/Frameworks/Python.framework/Versions/2.7/lib/python2.7/threading.py", line 801, in __bootstrap_inner
#      self.run()
#    File "/usr/local/Cellar/python@2/2.7.14_3/Frameworks/Python.framework/Versions/2.7/lib/python2.7/threading.py", line 754, in run
#      self.__target(*self.__args, **self.__kwargs)
#    File "resolve_dns.py", line 49, in workerFunction
#      processCertificate(elem)
#    File "resolve_dns.py", line 44, in processCertificate
#      print(rad.lookupA(certificate["commonName"]))
#    File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 34, in lookupA
#      return lookupName(name, dns.rdatatype.A)
#    File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 37, in lookupName
#      return lookupNameRecursive(name, record, 8, False)
#    File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 44, in lookupNameRecursive
#      return lookupNameRecursiveWithCache(name, record, cnameChainsToFollow, {}, resolveAllGlueless)
#    File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 47, in lookupNameRecursiveWithCache
#      return lookupNameRecursiveWithFullRecursionLimit(name, record, cnameChainsToFollow, cache, resolveAllGlueless, 30)
#    File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 132, in lookupNameRecursiveWithFullRecursionLimit
#      nsGroup = resultingNameServersRRsets[0]
#  IndexError: list index out of range

# Traceback (most recent call last):
#  File "/usr/local/Cellar/python@2/2.7.14_3/Frameworks/Python.framework/Versions/2.7/lib/python2.7/threading.py", line 801, in __bootstrap_inner
#    self.run()
#  File "/usr/local/Cellar/python@2/2.7.14_3/Frameworks/Python.framework/Versions/2.7/lib/python2.7/threading.py", line 754, in run
#    self.__target(*self.__args, **self.__kwargs)
#  File "resolve_dns.py", line 54, in workerFunction
#    processCertificate(elem)
#  File "resolve_dns.py", line 47, in processCertificate
#    print("cn common name: {}, lookup result {}.".format(certificate["commonName"], rad.lookupA(certificate["commonName"])))
#  File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 60, in lookupA
#    return lookupName(name, dns.rdatatype.A)
#  File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 63, in lookupName
#    return lookupNameRecursive(name, record, 8, False)
#  File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 70, in lookupNameRecursive
#    return lookupNameRecursiveWithCache(name, record, cnameChainsToFollow, {}, resolveAllGlueless)
#  File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 73, in lookupNameRecursiveWithCache
#    return lookupNameRecursiveWithFullRecursionLimit(name, record, cnameChainsToFollow, cache, resolveAllGlueless, 30)
#  File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 116, in lookupNameRecursiveWithFullRecursionLimit
#    nameserver = getAddressForHostnameFromResultChain(nsLookup)
#  File "/Users/henry/Google Drive/Documents/GitHub/routing-aware-dns/routing_aware_dns_resolver.py", line 46, in getAddressForHostnameFromResultChain
#    return answerRR.address
#AttributeError: 'RRSIG' object has no attribute 'address'


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
  return lookupNameRecursive(name, record, 8, False)



listOfAllRootServersAndIPs = [("a.root-servers.net.", "198.41.0.4"), ("b.root-servers.net.", "199.9.14.201"), ("c.root-servers.net.", "192.33.4.12"), ("d.root-servers.net.", "199.7.91.13"), ("e.root-servers.net.", "192.203.230.10"), ("f.root-servers.net.", "192.5.5.241"), ("g.root-servers.net.", "192.112.36.4"), ("h.root-servers.net.", "198.97.190.53"), ("i.root-servers.net.", "192.36.148.17"), ("j.root-servers.net.", "192.58.128.30"), ("k.root-servers.net.", "193.0.14.129"), ("l.root-servers.net.", "199.7.83.42"), ("m.root-servers.net.", "202.12.27.33")]

def lookupNameRecursive(name, record, cnameChainsToFollow, resolveAllGlueless):
  return lookupNameRecursiveWithCache(name, record, cnameChainsToFollow, {}, resolveAllGlueless)

def lookupNameRecursiveWithCache(name, record, cnameChainsToFollow, cache, resolveAllGlueless):
  return lookupNameRecursiveWithFullRecursionLimit(name, record, cnameChainsToFollow, cache, resolveAllGlueless, 30)

def lookupNameRecursiveWithFullRecursionLimit(name, record, cnameChainsToFollow, cache, resolveAllGlueless, fullRecursionLimit):

  if (name, record) in cache:
    return cache[(name, record)]

  if fullRecursionLimit < 0:
    raise ValueError("Recursed too much when performing query for domain {}.".format(name))
  backupResolver = dns.resolver.Resolver()
  # Use local bind as backup resolver for DNSSEC validation.
  backupResolver.nameservers = ["127.0.0.1"]
  # USe Google DNS as backup resolver.

  #backupResolver.nameservers = ["8.8.8.8"]
  backupResolverAnswer = None
  try:
    backupResolverResponse = backupResolver.query(name, record).response
    backupResolverAnswer = backupResolverResponse.answer
  except dns.resolver.NoNameservers as nsError:
    if "answered SERVFAIL" in nsError.msg:
      raise ValueError("SERVFAIL for domain {}. Likely invalid DNSSEC.".format(name))
    else:
      raise
  except dns.resolver.NXDOMAIN as nsError:
    raise ValueError("NXDOMAIN for domain {}.".format(name))
  

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
      validIndexes = list(set(xrange(len(listOfAllNameServersAndLookupsOrIPs))) - set([index for (index, _) in listOfFailedNameserverIndexes]))
      if len(validIndexes) == 0:
        raise ValueError("No Nameservers for domain {}".format(name))
      nsIndex = random.choice(validIndexes)
      (nameserverName, ipOrLookup) = listOfAllNameServersAndLookupsOrIPs[nsIndex]
      if isinstance(ipOrLookup, basestring):
        nameserver = ipOrLookup
      elif ipOrLookup == None:
        nsLookup = lookupNameRecursiveWithFullRecursionLimit(nameserverName, dns.rdatatype.A, 8, cache, resolveAllGlueless, fullRecursionLimit - 1)
        listOfAllNameServersAndLookupsOrIPs[nsIndex] = (nameserverName, nsLookup)
        nameserver = getAddressForHostnameFromResultChain(nsLookup)
      else:
        nameserver = getAddressForHostnameFromResultChain(ipOrLookup)
      #print("chosen ns: {}".format(nameserverName))
      message = dns.message.make_query(name, record, want_dnssec=True)
      try:
        response = dns.query.udp(message, nameserver, timeout=4)
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
      answerRRSet = response.answer[0]

      answerRR = random.choice(answerRRSet)
      if answerRR.rdtype == dns.rdatatype.CNAME:
        if cnameChainsToFollow == 0:
          raise ValueError("CNAME chain too long.")
        else:
          # This might be changed to not read as a string with the word and instead just give the full answer RR set.
          res = [(nameServerList, completeNameServerList, zoneList, dnsSecCount, response.answer[0] == backupResolverAnswer[0], answerRRSet)]
          res.extend(lookupNameRecursiveWithCache(answerRR.target.to_text(), record, cnameChainsToFollow - 1, cache, resolveAllGlueless))
          cache[(name, record)] = res
          return res
      # Running answer.address breaks the lookup of MX records. Support will be added if needed.
      # To fix MX record support, returning full answer RR set.
      res = [(nameServerList, completeNameServerList, zoneList, dnsSecCount, response.answer[0] == backupResolverAnswer[0], answerRRSet)]
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
        if g.rdtype != dns.rdatatype.A:
          continue
        if g.name.to_text() in listOfAllNameServers:
          listOfGluelessNameServers.remove(g.name.to_text())
          for nsAddress in g:
            listOfGluedNameServersAndIPs.append((g.name.to_text(), nsAddress.address))
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
          listOfGluelessNameServersAndLookups.append((gluelessNameServer, lookupNameRecursiveWithFullRecursionLimit(gluelessNameServer, dns.rdatatype.A, 8, cache, resolveAllGlueless, fullRecursionLimit - 1)))
      else:
        listOfGluelessNameServersAndLookups = [(gluelessNameServer, None) for gluelessNameServer in listOfGluelessNameServers]        
      listOfAllNameServersAndLookupsOrIPs = listOfGluedNameServersAndIPs[:]
      listOfAllNameServersAndLookupsOrIPs.extend(listOfGluelessNameServersAndLookups)

def getFullDNSTargetIPList(lookupResult):
  ipList = []
  for cnameLookup in lookupResult:
    dnsSecCount = cnameLookup[3]
    completeNameServerLists = cnameLookup[1]
    for zoneIndex in xrange(dnsSecCount, len(completeNameServerLists)):
        completeNameServerList = completeNameServerLists[zoneIndex]
        for nsName, nsIPOrLookup in completeNameServerList:
            if isinstance(nsIPOrLookup, basestring):
              ipList.append(nsIPOrLookup)
            elif nsIPOrLookup != None:
              ipList.extend(getFullDNSTargetIPList(nsIPOrLookup))
  return list(set(ipList))

# This is the full list of IPs that could be hijacked.
# Use this to calculate attack viability probability.
def getFullTargetIPList(name, record, includeARecords):
  if includeARecords:
    if record != dns.rdatatype.A:
      raise ValueError("Requested inclusion of A records in target IP list but query was for other record type.", record)
    lookupResult = lookupName(name, record)
    res = getFullDNSTargetIPList(lookupResult)
    res.extend(getAllAddressesForHostnameFromResultChain(lookupResult))
    return list(set(res))
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
    for zoneIndex in xrange(dnsSecCount, len(nameServerList)):
        (nsName, nsIP) = nameServerList[zoneIndex]
        ipList.append(nsIP)
  return ipList


def getPartialTargetIPList(name, record, includeARecords):
  if includeARecords:
    if record != dns.rdatatype.A:
      raise ValueError("Requested inclusion of A records in target IP list but query was for other record type.", record)
    lookupResult = lookupName(name, record)
    res = getPartialDNSTargetIPList(lookupResult)
    res.append(getAddressForHostnameFromResultChain(lookupResult))
    return res
  else:
    return getPartialDNSTargetIPList(lookupName(name, record))

# For now, All Let's Encrypt validation methods involve contacting and resolving an A record.
# For no good reason, ietf.org is a glueless DNS lookup. It is not supported.
#print(getFullTargetIPList("live.com", dns.rdatatype.A, False))
#print(getAllAddressesForHostname("yahoo.com"))

#print(getAddressForHostnameFromResultChain(lookupA("www.amazon.com")))
#print([str(mx) for mx in lookupName("yahoo.com", dns.rdatatype.MX)[0][5]])

#print([str(caa) for caa in lookupName("google.com", dns.rdatatype.CAA)[0][5]])  
#print(lookupA("ietf.org"))
#print(getFullTargetIPList("www.ietf.org", dns.rdatatype.A, False))
#print(getPartialTargetIPList("www.amazon.com", dns.rdatatype.A, False))