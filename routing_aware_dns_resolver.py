

#from __future__ import print_function
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import dns.message
import random

def getAddressForHostname(name):
  return getAddressForHostnameFromResultChain(lookupA(name))
  

def getAddressForHostnameFromResultChain(resultChain):
  answerRRSet = resultChain[len(resultChain) - 1][5]
  answerRR = random.choice(answerRRSet)
  return answerRR.address

def getAllAddressesForHostname(name):
  return getAllAddressesForHostnameFromResultChain(lookupA(name))
  

def getAllAddressesForHostnameFromResultChain(resultChain):
  answerRRSet = resultChain[len(resultChain) - 1][5]
  res = []
  for answerRR in answerRRSet:
    res.append(answerRR.address)
  return res

def lookupA(name):
  return lookupName(name, dns.rdatatype.A)

def lookupName(name, record):
  return lookupNameRecursive(name, record, 8)



listOfAllRootServersAndIPs = [("a.root-servers.net.", "198.41.0.4"), ("b.root-servers.net.", "199.9.14.201"), ("c.root-servers.net.", "192.33.4.12"), ("d.root-servers.net.", "199.7.91.13"), ("e.root-servers.net.", "192.203.230.10"), ("f.root-servers.net.", "192.5.5.241"), ("g.root-servers.net.", "192.112.36.4"), ("h.root-servers.net.", "198.97.190.53"), ("i.root-servers.net.", "192.36.148.17"), ("j.root-servers.net.", "192.58.128.30"), ("k.root-servers.net.", "193.0.14.129"), ("l.root-servers.net.", "199.7.83.42"), ("m.root-servers.net.", "202.12.27.33")]

def lookupNameRecursive(name, record, cnameChainsToFollow):
  backupResolver = dns.resolver.Resolver()
  # Use local bind as backup resolver for DNSSEC validation.
  #backupResolver.nameservers = ["127.0.0.1"]
  # USe Google DNS as backup resolver.

  backupResolver.nameservers = ["8.8.8.8"]
  backupResolverAnswer = None
  try:
    backupResolverResponse = backupResolver.query(name, record).response
    backupResolverAnswer = backupResolverResponse.answer
  except dns.resolver.NoNameservers as nsError:
    if "answered SERVFAIL" in nsError.msg:
      raise ValueError("Invalid DNSSEC for domain.") 
    else:
      raise
  

  nameServerList = []
  completeNameServerList = [listOfAllRootServersAndIPs]
  zoneList = ["."]
  dnsSecCount = 1 # We assume root servers are DNSSEC enabled
  dnsSecTrustChain = True
  (nameserverName, nameserver) = random.choice(listOfAllRootServersAndIPs)
  dnsSecValid = True
  while True:
    message = dns.message.make_query(name, record, want_dnssec=True)
    response = dns.query.udp(message, nameserver)
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
      answerRRSet = response.answer[0]

      answerRR = random.choice(answerRRSet)
      if answerRR.rdtype == dns.rdatatype.CNAME:
        if cnameChainsToFollow == 0:
          raise ValueError("CNAME chain too long.")
        else:
          res = [(nameServerList, completeNameServerList, dnsSecCount, response.answer[0] == backupResolverAnswer[0], "CNAME {}".format(answerRR.target))]
          res.extend(lookupNameRecursive(answerRR.target, record, cnameChainsToFollow - 1))
          return res
      # Running answer.address breaks the lookup of MX records. Support will be added if needed.
      # To fix MX record support, returning full answer RR set.
      return [(nameServerList, completeNameServerList, zoneList, dnsSecCount, response.answer[0] == backupResolverAnswer[0], answerRRSet)]
    else:

      resultingNameServersRRsets = [a for a in response.authority if a.rdtype == dns.rdatatype.NS]
      listOfAllNameServers = []

      nsGroup = resultingNameServersRRsets[0]

      zoneList.append(nsGroup.name)

      # Iterate over start of authorities (e.g., com., edu.)
      for ns in nsGroup:
        listOfAllNameServers.append(ns.target.to_text())

      listOfAllNameServersAndIPs = []
      for g in response.additional:
        if g.rdtype != dns.rdatatype.A:
          continue
        if g.name.to_text() in listOfAllNameServers:
          for nsAddress in g:
            listOfAllNameServersAndIPs.append((g.name.to_text(), nsAddress.address))

      if len(listOfAllNameServersAndIPs) == 0:
        print("Authoratative NS not found in glue records.")
        print("Glueless DNS not supported.")
        print("Authoratative NS list: \n{}".format(response.authority[0]))
        print("Glue record list: \n{}".format(response.additional))
        raise ValueError("No NS records could be resolved from the additional records. Possibly glueless DNS.", response.authority[0], response.additional)
      completeNameServerList.append(listOfAllNameServersAndIPs)
      (nameserverName, nameserver) = random.choice(listOfAllNameServersAndIPs)
      
def getFullDNSTargetIPList(lookupResult):
  ipList = []
  for cnameLookup in lookupResult:
    dnsSecCount = cnameLookup[3]
    completeNameServerLists = cnameLookup[1]
    for zoneIndex in xrange(dnsSecCount, len(completeNameServerLists)):
        completeNameServerList = completeNameServerLists[zoneIndex]
        for nsName, nsIP in completeNameServerList:
            ipList.append(nsIP)
  return ipList

# This is the full list of IPs that could be hijacked.
# Use this to calculate attack viability probability.
def getFullTargetIPList(name, record, includeARecords):
  if includeARecords:
    if record != dns.rdatatype.A:
      raise ValueError("Requested inclusion of A records in target IP list but query was for other record type.", record)
    lookupResult = lookupName(name, record)
    res = getFullDNSTargetIPList(lookupResult)
    res.extend(getAllAddressesForHostnameFromResultChain(lookupResult))
    return res
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
#print(lookupA("www.tmall.com"))
print(getFullTargetIPList("live.com", dns.rdatatype.A, False))
#print(getAllAddressesForHostname("yahoo.com"))


#print([str(mx) for mx in lookupName("yahoo.com", dns.rdatatype.MX)[0][5]])

#print([str(caa) for caa in lookupName("google.com", dns.rdatatype.CAA)[0][5]])  

