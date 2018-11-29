# Resolve certificates for cert database.
import routing_aware_dns_resolver as rad
import MySQLdb as db
import time

import Queue
import threading
import urllib2

import os,sys
import traceback
import json



# Code to use external read certificate history.
#import imspect
#currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
#parentdir = os.path.dirname(currentdir)
#bgpfpstudy = parentdir + "/BGP-age-false-positive-study"
#sys.path.insert(0,bgpfpstudy) 
#from read_certificate_history import getNextCertificate

from read_certificate_history_unordered import getNextCertificate

# 100 is a good production thread count, but for testing 5 threads is more stable.
threadCount = 50






scriptPath = os.path.dirname(os.path.realpath(__file__))


lastCertificateIndexProcessedFileLocation = scriptPath + "/last-certificate-index-processed.var"

lastCertificateIndexProcessedFile = open(lastCertificateIndexProcessedFileLocation, 'wb')

logFile = open(scriptPath + "/full-output.log", 'a')

def getLogHeader():
  return "[@{}] ".format(time.time())

def writeLog(*lines):
  for line in lines:
    logFile.write(getLogHeader() + line + "\n")
  logFile.flush()

writeLog("Program Start.")


# called by each thread
def processCertificate(certificate, conn, cursor):
  global certsProcessed
  writeLog("cn={}: Processing Certificate".format(certificate["commonName"]))
  retry = 0
  error = None
  while retry < 3:
    retry += 1
    try:
      lookup = rad.lookupA(certificate["commonName"])
      partialIPList = rad.getFullDNSTargetIPList(lookup)
      fullIPList = rad.getPartialDNSTargetIPList(lookup)
      allAddresses = rad.getAddressForHostnameFromResultChain(lookup)
      matchedBackupResolver = rad.checkMatchedBackupResolver(lookup)
      sql = "INSERT INTO dnsLookups (certSqlId, region, resolvedIPs, partialDNSIPs, fullDNSIPs, matchedBackupResolver) VALUES ({}, 'Los Angeles', '{}', '{}', '{}', {})".format(certificate["sqlId"], json.dumps(allAddresses), json.dumps(partialIPList), json.dumps(fullIPList), "true" if matchedBackupResolver else "false")
      cursor.execute(sql)
      conn.commit()
      writeLog("cn={}: lookup had no errors.".format(certificate["commonName"]), 
        "cn={}: full lookup result: {}".format(certificate["commonName"], str(lookup)), 
        "cn={}: result portion of lookup as text: {}".format(certificate["commonName"], str([answer[5].to_text() for answer in lookup])), 
        "cn={}: sql committed to server: {}".format(certificate["commonName"], sql))
      error = None
      break
      #print("cn {} processed".format(certificate["commonName"]))
      #print("cn common name: {}, lookup result {}.".format(certificate["commonName"], rad.lookupA(certificate["commonName"])))
    except ValueError as e:

      errMsg = str(e)
      if errMsg.startswith("NXDOMAIN"):
        cursor.execute("INSERT INTO dnsLookups (certSqlId, region, lookupError) VALUES ({}, 'Los Angeles', '{}')"
          .format(certificate["sqlId"], "NXDOMAIN"))
        conn.commit()
        print("NXDOMAIN for cn " + certificate["commonName"])
      elif errMsg.startswith("SERVFAIL"):
        cursor.execute("INSERT INTO dnsLookups (certSqlId, region, lookupError) VALUES ({}, 'Los Angeles', '{}')"
          .format(certificate["sqlId"], "SERVFAIL"))
        conn.commit()
        print("SERVFAIL for cn " + certificate["commonName"])
      elif errMsg.startswith("NoAnswer"):
        cursor.execute("INSERT INTO dnsLookups (certSqlId, region, lookupError) VALUES ({}, 'Los Angeles', '{}')"
          .format(certificate["sqlId"], "NoAnswer"))
        conn.commit()
        print("NoAnswer for cn " + certificate["commonName"])
      elif errMsg.startswith("NoNameservers"):
        cursor.execute("INSERT INTO dnsLookups (certSqlId, region, lookupError) VALUES ({}, 'Los Angeles', '{}')"
          .format(certificate["sqlId"], "NoNameservers"))
        conn.commit()
        print("NoNameservers for cn " + certificate["commonName"])
      else:
        writeLog("cn={}: Unhandled value error: {}".format(certificate["commonName"], errMsg))
        cursor.execute("INSERT INTO dnsLookups (certSqlId, region, lookupError) VALUES ({}, 'Los Angeles', '{}')"
          .format(certificate["sqlId"], "Unhandled value error"))
        conn.commit()
      writeLog("cn={}: ERROR, VALUE ERROR in lookup: {}".format(certificate["commonName"], errMsg))
      error = None
      break
    except Exception as e:
      writeLog("cn={}: ERROR, UNHANDLED EXCEPTION in lookup causing retry (retry count of {}): {}".format(certificate["commonName"], retry, str(e)))
      error = e
      continue
  if error:
    cursor.execute("INSERT INTO dnsLookups (certSqlId, region, lookupError) VALUES ({}, 'Los Angeles', '{}')"
      .format(certificate["sqlId"], "Unhandled exception"))
    conn.commit()
    writeLog("cn={}: ERROR, UNHANDLED EXCEPTION in lookup written to server (max retries reached): {}".format(certificate["commonName"], str(error)))
  certsProcessed += 1    

def workerFunction(q):
  conn = db.connect('localhost', 'routeages', 'routeages', 'routeagescalc',  port=3306)
  cursor = conn.cursor()
  elem = q.get()
  while elem != None:
    processCertificate(elem, conn, cursor)
    elem = q.get()

queues = [None] * threadCount

for index in xrange(threadCount):
  queues[index] = Queue.Queue()


for q in queues:
    t = threading.Thread(target=workerFunction, args = (q,))
    # Change daemon to True to allow program to exit before all threads are done.
    #t.daemon = True
    t.start()

certsProcessed = 1
startTime = time.time()
cert = getNextCertificate(lastCertificateIndexProcessedFile)
while cert != None:
  elapsed = time.time() - startTime
  secondsPerACertificate = elapsed / certsProcessed
  print("Sec per a cert: {}".format(secondsPerACertificate))
  print("Certs processed: {}".format(certsProcessed))
  writeLog("Sec per a cert: {}".format(secondsPerACertificate))
  writeLog("Certs processed: {}".format(certsProcessed))
  shortestQueueLength = 10
  shortestQueue = None
  for q in queues:
    #print(q.qsize())
    if q.empty():
      shortestQueue = q
      shortestQueueLength = 0
      break
    elif q.qsize() < shortestQueueLength:
      shortestQueueLength = q.qsize()
      shortestQueue = q
  if shortestQueue != None:
    shortestQueue.put(cert)
    cert = getNextCertificate(lastCertificateIndexProcessedFile)
  else:
    try:
      time.sleep(3)
    except KeyboardInterrupt:
      print("Keyboard Interrupt. Processing queued certificates and exiting program.")
      writeLog("Program Stopping: Keyboard Interrupt")
      # exit all threads.
      for q in queues:
        q.put(None)
      exit()

print("Final Certificate Queued. Processing queued certificates and exiting program.")
writeLog("Program Stopping: Finished Certificates")
#queues[0].put()
#queues[0].put(getNextCertificate(lastCertificateIndexProcessedFile))
#queues[0].put(getNextCertificate(lastCertificateIndexProcessedFile))
#queues[0].put(getNextCertificate(lastCertificateIndexProcessedFile))
for q in queues:
  q.put(None)
