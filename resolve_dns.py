# Resolve certificates for cert database.
import routing_aware_dns_resolver as rad
import MySQLdb as db
import time

import Queue
import threading
import urllib2

import os,sys


# Code to use external read certificate history.
#import imspect
#currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
#parentdir = os.path.dirname(currentdir)
#bgpfpstudy = parentdir + "/BGP-age-false-positive-study"
#sys.path.insert(0,bgpfpstudy) 
#from read_certificate_history import getNextCertificate

from read_certificate_history_unordered import getNextCertificate



threadCount = 4
#threadCount = 200





scriptPath = os.path.dirname(os.path.realpath(__file__))


lastCertificateIndexProcessedFileLocation = scriptPath + "/last-certificate-index-processed.var"

lastCertificateIndexProcessedFile = open(lastCertificateIndexProcessedFileLocation, 'wb')





# called by each thread
def processCertificate(certificate):
  try:
    rad.lookupA(certificate["commonName"])
    #print("cn common name: {}, lookup result {}.".format(certificate["commonName"], rad.lookupA(certificate["commonName"])))
  except ValueError as e:
    errMsg = str(e)
    if errMsg.startswith("NXDOMAIN"):
      print("NXDOMAIN for cn " + certificate["commonName"])
    elif errMsg.startswith("SERVFAIL"):
      print("SERVFAIL for cn " + certificate["commonName"])
    else:
      raise

def workerFunction(q):
  elem = q.get()
  while elem != None:
    processCertificate(elem)
    elem = q.get()

queues = [None] * threadCount

for index in xrange(threadCount):
  queues[index] = Queue.Queue()


for q in queues:
    t = threading.Thread(target=workerFunction, args = (q,))
    # Change daemon to True to allow program to exit before all threads are done.
    #t.daemon = True
    t.start()


cert = getNextCertificate(lastCertificateIndexProcessedFile)
while cert != None:
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
      # exit all threads.
      for q in queues:
        q.put(None)
      exit()

print("Final Certificate Queued. Processing queued certificates and exiting program.")
#queues[0].put()
#queues[0].put(getNextCertificate(lastCertificateIndexProcessedFile))
#queues[0].put(getNextCertificate(lastCertificateIndexProcessedFile))
#queues[0].put(getNextCertificate(lastCertificateIndexProcessedFile))
for q in queues:
  q.put(None)