# This file presents a que to get the next certificate that is available. It is instantanious in this version but eventually will be blocking.
# This file is included by test_certs.py and is a core file for the route age study.

import MySQLdb as mariadb
#import sqlite3
import time
import sys
import os
import os.path

# Python mysql connect statement
conn = mariadb.connect('localhost', 'routeages', 'routeages', 'routeagescalc',  port=3306)

# SQlite3 connect statement.
#conn = sqlite3.connect('../routeages.db')
cursor = conn.cursor()
result = None


scriptPath = os.path.dirname(os.path.realpath(__file__))
lastCertificateIndexProcessedFileLocation = scriptPath + "/last-certificate-index-processed.var"
# The name of this variable is misleading. 0 means that the first certificate in the database has NOT been processed and is next in que for processing.
lastCertificateIndexProcessed = 0

if not os.path.isfile(lastCertificateIndexProcessedFileLocation) or os.stat(lastCertificateIndexProcessedFileLocation).st_size == 0:
	with open(lastCertificateIndexProcessedFileLocation, 'wb') as lastCertificateIndexProcessedFile:
		lastCertificateIndexProcessedFile.write("0000000000000000")#The file is 16 base 16 digits long.
# Open the file in read mode ot get the current value. Then close the file in read mode and open it in write mode. The b after the r stands for binary and assures us we won't run into issues with \n on windows.
with open(lastCertificateIndexProcessedFileLocation, 'rb') as lastCertificateIndexProcessedFile:
	lastCertificateIndexProcessed = int(lastCertificateIndexProcessedFile.read())



def pad16(number): #pads a number to be 16 bytes of decimal ASCII.
	return "{0:016d}".format(number)
def writeLastCertificateIndexProcessedToDB(lastCertificateIndexProcessedFile):
	global lastCertificateIndexProcessed
	lastCertificateIndexProcessedFile.seek(0) # reset the file writing head to the beginning.
	lastCertificateIndexProcessedFile.write(pad16(lastCertificateIndexProcessed)) #The file is 16 base 16 digits long.

# This function was improved to include limiting to prevent from loading the entire db into ram at once.
def getNewCerts():
	global result, cursor, index, lastCertificateIndexProcessed
	cursor.execute("""SELECT sqlId, webCertId, commonName, certTimestamp, processingTimestamp, 
		resolvedIP FROM certificates LIMIT 100000 OFFSET {0}""".format(lastCertificateIndexProcessed))
	if (cursor.rowcount == 0):
		# This is an exit condition. We are out of certificates and thus are done with processing.
		print "SQL for certificates returned no rows (no more certs remain). Exiting."
		sys.stdout.flush()
		exit()

def getNextCertificate(lastCertificateIndexProcessedFile):
	global cursor, result, lastCertificateIndexProcessed
	while result == None:
		getNewCerts()
		result = cursor.fetchone()

	retValue = {"timestamp": result[3], "commonName": result[2], "processingTimestamp": result[4], "sqlId": result[0], 
		"webCertId": result[1], "resolvedIP": result[5]}
	result = cursor.fetchone()

	#print "cert with timestamp      : " + str(retValue['timestamp'])
	#sys.stdout.flush()
	lastCertificateIndexProcessed += 1
	writeLastCertificateIndexProcessedToDB(lastCertificateIndexProcessedFile)
	return retValue
