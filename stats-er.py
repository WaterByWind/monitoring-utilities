#!/usr/bin/python -u
#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The MIT License (MIT)
#
# Copyright (c) 2017 Waterside Consulting, inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
##
## Quick-n-Dirty Read ER environmental parameters
##
#
# Date/Time is exclusively UTC
# Temperatures in Celsius
# Fan speeds in RPM
# Voltage in Volts
# Current in Amps
# Power in Watts
#

##
## Configuration
##
# Interval between start of readings, in seconds, fraction OK
sensorReadInterval = 20.0

#
# Publish to InfluxDB?
#
flg_PubDB=False
# InfluxDB defs
dbHost='influxdb.localdomain.com'
dbPort='8086'
dbUser='edgemax'
dbPass='edgemax'
dbDatabase='edgerouter'

#
# Publish to flat files?
#
flg_PubFile=False
# Directory for files
dirStatsLogs='/config/user-data/monstats'

##
## Configuration ends
##
import sys, os, time, logging, subprocess, re
from datetime import datetime
from socket import gethostname

# For InfluxDB Client
if flg_PubDB:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from influxdb import InfluxDBClient

# External executables
binUBNTHal='/usr/sbin/ubnt-hal'

##
## Supporting functions
##
#
def bailout(msgStr):
	logging.error('FATAL: {}'.format(msgStr))
	raise SystemExit(1);

##
## Readers
##
#
## Read power use
#
def readPower():
    sCmd="getPowerStatus"
    kvList={}

    cmdOutput=subprocess.check_output([binUBNTHal, sCmd])
    for line in cmdOutput.split('\n'):
        items=line.split(':')
        if len(items) < 2:
            continue
        key=re.sub(r'System\s*([a-z]+).*', r'\1', items[0])
        val=re.sub(r'\s*([0-9.]*)\s*[VAW]\s*', r'\1', items[1])
        if val != '':
            kvList[key]=float(val)
    logging.debug('Read power: {}'.format(kvList))
    return kvList
#
## Read platform temps
#
def readTemps():
    sCmd="getTemp"
    kvList={}

    cmdOutput=subprocess.check_output([binUBNTHal, sCmd])
    for line in cmdOutput.split('\n'):
        items=line.split(':')
        if len(items) < 2:
            continue
        key=re.sub(r'\s*', r'', items[0]).lower()
        val=re.sub(r'\s*([0-9.]*)\s*C\s*', r'\1', items[1])
        if val != '':
            kvList[key]=float(val)
    logging.debug('Read temps: {}'.format(kvList))
    return kvList
#
## Read fan speeds
#
def readFans():
    sCmd="getFanTach"
    kvList={}

    cmdOutput=subprocess.check_output([binUBNTHal, sCmd])
    for line in cmdOutput.split('\n'):
        items=line.split(':')
        if len(items) < 2:
            continue
        key=re.sub(r'\s*', r'', items[0]).lower()
        val=re.sub(r'\s*([0-9]*)\s*RPM\s*', r'\1', items[1])
        if val != '':
            kvList[key]=int(val)
    logging.debug('Read fans: {}'.format(kvList))
    return kvList

##
## Writers
##
#
## Publish to InfluxDB
#
def writeDataDB(dbC, tStamp, tempList, fanList, powerList):
        hName=gethostname()
        jsonBody= [
                    {
                        "measurement" : 'fan',
                        "time" : tStamp.isoformat('T') + 'Z',
                        "tags" : {
                                "host" : hName
                            },
                        "fields" : fanList
                    }
                ]
        logging.debug('Writing to db: {}'.format(jsonBody))
        dbC.write_points(jsonBody)
        jsonBody= [
                    {
                        "measurement" : 'temp',
                        "time" : tStamp.isoformat('T') + 'Z',
                        "tags" : {
                                "host" : hName
                            },
                        "fields" : tempList
                    }
                ]
        logging.debug('Writing to db: {}'.format(jsonBody))
        dbC.write_points(jsonBody)
        jsonBody= [
                    {
                        "measurement" : 'power',
                        "time" : tStamp.isoformat('T') + 'Z',
                        "tags" : {
                                "host" : hName
                            },
                        "fields" : powerList
                    }
                ]
        logging.debug('Writing to db: {}'.format(jsonBody))
        dbC.write_points(jsonBody)
	return
#
## Publish to File
#
def writeDataFile(tStamp, tempList, fanList, powerList):

    def writeMeasurement(hName, mName, ts, mDict):
        fStr=''
        delim=''
        fNam = '{}/log-{}.{}.txt'.format(dirStatsLogs, mName, ts.strftime('%F'))
        logging.debug('Using file {}'.format(fNam))
        for k in mDict.keys():
            fStr += '{}{}={}'.format(delim,k,mDict[k])
            delim=','
        logging.debug('Writing {} to file: {}'.format(mName, fStr))
        with open(fNam, 'a') as f:
            f.write('{},host={} {} {}Z\n'.format(mName, hName, fStr, ts.isoformat('T')))
        return

    hName=gethostname()
    writeMeasurement(hName, 'fan', tStamp, fanList)
    writeMeasurement(hName, 'temp', tStamp, tempList)
    writeMeasurement(hName, 'power', tStamp, powerList)
    return

#
## Orchestrator
#
def doCycle(dbC):
        tStamp=datetime.utcnow()
        tempList=readTemps()
        fanList=readFans()
        powerList=readPower()

        if flg_PubDB:
            writeDataDB(dbC, tStamp, tempList, fanList, powerList)
        if flg_PubFile:
            writeDataFile(tStamp, tempList, fanList, powerList)

	return

##
## And away we go
##
if __name__ == "__main__":
	logging.basicConfig(level=logging.INFO)

	if not os.path.isfile(binUBNTHal):
		bailout('Missing ubnt-hal binary: {}'.format(binUBNTHal))
        if flg_PubFile:
            if not os.path.isdir(dirStatsLogs):
                bailout('Missing stats logs directory: {}'.format(dirStatsLogs))
        if flg_PubDB:
            logging.debug('Connecting to database server: {}:{}'.format(dbHost,dbPort))
            dbClient = InfluxDBClient(host=dbHost, port=dbPort, username=dbUser, password=dbPass, database=dbDatabase)
        else:
            dbClient=False

	while True:
		tStart = datetime.utcnow()
		logging.debug('Begin read/log cycle at {}'.format(tStart))
		doCycle(dbClient)
		tDiff = datetime.utcnow() - tStart
		tSec = sensorReadInterval - tDiff.total_seconds()
		if tSec > 0.0:
			time.sleep(tSec)
		else:
			logging.warning('Read cycle exceeded read polling interval')

# Not reached
sys.exit(0)
