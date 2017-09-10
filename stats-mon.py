#!/usr/bin/python
#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
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
#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
"""
stats-mon.py:  Collect metrics and log to time-series database

Used to supplement standard SNMP monitoring for metrics not otherwise reported.
Initial support for Fan speeds, Temperatures, and Power consumption of
Ubiquiti EdgeOS-based EdgeMAX platforms.

Metrics are collected and consolidated as relevant time-series measurements.
Each poll cycle is further consolidated as a single measurement set for
publication.

Measurement sets are queued for semi-reliable publication to time series
database.  If publication fails the measurements remain queued to try again
with the next polling interval.  Measurement sets accumulate up to the
maximum configured value, at which point the oldest sets are discarded
to accomodate more recent measurements.

Logging is performed via standard python 'logger' facilities, with a
syslog handler explicitly configured.
"""

__author__     = "WaterByWind"
__copyright__  = "Copyright 2017, Waterside Consulting, inc."
__license__    = "MIT"
__version__    = "1.0"
__maintainer__ = "WaterByWind"
__email__      = "WaterByWind@WatersideConsulting.com"
__status__     = "Development"

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Dependencies
##
import sys
import os
import time
import re
import errno
import subprocess
import logging
import resource
from datetime import datetime
from logging.handlers import SysLogHandler
from socket import gethostname

# For EdgeOS without standard modules which all get listed below
# This specific method is needed for now but may change back to from . import. . .
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# python-influxdb seems to be "broken" now and needs the extra explicit imports
import requests
import requests.exceptions
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError
from influxdb.exceptions import InfluxDBServerError

# TODOs
# - cmd line options
# - possible as snmpd subagent (AgentX?)
# - additional metrics
#   - firewall/nat hit counts
#   - conntrack?  Prob need conntrackd which doesn't exist here
#   - services?
# - Additional publish services?
# - Drop privileges? (not run as root)
#   - Risk and value here?
# - Internal metrics (cpu, etc) for tracking monitoring impact
#
# Modules for AgentX:
# -- netsnmpagent:  https://pypi.python.org/pypi/netsnmpagent
# -- pyagentx:      https://pypi.python.org/pypi/pyagentx
#


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Configuration
##

# Interval between start of each poll cycle, in seconds; Fraction OK (but why?)
TIME_POLL_INTERVAL = 60.0

# Maximum number of queued measurement sets
MAX_SETS_QUEUED = 1024

# Detach and become daemon
DEF_DAEMON = True

# Logging
LOGLEVEL = logging.DEBUG                # Python logging level
LOGFACILITY = SysLogHandler.LOG_LOCAL5  # syslog facility
LOGSOCK = '/dev/log'                    # syslog socket

# Defaults for becoming daemon
DEF_DIR_WORK = '/'                      # Default working dir
DEF_UMASK = 0o0000                      # Default UMASK in octal
DEF_MAX_FD = 4096                       # Default max FD to close()

# Defaults for PID lockfile
LOCKDIR = '/var/run'                    # Directory for pidfile
LOCKFILE = 'stats-mon.pid'              # pidfile name
MAX_LOCK_ATTEMPT = 5                    # Attempts to acquire pidfile

# InfluxDB connection parameters
INFLUXDB = {
    'HOST'    : 'influxdb.localdomain.com',
    'PORT'    : '8086',
    'USER'    : 'user',
    'PASSWD'  : 'password',
    'DATABASE': 'edgemax'
}

##
# Configuration Ends here
##
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# "Constant" definitions
##
# Capabilities known
CAP_FAN = 'fan'
CAP_POWER = 'power'
CAP_TEMP = 'temp'
LIST_CAP = [CAP_FAN, CAP_POWER, CAP_TEMP]

# External paths and arguments
BIN_UBNTHAL = '/usr/sbin/ubnt-hal'

CMD_HAL = {
    CAP_FAN: 'getFanTach',
    CAP_POWER: 'getPowerStatus',
    CAP_TEMP: 'getTemp'
}

# Device types known
DEV_EDGEROUTER = 'edgerouter'

#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Exception classes
##

class LockError(RuntimeError):
    """ Base exception for errors while aquiring a lock """

    def __init__(self, msg='(unknown)'):
        self.msg = 'Failed to acquire lock: {}'.format(msg)
        super(LockError, self).__init__(self.msg)


class AcquireLockError(LockError):
    """ Unexpected failure after too many retries """
    pass


class ProcessRunningError(LockError):
    """ Another instance already found running """
    pass


class MissingOSExecutable(RuntimeError):
    """ Exception for missing OS executables """

    def __init__(self, msg='(unknown)'):
        self.msg = 'Missing OS executable: {}'.format(msg)
        super(MissingOSExecutable, self).__init__(self.msg)


class NothingToDo(RuntimeError):
    """ Exception when no metrics to collect """

    def __init__(self, msg='(unknown)'):
        self.msg = 'Nothing to do: {}'.format(msg)
        super(NothingToDo, self).__init__(self.msg)


class InternalError(RuntimeError):
    """ Base exception for unexpected internal errors """

    def __init__(self, msg='(unknown)'):
        self.msg = 'Internal error: {}'.format(msg)
        super(InternalError, self).__init__(self.msg)


class UnexpectUseError(InternalError):
    """ Unexpected attempt to use/monitor non-existing entity """
    pass


class MeasureMismatchError(InternalError):
    """ Attempt to add mismatched measurement to series """
    pass


class DaemonError(Exception):
    """ Base exception for errors while becoming a daemon """

    def __init__(self, msg='(unknown)'):
        self.msg = 'Failure becoming a daemon: {}'.format(msg)
        super(DaemonError, self).__init__(self.msg)


class DaemonChdirError(DaemonError):
    """ Failed chdir() while becoming a daemon """

    def __init__(self, tdir='', errno=0, msg='(unknown)'):
        self.msg = 'Failed chdir({}): [errno={}] {}'.format(tdir, errno, msg)
        super(DaemonChdirError, self).__init__(self.msg)


class DaemonForkError(DaemonError):
    """ Failed fork() while becoming a daemon """

    def __init__(self, stage='', errno=0, msg='(unknown)'):
        self.msg = 'Failed {} fork(): [errno={}] {}'.format(stage, errno, msg)
        super(DaemonForkError, self).__init__(self.msg)


class DaemonOpenError(DaemonError):
    """ Failed open()/dup2() while becoming a daemon """

    def __init__(self, e):
        if hasattr(e, 'filename'):
            _msg = 'open({})'.format(e.filename)
        else:
            _msg = 'dup2()'
        self.msg = 'Failed {}: [errno={}] {}'.format(_msg, e.errno, e.strerror)
        super(DaemonOpenError, self).__init__(self.msg)


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Publisher Classes
##
# -- perhaps create base class TimeSeriesPublisher with more dbs supported?

class InfluxDBPublisher(object):
    def __init__(self,
                 host='localhost',
                 port=8086,
                 username='nobody',
                 password='nobody',
                 database=None,
                 ssl=False,
                 verify_ssl=False,
                 timeout=None,
                 retries=3,
                 use_udp=False,
                 udp_port=4444,
                 proxies=None
                 ):
        self.connP = {'host': host,
                      'port': port,
                      'username': username,
                      'password': password,
                      'database': database,
                      'ssl': ssl,
                      'verify_ssl': verify_ssl,
                      'timeout': timeout,
                      'retries': retries,
                      'use_udp': use_udp,
                      'udp_port': udp_port,
                      'proxies': proxies
                      }
        self.dataList = []
        self._pointSet = []

        logging.debug('Creating InfluxDB client to server: {}:{}/{}'.format(
            self.connP['host'], self.connP['port'], self.connP['database']))
        self._client = InfluxDBClient(**self.connP)

    def _doWrite(self, jsonList):
        logging.debug('Writing {} series to db: {}'.format(
            len(jsonList), jsonList))
        success = False

        try:
            self._client.write_points(jsonList)
        except requests.exceptions.ConnectionError as e:
            logging.error('Connection Error: {}'.format(e))
        except InfluxDBClientError as e:
            logging.error('InfluxDBClientError: {}'.format(e))
        except InfluxDBServerError as e:
            logging.error('InfluxDBServerError: {}'.format(e))
        except:
            e = sys.exc_info()[0]
            logging.error('Exception: {}'.format(e))
        else:
            success = True
        return(success)

    def queuePoint(self, jsonBody):
        self._pointSet.append(jsonBody)

    def stageQueue(self):
        if len(self._pointSet) > 0:
            # If reached/exceeded maximum number of queueed measurement
            # sets discard oldest entries to accomodate new entries
            while len(self.dataList) >= MAX_SETS_QUEUED:
                logging.warning(
                    'Max queued measurement set count of {} exceeded'.format(MAX_SETS_QUEUED))
                discard = self.dataList.pop(0)
                logging.warning('Discarding oldest set: {}'.format(discard))
            self.dataList.append(self._pointSet)
            self._pointSet = []

    def publish(self):
        self.stageQueue()
        while len(self.dataList) > 0:
            # Fetch next data set to publish
            pset = self.dataList.pop(0)
            # Publish single data set
            if not self._doWrite(pset):
                # Failure:  put data back to try again later
                self.dataList.insert(0, pset)
                logging.warning(
                    'Deferring publish of {} sets to next poll interval'.format(len(self.dataList)))
                break


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Device classes
##

class BaseDevice(object):
    def __init__(self):
        self._method = {}.fromkeys(LIST_CAP, None)
        self._measurements = []

    def _regMethod(self, cap, method):
        self._method[cap] = method

    def _fetchExt(self, mp, cap, cmd):
        if not self.hasCap(cap):
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            cstr = ' '.join(map(str, cmd))
            msg = '{}.{}: Unexpected attempt to use non-asserted capability: \'{}\''.format(
                cls, func, cstr)
            raise UnexpectUseError(msg)
        elif mp.measurement != cap:
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            msg = '{}.{}: Incorrect measurement type \'{}\' passed'.format(
                cls, func, mp.measurement)
            raise MeasureMismatchError(msg)
        else:
            # Should probably catch subprocess.CalledProcessError and OSError
            cmdOut = subprocess.check_output(cmd)
        return(cmdOut)

    def listCap(self):
        return ([k for k, v in self._method.items() if v is not None])

    def hasCap(self, key):
        return (self._method.get(key, None) is not None)

    def read(self, cap, mp):
        success = False
        mp.resetpoint()
        f = self._method.get(cap, None)
        if f is not None:
            success = f(mp)
        return(success)


class EdgeRouter(BaseDevice):
    def __init__(self):
        super(EdgeRouter, self).__init__()
        self.devtype = DEV_EDGEROUTER
        if not os.path.isfile(BIN_UBNTHAL):
            raise MissingOSExecutable(BIN_UBNTHAL)

        # If capability is supported, assert availability
        if self._checkCap(CAP_FAN):
            self._regMethod(CAP_FAN, self._readFan)
        if self._checkCap(CAP_POWER):
            self._regMethod(CAP_POWER, self._readPower)
        if self._checkCap(CAP_TEMP):
            self._regMethod(CAP_TEMP, self._readTemp)
        return

    def _checkCap(self, cap):
        cmd = [BIN_UBNTHAL, CMD_HAL[cap]]
        supported = False
        try:
            out = subprocess.check_output(
                cmd, stderr=subprocess.STDOUT).splitlines()[-1]
        except subprocess.CalledProcessError:
            pass
        else:
            if not out.endswith('not supported on this platform'):
                supported = True
        return(supported)

    def _readFan(self, mp):
        cmd = [BIN_UBNTHAL, CMD_HAL[CAP_FAN]]
        success = False

        try:
            cmdOut = self._fetchExt(mp, CAP_FAN, cmd)
        except (UnexpectUseError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            for line in cmdOut.splitlines():
                items = line.split(':')
                if len(items) < 2:
                    continue
                key = re.sub(r'\s*', r'', items[0]).lower()
                val = re.sub(r'\s*([0-9]*)\s*RPM\s*', r'\1', items[1])
                if val != '':
                    mp.addfield(key, int(val))
            success = True
        return(success)

    def _readPower(self, mp):
        cmd = [BIN_UBNTHAL, CMD_HAL[CAP_POWER]]
        success = False

        try:
            cmdOut = self._fetchExt(mp, CAP_POWER, cmd)
        except (UnexpectUseError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            for line in cmdOut.splitlines():
                items = line.split(':')
                if len(items) < 2:
                    continue
                key = re.sub(r'System\s*([a-z]+).*', r'\1', items[0])
                val = re.sub(r'\s*([0-9.]*)\s*[VAW]\s*', r'\1', items[1])
                if val != '':
                    mp.addfield(key, float(val))
            success = True
        return(success)

    def _readTemp(self, mp):
        cmd = [BIN_UBNTHAL, CMD_HAL[CAP_TEMP]]
        success = False

        try:
            cmdOut = self._fetchExt(mp, CAP_TEMP, cmd)
        except (UnexpectUseError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            for line in cmdOut.splitlines():
                items = line.split(':')
                if len(items) < 2:
                    continue
                key = re.sub(r'\s*', r'', items[0]).lower()
                val = re.sub(r'\s*([0-9.]*)\s*C\s*', r'\1', items[1])
                if val != '':
                    mp.addfield(key, float(val))
            success = True
        return(success)


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Measurement classes
##

class MeasurePoint(object):
    """ Base class for all measurements """

    def __init__(self):
        self._resettags()
        self._resetfields()

    def _resettags(self):
        self.tags = {}

    def _resetfields(self):
        self.fields = {}

    def _stamptime(self):
        self.tstamp = datetime.utcnow()

    def resetpoint(self):
        self._resettags()
        self._resetfields()
        self.addtag('host', gethostname())
        self._stamptime()

    def addtag(self, key, val):
        self.tags[key] = val

    def addfield(self, key, val):
        self.fields[key] = val

    def getRecInflux(self):
        t = ','.join(['{}={}'.format(k, self.tags[k])
                      for k in self.tags.keys()])
        f = ','.join(['{}={}'.format(k, self.fields[k])
                      for k in self.fields.keys()])
        s = '{},{} {} {}Z'.format(
            self.measurement, t, f, self.tstamp.isoformat('T'))
        return(s)

    def getRecJSON(self):
        jsonBody = {
            'measurement': self.measurement,
            'time': self.tstamp.isoformat('T') + 'Z',
            'tags': self.tags,
            'fields': self.fields
        }
        return(jsonBody)


class FanSpeeds(MeasurePoint):
    """ Fan speed time series measurement """

    def __init__(self):
        super(FanSpeeds, self).__init__()
        self.measurement = CAP_FAN


class PowerUse(MeasurePoint):
    """ Power usage time series measurement """

    def __init__(self):
        super(PowerUse, self).__init__()
        self.measurement = CAP_POWER


class Temperatures(MeasurePoint):
    """ Temperature time series measurement """

    def __init__(self):
        super(Temperatures, self).__init__()
        self.measurement = CAP_TEMP


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Context Managers
##

class PidFileLock(object):
    """ Context manager to ensure only a single instance may start """

    def __init__(self):
        self.pid = os.getpid()
        self.fpath = '/'.join((LOCKDIR, LOCKFILE))
        self.fd = None

    def __enter__(self):
        logging.debug('Acquiring PID lockfile: {}'.format(self.fpath))

        def _tryLock():
            try:
                self.fd = os.open(self.fpath,
                                  os.O_CREAT | os.O_EXCL | os.O_RDWR,
                                  0o0644)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
            else:
                # Lock acquired
                return(True)
            # Lock not acquired
            return(False)

        def _staleLock():
            with open(self.fpath, 'r') as f:
                _pid = int(f.read())
            try:
                os.kill(_pid, 0)
            except OSError as e:
                if e.errno == errno.ESRCH:
                    # PID does not exist
                    logging.warning(
                        'Removing stale lock from non-existent pid {}'.format(_pid))
                    os.unlink(self.fpath)
                    return(True)
                elif e.errno == errno.EPERM:
                    # Permission denied implies PID exists
                    raise ProcessRunningError(
                        'Existing instance pid={}'.format(_pid))
                else:
                    raise
            # PID exists
            raise ProcessRunningError('Existing instance pid={}'.format(_pid))

        for attempts in xrange(MAX_LOCK_ATTEMPT):
            logging.debug(
                'Lock attempt {}'.format(attempts + 1))
            if _tryLock():
                os.write(self.fd, str(self.pid))
                return(True)
            if not _staleLock():
                raise AcquireLockError(
                    'Unexpected state while checking existing pid')
        raise AcquireLockError(
            'Too mamy attempts: {}'.format(MAX_LOCK_ATTEMPT))

    def __exit__(self, eType, eValue, eTraceBack):
        logging.debug('Removing PID lockfile')
        try:
            os.unlink(self.fpath)
            os.close(self.fd)
        except (OSError, IOError):
            pass
        return(False)


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Support functions
##

def initLogging():
    """ Configure logging framework """
    logging.basicConfig(level=LOGLEVEL,
                        format='%(module)s:%(funcName)s:%(levelname)s %(asctime)s %(message)s')
    syslog = SysLogHandler(address=LOGSOCK, facility=LOGFACILITY)
    formatter = logging.Formatter(
        '%(module)s:%(funcName)s:%(levelname)s %(message)s')
    syslog.setFormatter(formatter)
    logger = logging.getLogger()
    logger.addHandler(syslog)


def handleException(eType, eValue, eTraceback):
    """ Replacement exception hook handler """
    """ Ensure uncaught exceptions get logged even if a daemon """
    logging.error("Fatal exception", exc_info=(eType, eValue, eTraceback))


def daemonize(workdir='/', umask=0o0000):
    """ Become standard *nix daemon """
    def _doFork(depth=''):
        try:
            pid = os.fork()
        except OSError as e:
            raise DaemonForkError(depth, e.errno, e.strerror)
        if (pid > 0):
            # Parent exits
            os._exit(0)

    logging.debug('Becoming a daemon')
    # First fork
    _doFork('first')
    # Child #1 - detach to new session & process group
    os.setsid()
    # Second fork
    _doFork('second')
    # Child #2 - continue on
    # Set working directory
    try:
        os.chdir(workdir)
    except OSError as e:
        raise DaemonChdirError(e.filename, e.errno, e.strerror)
    # Set file creation mask
    os.umask(umask)
    # Close all open file descriptors
    maxfd = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    if (maxfd == resource.RLIM_INFINITY):
        maxfd = DEF_MAX_FD
    for fd in xrange(maxfd - 1, -1, -1):
        try:
            os.close(fd)
        except OSError:
            # Intentionally ignore
            pass
    # Redirect stdin, stdout, stderr to /dev/null
    try:
        os.open(os.devnull, os.O_RDWR)
        os.dup2(0, 1)
        os.dup2(0, 2)
    except (OSError, IOError) as e:
        raise DaemonOpenError(e)
    logging.debug('Now running as a daemon')


# Process one full monitor cycle
# TODO:  This needs work!
def doCycle(monDev, dbC):
    for c in monDev.listCap():
        if c == CAP_FAN:
            p = FanSpeeds()
        elif c == CAP_POWER:
            p = PowerUse()
        elif c == CAP_TEMP:
            p = Temperatures()
        monDev.read(c, p)
        logging.debug('Measurement: {}'.format(p.getRecInflux()))
        dbC.queuePoint(p.getRecJSON())
    dbC.publish()


def main():
    """ This is where it all begins """
    initLogging()
    logging.info('Starting')
    sys.excepthook = handleException
    detach = DEF_DAEMON
    monDev = EdgeRouter()
    if len(monDev.listCap()) == 0:
        raise NothingToDo('No monitorable entities found')
    if detach:
        daemonize(workdir=DEF_DIR_WORK, umask=DEF_UMASK)

    with PidFileLock():
        dbClient = InfluxDBPublisher(host=INFLUXDB['HOST'],
                                     port=INFLUXDB['PORT'],
                                     username=INFLUXDB['USER'],
                                     password=INFLUXDB['PASSWD'],
                                     database=INFLUXDB['DATABASE']
                                     )
        while True:
            tStart = datetime.utcnow()
            logging.debug('Begin cycle')
            doCycle(monDev, dbClient)
            tDiff = datetime.utcnow() - tStart
            dSec = TIME_POLL_INTERVAL - tDiff.total_seconds()
            if dSec > 0.0:
                time.sleep(dSec)
            else:
                logging.warning(
                    'Cycle exceeded polling interval by {} seconds'.format(abs(dSec)))
            logging.debug('End cycle')

    # Should never reach here
    logging.info('Ending (unexpected)')


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# And away we go. . .
##
if __name__ == '__main__':
    main()
