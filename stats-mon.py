#!/usr/bin/python
#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Waterside Consulting, inc.
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
Ubiquiti EdgeOS-based EdgeMAX platforms.  Additional support now includes
netfilter (iptables) rule counters, detailed memory stats, conntrack,
kernel "random" entropy, vmstat, offload stats, per-cpu interrupts
(HW and SW), and kernel cache stats.

Metrics are collected and consolidated as relevant time-series measurements.
Each poll cycle is further consolidated as a single measurement set for
publication.

Measurement sets are queued for semi-reliable publication to time series
database.  If publication fails the measurements remain queued to try again
with the next polling interval.  Measurement sets accumulate up to the
maximum configured value, at which point the oldest sets are discarded
to accomodate more recent measurements.

Performance data of this monitoring daemon is also collected and published as
part of the rest of the measurements, providing visibility into monitoring
overhead.

Logging is performed via standard python 'logger' facilities, with a
syslog handler explicitly configured.
"""

__author__     = "WaterByWind"
__copyright__  = "Copyright 2020, Waterside Consulting, inc."
__license__    = "MIT"
__version__    = "1.2.7"
__maintainer__ = "WaterByWind"
__email__      = "WaterByWind@WatersideConsulting.com"
__status__     = "Development"

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Dependencies
##
#
# Python Modules
# - subprocess32:     https://pypi.org/project/subprocess32/
# - python-iptables:  https://pypi.org/project/python-iptables/
# - influxdb:         https://pypi.org/project/influxdb/
# - requests:         https://pypi.org/project/requests/
# - urllib3:          https://pypi.org/project/urllib3/
#
import sys
import os
import time
import re
import errno
import logging
import signal
import resource
from datetime import datetime
from logging.handlers import SysLogHandler
from socket import gethostname

# For modules not bundled with EdgeOS, which are in turn listed below
# This specific (ugly) method is needed for now but may change back to relative imports
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'lib'))

# Sanitize executable search path.  'python-iptables' depends upon '/sbin'
# being in the PATH, so let's just get this out of the way now.
os.environ['PATH'] = "/usr/bin:/bin:/usr/sbin:/sbin"

# python-influxdb seems to be "broken" now and needs the extra explicit imports
import requests
import requests.exceptions
from influxdb import InfluxDBClient
from influxdb.exceptions import InfluxDBClientError
from influxdb.exceptions import InfluxDBServerError

# Try to use improved subprocess32 from Python 3
# If not available fall back to original module
if os.name == 'posix' and sys.version_info[0] < 3:
    try:
        import subprocess32 as subprocess
    except ImportError:
        import subprocess
else:
    import subprocess

# Try to use python-iptables.  This is optional, so don't fail if missing
try:
    import iptc
except ImportError:
    iptc = None

#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# TODOs
##
## Need check for running as root
#
# - cmd line options
# - possible as snmpd subagent (AgentX?)
# - additional metrics
#   - conntrack?  Prob need conntrackd which doesn't exist here
#   - services?
# - Additional publish services?
# - Drop privileges? (not run as root)
#   - Risk and value here?
#
# Modules for AgentX:
# -- netsnmpagent:  https://pypi.python.org/pypi/netsnmpagent
# -- pyagentx:      https://pypi.python.org/pypi/pyagentx
#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Configuration
##

# Interval between start of each poll cycle, in seconds; Fraction OK (but why?)
TIME_POLL_INTERVAL = 60.0

# Maximum number of queued measurement sets
MAX_SETS_QUEUED = 1440

# Detach and become daemon?
DEF_DAEMON = True

# Logging
LOGLEVEL = logging.INFO                 # Python logging level
LOGFACILITY = SysLogHandler.LOG_LOCAL5  # syslog facility
LOGSOCK = '/dev/log'                    # syslog socket

# Defaults for becoming daemon
DEF_DIR_WORK = '/'                      # Default working dir
DEF_UMASK = 0o0000                      # Default UMASK
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
CAP_FANTACH    = 'fan'
CAP_FANCTRL    = 'fanctrl'
CAP_POWER      = 'power'
CAP_TEMP       = 'temp'
CAP_IPTABLES   = 'iptables'
CAP_MEMINFO    = 'meminfo'
CAP_VMSTAT     = 'vmstat'
CAP_CAVSTAT    = 'caviumstat'
CAP_CONNTRACK  = 'conntrack'
CAP_ENTROPY    = 'randentropy'
CAP_INTERRUPTS = 'interrupts'
CAP_SOFTIRQS   = 'softirqs'
CAP_SELFSTAT   = 'monstats'
CAP_SLABINFO   = 'slabinfo'

# Default capabilities to attempt to use
LIST_CAP = [CAP_FANTACH, CAP_FANCTRL, CAP_POWER, CAP_TEMP, CAP_IPTABLES,
    CAP_MEMINFO, CAP_VMSTAT, CAP_CAVSTAT, CAP_CONNTRACK, CAP_ENTROPY,
    CAP_INTERRUPTS, CAP_SOFTIRQS, CAP_SELFSTAT, CAP_SLABINFO]

# External paths and arguments
BIN_UBNTHAL = '/usr/sbin/ubnt-hal'

CMD_HAL = {
    CAP_FANTACH : 'getFanTach',
    CAP_FANCTRL : 'getFanCtrl',
    CAP_POWER   : 'getPowerStatus',
    CAP_TEMP    : 'getTemp'
}

PROC_PATH = {
    CAP_MEMINFO    : '/proc/meminfo',
    CAP_VMSTAT     : '/proc/vmstat',
    CAP_CAVSTAT    : '/proc/cavium/stats',
    CAP_CONNTRACK  : '/proc/sys/net/netfilter',
    CAP_ENTROPY    : '/proc/sys/kernel/random/entropy_avail',
    CAP_INTERRUPTS : '/proc/interrupts',
    CAP_SOFTIRQS   : '/proc/softirqs',
    CAP_SELFSTAT   : '/proc/self/stat',
    CAP_SLABINFO   : '/proc/slabinfo'
}

LIST_FN_CONNTRACK = ['nf_conntrack_max', 'nf_conntrack_count']
LIST_PROC_MON = ['snmpd']

# Device types known
DEV_EDGEROUTER = 'edgerouter'

# Protocols
PROTO_IPv4 = 4
PROTO_IPv6 = 6
LIST_PROTO_IP = [PROTO_IPv4, PROTO_IPv6]

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


class NotImplementedError(InternalError):
    """ Attempt to use method/function that has been defined but not implemented """
    pass


class UnexpectedUseError(InternalError):
    """ Unexpected attempt to use/monitor non-existing entity """
    pass


class UnexpectedTableError(InternalError):
    """ Unexpected iptables table name passed """
    pass


class MeasureMismatchError(InternalError):
    """ Attempt to add mismatched measurement to series """
    pass


class MissingDataSourceError(InternalError):
    """ Asserted capability has no data source """
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

#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Publisher Classes
##
# -- perhaps create base class TimeSeriesPublisher with more dbs supported?

class InfluxDBPublisher(object):
    """ Class for publishing to InfluxDB time-series database """

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
            # If reached/exceeded maximum number of queued measurement
            # sets discard oldest entries to accomodate new entries
            while len(self.dataList) >= MAX_SETS_QUEUED:
                discard = self.dataList.pop(0)
                logging.warning('Max count ({}) of queued measurement sets exceeded'.format(MAX_SETS_QUEUED))
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

#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Device classes
##

class BaseDevice(object):
    """ Base class for all monitored devices """

    def __init__(self):
        self._method = {}.fromkeys(LIST_CAP, None)
        self._dsClass = {}.fromkeys(LIST_CAP, None)
        self._mpClass = {}.fromkeys(LIST_CAP, None)
        self._dataSource = {}.fromkeys(LIST_CAP, None)
        self._measurements = []

    def _regMethod(self, cap, method):
        self._method[cap] = method

    def _regDSClass(self, cap, classobj):
        self._dsClass[cap] = classobj

    def _regMPClass(self, cap, classobj):
        self._mpClass[cap] = classobj

    def getDSClass(self, cap):
        return(self._dsClass.get(cap, None))

    def getMPClass(self, cap):
        return(self._mpClass.get(cap, None))

    def _newDSinst(self, cap):
        DS = self.getDSClass(cap)
        if not DS:
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            msg = '{}.{}: Unexpected attempt to use undefined data source: \'{}\''.format(
                cls, func, cap)
            raise UnexpectedUseError(msg)
        self._dataSource[cap] = DS(cap)

    def _fetchData(self, cap):
        if not self.hasCap(cap):
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            msg = '{}.{}: Unexpected attempt to use non-asserted capability: \'{}\''.format(
                cls, func, cap)
            raise UnexpectedUseError(msg)
        elif not self.hasDataSource(cap):
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            msg = '{}.{}: Asserted capability has no data source: \'{}\''.format(
                cls, func, cap)
            raise MissingDataSourceError(msg)
        else:
            if not self.hasDSinst(cap):
                self._newDSinst(cap)
            fetchOut = self._dataSource[cap].getstats()
        return(fetchOut)

    def listCap(self):
        return ([k for k, v in self._method.items() if v is not None])

    def hasCap(self, key):
        return (self._method.get(key, None) is not None)

    def hasDataSource(self, key):
        return (self._dsClass.get(key, None) is not None)

    def hasDSinst(self, key):
        return (self._dataSource.get(key, None) is not None)

    def read(self, cap):
        f = self._method.get(cap, None)
        if f is None:
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            msg = '{}.{}: Unexpected attempt to use undefined read method: \'{}\''.format(
                cls, func, cap)
            raise UnexpectedUseError(msg)
        return(f(cap))


class EdgeRouter(BaseDevice):
    """ Class for Ubiquiti EdgeMAX EdgeRouter devices """

    def __init__(self):
        super(EdgeRouter, self).__init__()
        self.devtype = DEV_EDGEROUTER
        if not os.path.isfile(BIN_UBNTHAL):
            raise MissingOSExecutable(BIN_UBNTHAL)
        # If capability is supported, assert availability, define data source and measurement
        if self._checkCap(CAP_FANTACH):
            self._regMethod(CAP_FANTACH, self._readFanTach)
            self._regDSClass(CAP_FANTACH, UBNTHALSource)
            self._regMPClass(CAP_FANTACH, FanSpeeds)
        if self._checkCap(CAP_FANCTRL):
            self._regMethod(CAP_FANCTRL, self._readFanCtrl)
            self._regDSClass(CAP_FANCTRL, UBNTHALSource)
            self._regMPClass(CAP_FANCTRL, FanControl)
        if self._checkCap(CAP_POWER):
            self._regMethod(CAP_POWER, self._readPower)
            self._regDSClass(CAP_POWER, UBNTHALSource)
            self._regMPClass(CAP_POWER, PowerUse)
        if self._checkCap(CAP_TEMP):
            self._regMethod(CAP_TEMP, self._readTemp)
            self._regDSClass(CAP_TEMP, UBNTHALSource)
            self._regMPClass(CAP_TEMP, Temperatures)
        if self._checkCap(CAP_IPTABLES):
            self._regMethod(CAP_IPTABLES, self._readIPtables)
            self._regDSClass(CAP_IPTABLES, IPtableSource)
            self._regMPClass(CAP_IPTABLES, IPtables)
        if self._checkCap(CAP_MEMINFO):
            self._regMethod(CAP_MEMINFO, self._readMemInfo)
            self._regDSClass(CAP_MEMINFO, ProcFSSource)
            self._regMPClass(CAP_MEMINFO, ProcMemInfo)
        if self._checkCap(CAP_VMSTAT):
            self._regMethod(CAP_VMSTAT, self._readVMStat)
            self._regDSClass(CAP_VMSTAT, ProcFSSource)
            self._regMPClass(CAP_VMSTAT, ProcVMStat)
        if self._checkCap(CAP_CAVSTAT):
            self._regMethod(CAP_CAVSTAT, self._readCavStats)
            self._regDSClass(CAP_CAVSTAT, ProcFSSource)
            self._regMPClass(CAP_CAVSTAT, ProcCavStat)
        if self._checkCap(CAP_ENTROPY):
            self._regMethod(CAP_ENTROPY, self._readEntropyAvail)
            self._regDSClass(CAP_ENTROPY, ProcFSSource)
            self._regMPClass(CAP_ENTROPY, ProcEntropyAvail)
        if self._checkCap(CAP_CONNTRACK):
            self._regMethod(CAP_CONNTRACK, self._readConntrack)
            self._regDSClass(CAP_CONNTRACK, ProcFSSource)
            self._regMPClass(CAP_CONNTRACK, ProcConntrack)
        if self._checkCap(CAP_INTERRUPTS):
            self._regMethod(CAP_INTERRUPTS, self._readInterrupts)
            self._regDSClass(CAP_INTERRUPTS, ProcFSSource)
            self._regMPClass(CAP_INTERRUPTS, ProcInterrupts)
        if self._checkCap(CAP_SOFTIRQS):
            self._regMethod(CAP_SOFTIRQS, self._readSoftIRQs)
            self._regDSClass(CAP_SOFTIRQS, ProcFSSource)
            self._regMPClass(CAP_SOFTIRQS, ProcSoftIRQs)
        if self._checkCap(CAP_SELFSTAT):
            self._regMethod(CAP_SELFSTAT, self._readSelfStats)
            self._regDSClass(CAP_SELFSTAT, ProcFSSource)
            self._regMPClass(CAP_SELFSTAT, ProcSelfStats)
        if self._checkCap(CAP_SLABINFO):
            self._regMethod(CAP_SLABINFO, self._readSlabinfo)
            self._regDSClass(CAP_SLABINFO, ProcFSSource)
            self._regMPClass(CAP_SLABINFO, ProcSlabinfo)

    def _checkCap(self, cap):
        supported = False
        if cap == CAP_IPTABLES:
            supported = (iptc is not None)
        elif cap in PROC_PATH:
            supported = os.path.isfile(PROC_PATH[cap])
        elif cap in CMD_HAL:
            try:
                out = subprocess.check_output([BIN_UBNTHAL, CMD_HAL[cap]],
                    stderr=subprocess.STDOUT).splitlines()[-1]
            except subprocess.CalledProcessError:
                pass
            else:
                if not out.endswith('not supported on this platform'):
                    supported = True
        else:
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            msg = '{}.{}: Unexpected attempt to use non-implemented capability: \'{}\''.format(
                cls, func, cap)
            raise UnexpectedUseError(msg)
        if supported:
            logging.debug("Has capability '{}'".format(cap))
        return(supported)

    def _readFanTach(self, cap):
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            for line in fetchOut.splitlines():
                items = line.split(':')
                if len(items) < 2:
                    continue
                key = re.sub(r'\s*', r'', items[0]).lower()
                val = re.sub(r'\s*([0-9]*)\s*RPM\s*', r'\1', items[1])
                if val != '':
                    mp.addfield(key, int(val))
        return([mp])

    def _readFanCtrl(self, cap):
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            key = 'fanctrl'
            if fetchOut != '':
                mp.addfield(key, int(fetchOut))
        return([mp])

    def _readPower(self, cap):
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            for line in fetchOut.splitlines():
                items = line.split(':')
                if len(items) < 2:
                    continue
                key = re.sub(r'System\s*([a-z]+).*', r'\1', items[0])
                val = re.sub(r'\s*([0-9.]*)\s*[VAW]\s*', r'\1', items[1])
                if val != '':
                    mp.addfield(key, float(val))
        return([mp])

    def _readTemp(self, cap):
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            for line in fetchOut.splitlines():
                items = line.split(':')
                if len(items) < 2:
                    continue
                key = re.sub(r'\s*', r'', items[0]).lower()
                val = re.sub(r'\s*([0-9.]*)\s*C\s*', r'\1', items[1])
                if val != '':
                    mp.addfield(key, float(val))
        return([mp])

    def _readIPtables(self, cap):
        mpList = []
        MPClass = self.getMPClass(cap)
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, UnexpectedTableError,
            MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            for p in fetchOut.keys():
                for t in fetchOut[p].keys():
                    tStamp = fetchOut[p][t]['tStamp']
                    for c in fetchOut[p][t]['chains'].keys():
                        rList = fetchOut[p][t]['chains'][c]
                        for rule in rList.keys():
                            mp = MPClass()
                            mp.setpoint(tStamp)
                            mp.addtag('proto', 'IPv{}'.format(p))
                            mp.addtag('table', t)
                            mp.addtag('chain', c)
                            # EdgeOS rule comments, trimmed, as rule name
                            mp.addtag('ruleid', re.sub(r'([0-9]*)\s.*', r'\1', rule))
                            mp.addfield('pkts', rList[rule]['pkts'])
                            mp.addfield('bytes', rList[rule]['bytes'])
                            mpList.append(mp)
        return(mpList)

    def _readMemInfo(self, cap):
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            for line in fetchOut.splitlines():
                items = line.split(':', 1)
                if len(items) < 2:
                    continue
                key = items[0].strip()
                dat = items[1].strip()
                val = int(re.sub(r'\s*([0-9]*)\s*.*', r'\1', dat))
                scale = re.sub(r'\s*[0-9]*\s*([kKmMgG])[bB].*', r'\1', dat)
                # At least as of kernel 5.6 this is still always in kB
                if scale in 'kK':
                    val = val << 10
                elif scale in 'mM':
                    val = val << 20
                elif scale in 'gG':
                    val = val << 30
                mp.addfield(key, val)
        return([mp])

    def _readVMStat(self, cap):
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            for line in fetchOut.splitlines():
                items = line.split()
                if len(items) != 2:
                    continue
                mp.addfield(items[0], int(items[1]))
        return([mp])

    def _readCavStats(self, cap):
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            rexp = re.compile(r'ipv|pppoe|vlan')
            for line in fetchOut.splitlines():
                if '===' in line:
                    continue
                if ':' in line:
                    items = line.split(':', 2)
                    if len(items) < 3:
                        continue
                    _c = re.sub(r'\s+', r'_', re.sub(r' packets', r'', items[0]))
                    _p = items[1].split()[0]
                    _b = items[2].strip()
                    mp.addfield('{}_packets'.format(_c), int(_p))
                    mp.addfield('{}_bytes'.format(_c), int(_b))
                else:
                    items=line.split()
                    if len(items) == 2:
                        if 'ipv' in items[0]:
                            mp.addfield(items[0], int(items[1]))
                    elif len(items) == 5:
                        if rexp.match(items[0]):
                            _r = items[0]
                            mp.addfield('RX_packets_{}'.format(_r), int(items[1]))
                            mp.addfield('RX_bytes_{}'.format(_r), int(items[2]))
                            mp.addfield('TX_packets_{}'.format(_r), int(items[3]))
                            mp.addfield('TX_bytes_{}'.format(_r), int(items[4]))
        return([mp])

    def _readConntrack(self, cap):
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            for line in fetchOut.splitlines():
                items = line.split(':')
                if len(items) != 2:
                    continue
                mp.addfield(items[0], int(items[1]))
        return([mp])

    def _readEntropyAvail(self, cap):
        # Note:  entropy changes continually.  This metric should be used for
        # trending only to identify long-term persistent shortfall
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            mp.addfield('entropy_avail', int(fetchOut.splitlines()[0]))
        return([mp])

    def _readInterrupts(self, cap):
        mpList = []
        MPClass = self.getMPClass(cap)
        tStamp = datetime.utcnow()  # Use single timestamp for this entire measurement
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            ic = {}
            for line in fetchOut.splitlines():
                if ':' in line:
                    (irq, _r) = line.split(':',1)
                    ic[irq.strip()] = _r.split()
                else:
                    cpulist = line.split()
            ncpu = len(cpulist)
            for i in ic.keys():
                _c = ic[i]
                li = len(_c) - 1
                if li >= ncpu:
                    # First #cpu fields are interrupt counters per cpu
                    # Last two fields are controller and device names
                    mp = MPClass()
                    mp.setpoint(tStamp)
                    mp.addtag('irq', i)
                    mp.addtag('device', "{}/{}".format(_c[li-1],_c[li]))
                    for x in range(ncpu):
                        mp.addfield(cpulist[x], int(_c[x]))
                    mpList.append(mp)
        return(mpList)

    def _readSoftIRQs(self, cap):
        mpList = []
        MPClass = self.getMPClass(cap)
        tStamp = datetime.utcnow()  # Use single timestamp for this entire measurement
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            ic = {}
            for line in fetchOut.splitlines():
                if ':' in line:
                    (irq, _r) = line.split(':',1)
                    ic[irq.strip()] = _r.split()
                else:
                    cpulist = line.split()
            ncpu = len(cpulist)
            for i in ic.keys():
                _c = ic[i]
                mp = MPClass()
                mp.setpoint(tStamp)
                mp.addtag('irq', i)
                for x in range(ncpu):
                    mp.addfield(cpulist[x], int(_c[x]))
                mpList.append(mp)
        return(mpList)

    def _readSelfStats(self, cap):
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            mp = self.getMPClass(cap)()
            mp.resetpoint()
            items = fetchOut.split()
            # From proc(5), fields in order:
            #   pid comm state ppid pgrp session tty_nr tpgid flags minflt cminflt
            #   majflt cmajflt utime stime cutime cstime priority nice num_threads
            #   itrealvalue starttime vsize rss rsslim startcode endcode startstack
            #   kstkesp kstkeip signal blocked sigignore sigcatch wchan nswap cnswap
            #   exit_signal processor rt_priority policy delayacct_blkio_ticks
            #   guest_time cguest_time start_data end_data start_brk arg_start
            #   arg_end env_start env_end exit_code
            mp.addtag('pid', int(items[0]))
            mp.addtag('comm', items[1].strip('()'))
            mp.addfield('minflt', int(items[9]))
            mp.addfield('cminflt', int(items[10]))
            mp.addfield('majflt', int(items[11]))
            mp.addfield('cmajflt', int(items[12]))
            mp.addfield('utime', int(items[13]))
            mp.addfield('stime', int(items[14]))
            mp.addfield('cutime', int(items[15]))
            mp.addfield('cstime', int(items[16]))
            mp.addfield('priority', int(items[17]))
            mp.addfield('nice', int(items[18]))
            mp.addfield('vsize', int(items[22]))
            mp.addfield('rss', int(items[23]))
            mp.addfield('rt_priority', int(items[39]))
            mp.addfield('delayacct_blkio_ticks', int(items[41]))
        return([mp])

    def _readSlabinfo(self, cap):
        mpList = []
        MPClass = self.getMPClass(cap)
        tStamp = datetime.utcnow()  # Use single timestamp for this entire measurement
        try:
            fetchOut = self._fetchData(cap)
        except (UnexpectedUseError, MissingDataSourceError, MeasureMismatchError) as e:
            logging.warning(e.msg)
        else:
            lines = fetchOut.splitlines()
            # First line has version - we only support 2.1
            try:
                v = lines.pop(0).split(':')[1].strip()
            except IndexError:
                v = '(unknown)'
            if v == '2.1':
                # Second line lists fields (so we can discard)
                # name <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> \
                #  : tunables <limit> <batchcount> <sharedfactor> \
                #  : slabdata <active_slabs> <num_slabs> <sharedavail>
                line = lines.pop(0)
                for line in lines:
                    items = line.split()
                    mp = MPClass()
                    mp.setpoint(tStamp)
                    mp.addtag('name', items[0])
                    mp.addfield('active_objs', int(items[1]))
                    mp.addfield('num_objs', int(items[2]))
                    mp.addfield('objsize', int(items[3]))
                    mp.addfield('objperslab', int(items[4]))
                    mp.addfield('pagesperslab', int(items[5]))
                    mp.addfield('limit', int(items[8]))
                    mp.addfield('batchcount', int(items[9]))
                    mp.addfield('sharedfactor', int(items[10]))
                    mp.addfield('active_slabs', int(items[13]))
                    mp.addfield('num_slabs', int(items[14]))
                    mp.addfield('sharedavail', int(items[15]))
                    mpList.append(mp)
            else:
                logging.warning('Unrecognized /proc/slabinfo, version {}'.format(v))
        return(mpList)

#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Data source classes
##

class DataSource(object):
    """ Base class for all data sources """

    def __init__(self, cap):
        return

    def getstats(self):
        raise NotImplementedError()


class UBNTHALSource(DataSource):
    """ Class for data obtained via external executable 'ubnt-hal' """

    def __init__(self, cap):
        super(UBNTHALSource, self).__init__(cap)
        try:
            self.cmd = [BIN_UBNTHAL, CMD_HAL[cap]]
        except KeyError:
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            msg = '{}.{}: Unexpected attempt to use improperly-defined capability: \'{}\''.format(
                cls, func, cap)
            raise UnexpectedUseError(msg)

    def getstats(self):
        cmdOut = ''
        logging.debug("About to exec '{}'".format(' '.join(self.cmd)))
        try:
            cmdOut = subprocess.check_output(self.cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            logging.warning("Failed '{}' with return code {}: {}".format(
                ' '.join(e.cmd), e.returncode, e.output))
        except (IOError, OSError) as e:
            logging.warning("Failed to excecute '{}': [Errno {}] {}".format(
                ' '.join(e.cmd), e.errno, e.strerror))
        return(cmdOut)


class IPtableSource(DataSource):
    """ Class for data obtained via 'python-iptables' module """

    def __init__(self, cap):
        super(IPtableSource, self).__init__(cap)
        self.tableList = {
            PROTO_IPv4: [iptc.Table.FILTER, iptc.Table.MANGLE, iptc.Table.NAT],
            PROTO_IPv6: [iptc.Table6.FILTER, iptc.Table6.MANGLE]
        }
        self.iptable = {
            PROTO_IPv4: {k: None for k in self.tableList[PROTO_IPv4]},
            PROTO_IPv6: {k: None for k in self.tableList[PROTO_IPv6]}
        }
        self.stats = {}

    def _resetstats(self, proto, table):
        if proto not in self.stats:
            self.stats[proto] = {}
        self.stats[proto][table] = {}

    def _addStats(self, proto, table, chains, tstamp):
        self.stats[proto][table]['tStamp'] = tstamp
        self.stats[proto][table]['chains'] = chains

    def _extractStats(self, proto, table):
        """ Extract raw stats from iptables internal metrics """
        try:
            if self.iptable[proto][table]:
                logging.debug('Refreshing iptables v{} table \'{}\''.format(proto, table))
                self.iptable[proto][table].refresh()
            else:
                logging.debug('Fetching iptables v{} table \'{}\''.format(proto, table))
                if proto == PROTO_IPv4:
                    self.iptable[proto][table] = iptc.Table(table)
                else:
                    self.iptable[proto][table] = iptc.Table6(table)
        except KeyError:
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            msg = '{}.{}: Unknown iptables v{} table name passed: \'{}\''.format(
                cls, func, proto, table)
            raise UnexpectedTableError(msg)
        _tstmp = datetime.utcnow()
        self._resetstats(proto, table)
        chainList = {}
        for c in self.iptable[proto][table].chains:
            rstats = {}
            for r in c.rules:
                if r.target.name == 'LOG':
                    continue
                (_p, _b) = r.get_counters()
                for m in r.matches:
                    if m.name == 'comment':
                        if m.comment not in rstats:
                            rstats[m.comment] = {'pkts': _p, 'bytes': _b}
                        else:
                            rstats[m.comment]['pkts'] += _p
                            rstats[m.comment]['bytes'] += _b
            if rstats:
                chainList[c.name] = rstats
        self._addStats(proto, table, chainList, _tstmp)

    def getstats(self):
        for p in LIST_PROTO_IP:
            for t in self.tableList[p]:
                self._extractStats(p, t)
        return(self.stats)


class ProcFSSource(DataSource):
    """ Class for data obtained via '/proc' """

    def __init__(self, cap):
        super(ProcFSSource, self).__init__(cap)
        self.cap = cap
        try:
            self.path = PROC_PATH[cap]
        except KeyError:
            cls = type(self).__name__
            func = sys._getframe(1).f_code.co_name
            msg = '{}.{}: Unexpected attempt to use improperly-defined capability: \'{}\''.format(
                cls, func, cap)
            raise UnexpectedUseError(msg)

    def _readProcFile(self):
        logging.debug("About to read '{}'".format(self.path))
        try:
            with open(self.path, 'r') as f:
                lines = f.read()
        except (IOError, OSError) as e:
            logging.warning("Failed to open/read '{}': [Errno {}] {}".format(
                self.path, e.errno, e.strerror))
        return(lines)

    def _readProcNF(self):
        lines = ''
        for fn in LIST_FN_CONNTRACK:
            fpath = os.path.join(self.path, fn)
            logging.debug("About to read '{}'".format(fpath))
            try:
                with open(fpath, 'r') as f:
                    lines='{}{}:{}'.format(lines, fn, f.readline())
            except (IOError, OSError) as e:
                logging.warning("Failed to open/read '{}': [Errno {}] {}".format(
                    fpath, e.errno, e.strerror))
        return(lines)

    def getstats(self):
        if self.cap == CAP_CONNTRACK:
            return(self._readProcNF())
        else:
            return(self._readProcFile())

#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# Measurement classes
##

class MeasurePoint(object):
    """ Base class for all measurements, ready for publication to time-series database """

    def __init__(self):
        self._resettags()
        self._resetfields()

    def _resettags(self):
        self.tags = {}

    def _resetfields(self):
        self.fields = {}

    def _stamptime(self):
        self.tstamp = datetime.utcnow()

    def settimestamp(self, t):
        self.tstamp = t

    def setpoint(self, t):
        self.addtag('host', gethostname())
        self.settimestamp(t)

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
        self.measurement = CAP_FANTACH


class FanControl(MeasurePoint):
    """ Fan control time series measurement """

    def __init__(self):
        super(FanControl, self).__init__()
        self.measurement = CAP_FANCTRL


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


class IPtables(MeasurePoint):
    """ IPtables time series measurement """

    def __init__(self):
        super(IPtables, self).__init__()
        self.measurement = CAP_IPTABLES


class ProcMemInfo(MeasurePoint):
    """ /proc/meminfo time series measurement """

    def __init__(self):
        super(ProcMemInfo, self).__init__()
        self.measurement = CAP_MEMINFO


class ProcVMStat(MeasurePoint):
    """ /proc/vmstat time series measurement """

    def __init__(self):
        super(ProcVMStat, self).__init__()
        self.measurement = CAP_VMSTAT


class ProcCavStat(MeasurePoint):
    """ /proc/cavium/stats time series measurement """

    def __init__(self):
        super(ProcCavStat, self).__init__()
        self.measurement = CAP_CAVSTAT


class ProcConntrack(MeasurePoint):
    """ /proc/sys/net/netfilter time series measurement """

    def __init__(self):
        super(ProcConntrack, self).__init__()
        self.measurement = CAP_CONNTRACK


class ProcEntropyAvail(MeasurePoint):
    """ /proc/sys/kernel/random/entropy_avail time series measurement """

    def __init__(self):
        super(ProcEntropyAvail, self).__init__()
        self.measurement = CAP_ENTROPY


class ProcInterrupts(MeasurePoint):
    """ /proc/interrupts time series measurement """

    def __init__(self):
        super(ProcInterrupts, self).__init__()
        self.measurement = CAP_INTERRUPTS


class ProcSoftIRQs(MeasurePoint):
    """ /proc/softirqs time series measurement """

    def __init__(self):
        super(ProcSoftIRQs, self).__init__()
        self.measurement = CAP_SOFTIRQS


class ProcSelfStats(MeasurePoint):
    """ /proc/self/stats time series measurement """

    def __init__(self):
        super(ProcSelfStats, self).__init__()
        self.measurement = CAP_SELFSTAT


class ProcSlabinfo(MeasurePoint):
    """ /proc/slabinfo time series measurement """

    def __init__(self):
        super(ProcSlabinfo, self).__init__()
        self.measurement = CAP_SLABINFO

#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

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

#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

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

def handleSignal(sig, stack):
    """ Generically handle some basic signals to facilitate cleanup """
    _sigList={
        signal.SIGQUIT: "Quit ",
        signal.SIGTERM: "Terminate ",
        signal.SIGABRT: "Abort "
    }
    logging.error("Caught {}signal [{}]".format(_sigList.get(sig,None),sig))
    sys.exit(0)

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

def doCycle(monDev, dbC):
    """ Process one full monitor cycle """
    for c in monDev.listCap():
        for p in monDev.read(c):
            logging.debug('Measurement: {}'.format(p.getRecInflux()))
            dbC.queuePoint(p.getRecJSON())
    dbC.publish()


def main():
    """ This is where it all begins """
    initLogging()
    logging.info('Starting')
    sys.excepthook = handleException
    signal.signal(signal.SIGQUIT, handleSignal)
    signal.signal(signal.SIGTERM, handleSignal)
    signal.signal(signal.SIGABRT, handleSignal)
    detach = DEF_DAEMON
    monDev = EdgeRouter()
    if len(monDev.listCap()) == 0:
        raise NothingToDo('No monitorable entities found')
    if detach:
        daemonize(workdir=DEF_DIR_WORK, umask=DEF_UMASK)

    with PidFileLock():
        try:
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
                logging.debug('End cycle [duration {}]'.format(tDiff))
        except KeyboardInterrupt:
            logging.info('Caught Interrupt [SIGINT]')
        except SystemExit as e:
            if e.code:
                raise
        finally:
            logging.info('Exiting')

    # Should never reach here
    logging.info('Ending (unexpected)')

#
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
##
# And away we go. . .
##
if __name__ == '__main__':
    main()
