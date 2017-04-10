# Monitoring/logging utilities
Miscellaneous utilities and tools for collection, manipulation, and logging of arbitrary metrics

#### LICENSE
The standard license under which these tools, utilities, and files here are released.

#### README.md
This file (the one being read).

### <u>Contents</u>
A list of tools and utilities provided here.

#### stats-er.py
Periodic monitoring of UBNT EdgeRouter metrics not otherwise available via SNMP.  Supports publishing to remote InfluxDB and/or writing to local log files.

Currently this script will collect temperatures, fan speeds, and power usage from those units that include such sensors.  To determine if a given EdgeRouter supports these use `show hardware temperature`, `show hardware fan`, and `show hardware power` from a shell prompt on the ER.

The script as-configured will not actually perform any logging of data.  At minimum one of the two options for logging should be enabled by editing the configuration at the beginning of the script.  Additionally details such as database host, etc should be configured as appropriate.

This is a quick interim tool created for a specific use but may be useful to others.


##### Note  
Publishing to InfluxDB requires additional support libraries that are not part of the EdgeOS distribution.  These are easily obtained however.

The primary dependency is on [InfluxDB-Python](https://github.com/influxdata/influxdb-python), which in turn has a few dependencies.  

The current EdgeOS distribution is based upon Debian Wheezy, which does not itself include influxdb-python.  All of the required dependencies are, however, platform-independent.  The quickest solution would be to copy the few dependent python libraries from a standard Debian Jessie distribution:  
1.  On Debian 8 (Jessie) OS:  
    1.  `sudo apt install python-influxdb`  This will ensure all dependencies are included.
    2.  `cd /usr/lib/python2.7/dist-packages`
    3.  `tar zcf /tmp/pdepend.tgz chardet pytz six.py six.pyc urllib3 dateutil influxdb requests`
    4.  `scp /tmp/pdepend.tgz <edgerouter>:/tmp`
2.  On _&lt;edgerouter&gt;_:
    1.  `mkdir /config/scripts/stats-er`
    2.  `cd /config/scripts/stats-er`
    3.  `tar xpf /tmp/pdepend.tgz`
3.  Copy the `stats-er.py` into `/config/scripts/stats-er` and edit appropriately.  The script will find the dependent libraries from within the directory where it is located.

#### ubnt-edgerouter-extend-dashboard.json
Sample [Grafana](https://grafana.com) dashboard for use with the above `stats-er.py` publishing to InfluxDB.

To use, configure the database used by `stats-er.py` as a new datasource in your local Grafana instance, then import the .json into that same instance.
