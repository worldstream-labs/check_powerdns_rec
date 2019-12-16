![GitHub release](https://img.shields.io/github/release/worldstream-labs/check_powerdns_rec.svg) 
![GitHub](https://img.shields.io/github/license/worldstream-labs/check_powerdns_rec.svg?color=blue) 
![python 2](https://img.shields.io/badge/python-2-blue.svg)

# PowerDNS Recursive Resolver check

Icinga/Nagios plugin, interned to check PowerDNS Recursor status using rec_control.
A non-zero exit code is generated if the numbers of DNS queries per seconds exceeds
warning/critical

## Installation and requirements

*   Python 2.7
*   [rec_control](https://doc.powerdns.com/recursor/manpages/rec_control.1.html)  
    rec_control is included in the PowerDNS package. It is used to send commands to a running PowerDNS nameserver.
*   [monitoring-plugins](https://github.com/monitoring-plugins/monitoring-plugins)  
    On debian-based systems you need the package `nagios-plugins` or the package `monitoring-plugins`


## Usage
	usage: check_powerdns_rec.py [-h] [-A API_HOST | -T | -S SOCKET_DIR]
                             [-P API_PORT] [-k API_KEY] [-n CONFIG_NAME]
                             [-w WARNING] [-c CRITICAL] [-s SCRATCH] [-p]
                             [--skipsecurity] [-V]


	-h, --help            show this help message and exit
	-A API_HOST, --api-host API_HOST
	                      PowerDNS API host (do not combine with --socket-dir or
	                      --test)
	-T, --test            Test case; Use fake data (do not combine with --api-
	                      host or --socket-dir)
	-S SOCKET_DIR, --socket-dir SOCKET_DIR
	                      PDNS Control tool Socket directory (do not combine
	                      with --socket-dir or --test)
	-P API_PORT, --api-port API_PORT
	                      PowerDNS API port (default 8082)
	-k API_KEY, --api-key API_KEY
	                      PowerDNS API key
	-n CONFIG_NAME, --config-name CONFIG_NAME
	                      Name of PowerDNS virtual configuration
	-w WARNING, --warning WARNING
	                      Warning threshold (Queries/s)
	-c CRITICAL, --critical CRITICAL
	                      Critical threshold (Queries/s)
	-s SCRATCH, --scratch SCRATCH
	                      Scratch / temp base directory. Must exist. (default: /tmp)
	-p, --perfdata        Print performance data, (default: off)
	--skipsecurity        Skip PowerDNS security status, (default: off)
	-V, --version         show program's version number and exit


## License

PowerDNS Authoritative check is licensed under the terms of the GNU
General Public License Version 3.
