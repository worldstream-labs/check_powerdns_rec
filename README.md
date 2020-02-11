![GitHub release](https://img.shields.io/github/release/worldstream-labs/check_powerdns_rec.svg) 
![GitHub](https://img.shields.io/github/license/worldstream-labs/check_powerdns_rec.svg?color=blue) 
![python 2](https://img.shields.io/badge/python-2.7-blue.svg)
![python 3](https://img.shields.io/badge/python-3-blue.svg)

# PowerDNS Recursive Resolver check

Icinga/Nagios plugin, interned to check PowerDNS Recursor status using rec_control.
A non-zero exit code is generated if the numbers of DNS queries per seconds exceeds
warning/critical

## Installation and requirements

*   Python 2.7 or Python 3.x
*   [rec_control](https://doc.powerdns.com/recursor/manpages/rec_control.1.html)  
    rec_control is included in the PowerDNS package. It is used to send commands to a running PowerDNS nameserver.
*   [monitoring-plugins](https://github.com/monitoring-plugins/monitoring-plugins)  
    On debian-based systems you need the package `nagios-plugins` or the package `monitoring-plugins`


## Usage

For example: check the statistics using the API running on 127.0.0.1:8081 using key "myapikey".
```sh
./check_powerdns_rec.py -A 127.0.0.1 -P 8081 -k myapikey -p
```
Use --help argument for a description of all arguments. 
```sh
./check_powerdns_rec.py --help
```

## License

PowerDNS Authoritative check is licensed under the terms of the GNU
General Public License Version 3.
