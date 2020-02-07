#!/usr/bin/env python
# encoding: utf-8

# Remi Frenay, WorldStream B.V., 2019
# <rf@worldstream.nl>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
################################################################################

__author__ = 'Remi Frenay <rf@worldstream.nl>'
__version__ = '1.1.0'
__plugin_name__ = 'check_powerdns_rec.py'

import os
import pickle
import re
import subprocess
import requests
import json
import sys
import tempfile
import time

pdns_tool = 'rec_control'

querylist = ['questions']
avglist = querylist + ['nxdomain-answers', 'noerror-answers', 'servfail-answers-answers', 'recursing-questions',
                       'recursing-answers', 'answers-slow', 'answers0-1', 'answers1-10', 'answers10-100',
                       'answers100-1000', 'over-capacity-drops', 'policy-drops', 'cache-hits', 'cache-misses',
                       'packetcache-hits', 'packetcache-misses']
watchlist = avglist + ['qa-latency', 'security-status']




class MyPdnsError(Exception):
    pass



# noinspection PyTypeChecker
def parse_args():
    # Build argument list
    try:
        import argparse
    except ImportError:
        print 'Error importing library python-argparse'
        sys.exit(MStatus().UNKNOWN)

    parser = argparse.ArgumentParser(
        prog=__plugin_name__,
        description='Icinga/Nagios plugin, interned to check PowerDNS status using either rec_control or the API.'
                    'rec_control is the default interface to obtain statistisc'
                    'A non-zero exit code is generated, if the numbers of DNS queries per seconds exceeds'
                    ' warning/critical values. Additionally the plugin checks for the security-status of PowerDNS. ',
        epilog='This program is free software: you can redistribute it and/or modify '
               'it under the terms of the GNU General Public License as published by '
               'the Free Software Foundation, either version 3 of the License, or '
               'at your option) any later version. Author: ' + __author__)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-A', '--api-host', help='PowerDNS API host (do not combine with --socket-dir or --test)', type=str)
    group.add_argument('-T', '--test', help='Test case; Use fake data (do not combine with --api-host or --socket-dir)',
                        action='store_true')
    group.add_argument('-S', '--socket-dir', help='PDNS Control tool Socket directory (do not combine with --api-host or --test)', type=str, default='')

    parser.add_argument('-P', '--api-port', help='PowerDNS API port (default 8082)', type=int, default=8082)
    parser.add_argument('-k', '--api-key', help='PowerDNS API key', type=str, default='')
    parser.add_argument('-n', '--config-name', help='Name of PowerDNS virtual configuration', type=str, default='')
    parser.add_argument('-w', '--warning', help='Warning threshold (Queries/s)', type=int, default=0)
    parser.add_argument('-c', '--critical', help='Critical threshold (Queries/s)', type=int, default=0)
    parser.add_argument('-s', '--scratch', help='Scratch / temp base directory. Must exist. (Default value will be determined for by gettempdir function)', type=str,
                        default='')
    parser.add_argument('-p', '--perfdata', help='Print performance data, (default: off)', action='store_true')
    parser.add_argument('--skipsecurity', help='Skip PowerDNS security status, (default: off)', action='store_true')

    parser.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
    args = parser.parse_args()
    return args

class MStatus:
    """Monitoring status enum"""

    def __init__(self):
        self.OK = 0
        self.WARNING = 1
        self.CRITICAL = 2
        self.UNKNOWN = 3

class Monitoring:
    """"Monitoring"""

    def __init__(self):
        self.status = MStatus().UNKNOWN
        self.message = "Unknown Status"
        self.perfdata = []

    def set_status(self, _status):
        if _status == MStatus().UNKNOWN:
            return
        if self.status == MStatus().CRITICAL:
            return
        if _status == MStatus().CRITICAL:
            self.status = _status
            return
        if self.status == MStatus().WARNING:
            return
        self.status = _status

    def set_message(self, _message):
        self.message = _message

    def set_perfdata(self, _label, _value, _warning, _critical):
        self.perfdata.append([_label, _value, _warning, _critical])

    def report(self):
        if self.status == MStatus().OK:
            code = "OK"
        elif self.status == MStatus().WARNING:
            code = "WARNING"
        elif self.status == MStatus().CRITICAL:
            code = "CRITICAL"
        else:
            code = "UNKNOWN"
        output = code + ' - ' + self.message
        if len(self.perfdata) > 0:
            output += '|'
            for measurement in self.perfdata:
                output += (" '%s'=%d;%d;%d;0;" % (measurement[0], measurement[1], measurement[2], measurement[3]))
        print(output)
        sys.exit(self.status)


class PowerDnsApi:
    """PowerDNS API"""

    def __init__(self, api_host, api_port, api_key):
        self.api_host = api_host
        self.api_port = api_port
        self.api_key = api_key

    def statistics(self):
        return self.execute('/api/v1/servers/localhost/statistics')

    def execute(self, path):
        """Connect with PowerDNS API to execute request"""

        url = "http://%s:%d%s" % (self.api_host, self.api_port, path)
        headers = {'X-API-Key': self.api_key}
        try:
            result = requests.get(url, headers=headers, verify=False)
            if result.content == "Unauthorized":
                raise MyPdnsError("Incorrect API Key!")
            if result.status_code != 200:
                raise MyPdnsError("API unexpected result code %d" % result.status_code)
            object = json.loads(result.content)
            return object
        except requests.exceptions.ConnectionError:
            raise MyPdnsError("Error connecting to %s" % url)

class PowerDnsCtrlTool:
    """PowerDNS Control Tool"""

    def __init__(self, socket_dir, config_name):
        self.socket_dir = socket_dir
        self.config_name = config_name

    def get_all(self):
        return self.execute('get-all')

    def execute(self, cmd):
        """Connect with PowerDNS Control tool to execute request"""

        try:
            cli = [pdns_tool]
            if self.socket_dir:
                cli.append('--socket-dir=%s' % self.socket_dir)
            if self.config_name != '':
                cli.append('--config-name=%s' % self.config_name)
            cli.append(cmd)

            MyOut = subprocess.Popen(cli, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stdout, stderr = MyOut.communicate()
            if MyOut.returncode != 0:
                raise MyPdnsError(stdout)
            return stdout
        except OSError:
            raise MyPdnsError("Control command '%s' not found." % pdns_tool)


def get_fname(_path_base, _config):
    if _path_base == '':
        _path_base = tempfile.gettempdir()
    # returns cache file name
    if _config == '':
        return os.path.join(_path_base, 'monitor-pdns-rec')
    else:
        return os.path.join(_path_base, 'monitor-pdns-rec-' + _config)


def load_measurement(_filename):
    try:
        fd = open(_filename, 'rb')
        _data_old = pickle.load(fd)
        fd.close()
        return _data_old
    except IOError:
        return dict()


def save_measurement(_filename, _data_new):
    fd = open(_filename, 'wb')
    pickle.dump(_data_new, fd)
    fd.close()


def parse_pdns(_stdout):
    _new_data = dict()

    for val in _stdout.splitlines():
        m = re.match(r"^([a-z0-9\-]+)\s+(\d+)$", val)
        if m:
            if m.group(1) in watchlist:
                _new_data[m.group(1)] = int(m.group(2))
    return _new_data

def fake_statistics():
    stdout = "all-outqueries\t0\nanswers-slow\t0\nanswers0-1\t0\nanswers1-10\t0\nanswers10-100\t0\n" \
             "answers100-1000\t0\ncache-entries\t0\ncache-hits\t0\ncache-misses\t0\ncase-mismatches\t0\n" \
             "chain-resends\t0\nclient-parse-errors\t0\nconcurrent-queries\t0\ndlg-only-drops\t0\n" \
             "dont-outqueries\t0\nedns-ping-matches\t0\nedns-ping-mismatches\t0\nfailed-host-entries\t0\n" \
             "ipv6-outqueries\t0\nipv6-questions\t0\nmalloc-bytes\t0\nmax-mthread-stack\t0\nnegcache-entries\t0\n" \
             "no-packet-error\t0\nnoedns-outqueries\t0\nnoerror-answers\t0\nnoping-outqueries\t0\n" \
             "nsset-invalidations\t0\nnsspeeds-entries\t0\nnxdomain-answers\t0\noutgoing-timeouts\t0\n" \
             "over-capacity-drops\t0\npacketcache-entries\t0\npacketcache-hits\t0\npacketcache-misses\t0\n" \
             "policy-drops\t0\nqa-latency\t0\nquestions\t0\nresource-limits\t0\nserver-parse-errors\t0\n" \
             "servfail-answers\t0\nspoof-prevents\t0\nsys-msec\t0\ntcp-client-overflow\t0\ntcp-clients\t0\n" \
             "tcp-outqueries\t0\ntcp-questions\t0\nthrottle-entries\t0\nthrottled-out\t0\n" \
             "throttled-outqueries\t0\nunauthorized-tcp\t0\nunauthorized-udp\t0\nunexpected-packets\t0\n" \
             "unreachables\t0\nuptime\t0\nuser-msec\t0\nsecurity-status\t1\n"

    _data_new = parse_pdns(stdout)
    _data_new['epoch'] = int(time.time())

    _data_old = _data_new.copy()
    _data_old['epoch'] -= 1
    return _data_old, _data_new

def parse2_pdns(_stdout):
    _new_data = dict()

    for val in _stdout:
        if ('type' in val) and ('name' in val) and ('value' in val) and (val['type'] == 'StatisticItem') and (val['name'] in watchlist):
            _new_data[val['name']] = int(val['value'])
    return _new_data


def calc_avgps(_data_old, _data_new):
    _data_avg = dict()
    _queries = 0

    try:
        elapsed = _data_new['epoch'] - _data_old['epoch']
        for _label, _value in _data_old.items():
            if (_label in _data_new) and (_label in avglist):
                delta = _data_new[_label] - _value
                _data_avg[_label] = delta / elapsed
                if delta < 0:
                    return dict(), 0
                if _label in querylist:
                    _queries += delta
        _queries /= elapsed
        return _data_avg, _queries
    except KeyError:
        return dict(), 0
    except ZeroDivisionError:
        return dict(), 0


# main
if __name__ == '__main__':

    monitor = Monitoring()

    try:
        args = parse_args()

        if args.test:
            data_old, data_new = fake_statistics()
        else:
            if args.api_host:
                pdns = PowerDnsApi(args.api_host, args.api_port, args.api_key)
                result = pdns.statistics()
                data_new = parse2_pdns(result)
            else:
                pdns = PowerDnsCtrlTool(args.socket_dir, args.config_name)
                result = pdns.get_all()
                data_new = parse_pdns(result)
            # noinspection PyUnboundLocalVariable
            data_new['epoch'] = int(time.time())
            filename = get_fname(args.scratch, args.config_name)
            data_old = load_measurement(filename)
            if len(data_new) > 1:
                save_measurement(filename, data_new)
        (data_avg, queries) = calc_avgps(data_old, data_new)

        if ('security-status' in data_new) and (args.skipsecurity == 0):
            if data_new['security-status'] == 0:
                monitor.set_status(MStatus().CRITICAL)
                security = 'NXDOMAIN or resolution failure.'
            elif data_new['security-status'] == 1:
                monitor.set_status(MStatus().OK)
                security = 'PowerDNS running.'
            elif data_new['security-status'] == 2:
                monitor.set_status(MStatus().WARNING)
                security = 'PowerDNS upgrade recommended.'
            elif data_new['security-status'] == 3:
                monitor.set_status(MStatus().CRITICAL)
                security = 'PowerDNS upgrade mandatory.'
            else:
                monitor.set_status(MStatus().CRITICAL)
                security = "PowerDNS unexpected security-status %d." % data_new['security-status']
        else:
            security = ''
        if args.warning and (queries >= args.warning):
            monitor.set_status(MStatus().WARNING)
        if args.critical and (queries >= args.critical):
            monitor.set_status(MStatus().CRITICAL)

        monitor.set_status(MStatus().OK)
        monitor.set_message("%s Queries: %d/s." % (security, queries))
        if args.perfdata:
            for label, value in sorted(data_avg.items()):
                monitor.set_perfdata(label, value, args.warning, args.critical)
    except MyPdnsError as e:
        monitor.set_message(str(e))
    monitor.report()
