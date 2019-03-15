#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019 Fortinet, Inc.
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
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_log_memory_filter
short_description: Filters for memory buffer in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify log_memory feature and filter category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.2
version_added: "2.8"
author:
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Requires fortiosapi library developed by Fortinet
    - Run as a local_action in your playbook
requirements:
    - fortiosapi>=0.9.8
options:
    host:
       description:
            - FortiOS or FortiGate ip address.
       required: true
    username:
        description:
            - FortiOS or FortiGate username.
        required: true
    password:
        description:
            - FortiOS or FortiGate password.
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS
              protocol
        type: bool
        default: true
    log_memory_filter:
        description:
            - Filters for memory buffer.
        default: null
        suboptions:
            admin:
                description:
                    - Enable/disable admin login/logout logging.
                choices:
                    - enable
                    - disable
            anomaly:
                description:
                    - Enable/disable anomaly logging.
                choices:
                    - enable
                    - disable
            auth:
                description:
                    - Enable/disable firewall authentication logging.
                choices:
                    - enable
                    - disable
            cpu-memory-usage:
                description:
                    - Enable/disable CPU & memory usage logging every 5 minutes.
                choices:
                    - enable
                    - disable
            dhcp:
                description:
                    - Enable/disable DHCP service messages logging.
                choices:
                    - enable
                    - disable
            dns:
                description:
                    - Enable/disable detailed DNS event logging.
                choices:
                    - enable
                    - disable
            event:
                description:
                    - Enable/disable event logging.
                choices:
                    - enable
                    - disable
            filter:
                description:
                    - Memory log filter.
            filter-type:
                description:
                    - Include/exclude logs that match the filter.
                choices:
                    - include
                    - exclude
            forward-traffic:
                description:
                    - Enable/disable forward traffic logging.
                choices:
                    - enable
                    - disable
            gtp:
                description:
                    - Enable/disable GTP messages logging.
                choices:
                    - enable
                    - disable
            ha:
                description:
                    - Enable/disable HA logging.
                choices:
                    - enable
                    - disable
            ipsec:
                description:
                    - Enable/disable IPsec negotiation messages logging.
                choices:
                    - enable
                    - disable
            ldb-monitor:
                description:
                    - Enable/disable VIP real server health monitoring logging.
                choices:
                    - enable
                    - disable
            local-traffic:
                description:
                    - Enable/disable local in or out traffic logging.
                choices:
                    - enable
                    - disable
            multicast-traffic:
                description:
                    - Enable/disable multicast traffic logging.
                choices:
                    - enable
                    - disable
            netscan-discovery:
                description:
                    - Enable/disable netscan discovery event logging.
                choices:
            netscan-vulnerability:
                description:
                    - Enable/disable netscan vulnerability event logging.
                choices:
            pattern:
                description:
                    - Enable/disable pattern update logging.
                choices:
                    - enable
                    - disable
            ppp:
                description:
                    - Enable/disable L2TP/PPTP/PPPoE logging.
                choices:
                    - enable
                    - disable
            radius:
                description:
                    - Enable/disable RADIUS messages logging.
                choices:
                    - enable
                    - disable
            severity:
                description:
                    - Log every message above and including this severity level.
                choices:
                    - emergency
                    - alert
                    - critical
                    - error
                    - warning
                    - notification
                    - information
                    - debug
            sniffer-traffic:
                description:
                    - Enable/disable sniffer traffic logging.
                choices:
                    - enable
                    - disable
            ssh:
                description:
                    - Enable/disable SSH logging.
                choices:
                    - enable
                    - disable
            sslvpn-log-adm:
                description:
                    - Enable/disable SSL administrator login logging.
                choices:
                    - enable
                    - disable
            sslvpn-log-auth:
                description:
                    - Enable/disable SSL user authentication logging.
                choices:
                    - enable
                    - disable
            sslvpn-log-session:
                description:
                    - Enable/disable SSL session logging.
                choices:
                    - enable
                    - disable
            system:
                description:
                    - Enable/disable system activity logging.
                choices:
                    - enable
                    - disable
            vip-ssl:
                description:
                    - Enable/disable VIP SSL logging.
                choices:
                    - enable
                    - disable
            voip:
                description:
                    - Enable/disable VoIP logging.
                choices:
                    - enable
                    - disable
            wan-opt:
                description:
                    - Enable/disable WAN optimization event logging.
                choices:
                    - enable
                    - disable
            wireless-activity:
                description:
                    - Enable/disable wireless activity event logging.
                choices:
                    - enable
                    - disable
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Filters for memory buffer.
    fortios_log_memory_filter:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      log_memory_filter:
        admin: "enable"
        anomaly: "enable"
        auth: "enable"
        cpu-memory-usage: "enable"
        dhcp: "enable"
        dns: "enable"
        event: "enable"
        filter: "<your_own_value>"
        filter-type: "include"
        forward-traffic: "enable"
        gtp: "enable"
        ha: "enable"
        ipsec: "enable"
        ldb-monitor: "enable"
        local-traffic: "enable"
        multicast-traffic: "enable"
        netscan-discovery: "<your_own_value>"
        netscan-vulnerability: "<your_own_value>"
        pattern: "enable"
        ppp: "enable"
        radius: "enable"
        severity: "emergency"
        sniffer-traffic: "enable"
        ssh: "enable"
        sslvpn-log-adm: "enable"
        sslvpn-log-auth: "enable"
        sslvpn-log-session: "enable"
        system: "enable"
        vip-ssl: "enable"
        voip: "enable"
        wan-opt: "enable"
        wireless-activity: "enable"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

'''

from ansible.module_utils.basic import AnsibleModule


def login(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password)


def filter_log_memory_filter_data(json):
    option_list = ['admin', 'anomaly', 'auth',
                   'cpu-memory-usage', 'dhcp', 'dns',
                   'event', 'filter', 'filter-type',
                   'forward-traffic', 'gtp', 'ha',
                   'ipsec', 'ldb-monitor', 'local-traffic',
                   'multicast-traffic', 'netscan-discovery', 'netscan-vulnerability',
                   'pattern', 'ppp', 'radius',
                   'severity', 'sniffer-traffic', 'ssh',
                   'sslvpn-log-adm', 'sslvpn-log-auth', 'sslvpn-log-session',
                   'system', 'vip-ssl', 'voip',
                   'wan-opt', 'wireless-activity']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def log_memory_filter(data, fos):
    vdom = data['vdom']
    log_memory_filter_data = data['log_memory_filter']
    filtered_data = filter_log_memory_filter_data(log_memory_filter_data)

    return fos.set('log.memory',
                   'filter',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_log_memory(data, fos):
    login(data, fos)

    if data['log_memory_filter']:
        resp = log_memory_filter(data, fos)

    fos.logout()
    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "log_memory_filter": {
            "required": False, "type": "dict",
            "options": {
                "admin": {"required": False, "type": "str",
                          "choices": ["enable", "disable"]},
                "anomaly": {"required": False, "type": "str",
                            "choices": ["enable", "disable"]},
                "auth": {"required": False, "type": "str",
                         "choices": ["enable", "disable"]},
                "cpu-memory-usage": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "dhcp": {"required": False, "type": "str",
                         "choices": ["enable", "disable"]},
                "dns": {"required": False, "type": "str",
                        "choices": ["enable", "disable"]},
                "event": {"required": False, "type": "str",
                          "choices": ["enable", "disable"]},
                "filter": {"required": False, "type": "str"},
                "filter-type": {"required": False, "type": "str",
                                "choices": ["include", "exclude"]},
                "forward-traffic": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "gtp": {"required": False, "type": "str",
                        "choices": ["enable", "disable"]},
                "ha": {"required": False, "type": "str",
                       "choices": ["enable", "disable"]},
                "ipsec": {"required": False, "type": "str",
                          "choices": ["enable", "disable"]},
                "ldb-monitor": {"required": False, "type": "str",
                                "choices": ["enable", "disable"]},
                "local-traffic": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "multicast-traffic": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]},
                "netscan-discovery": {"required": False, "type": "str",
                                      "choices": []},
                "netscan-vulnerability": {"required": False, "type": "str",
                                          "choices": []},
                "pattern": {"required": False, "type": "str",
                            "choices": ["enable", "disable"]},
                "ppp": {"required": False, "type": "str",
                        "choices": ["enable", "disable"]},
                "radius": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "severity": {"required": False, "type": "str",
                             "choices": ["emergency", "alert", "critical",
                                         "error", "warning", "notification",
                                         "information", "debug"]},
                "sniffer-traffic": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "ssh": {"required": False, "type": "str",
                        "choices": ["enable", "disable"]},
                "sslvpn-log-adm": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "sslvpn-log-auth": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "sslvpn-log-session": {"required": False, "type": "str",
                                       "choices": ["enable", "disable"]},
                "system": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "vip-ssl": {"required": False, "type": "str",
                            "choices": ["enable", "disable"]},
                "voip": {"required": False, "type": "str",
                         "choices": ["enable", "disable"]},
                "wan-opt": {"required": False, "type": "str",
                            "choices": ["enable", "disable"]},
                "wireless-activity": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)
    try:
        from fortiosapi import FortiOSAPI
    except ImportError:
        module.fail_json(msg="fortiosapi module is required")

    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_log_memory(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
