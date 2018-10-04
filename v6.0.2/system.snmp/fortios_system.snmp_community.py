#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2018 Fortinet, Inc.
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
#
# the lib use python logging can get it if the following is set in your
# Ansible config.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_system.snmp_community
short_description: SNMP community configuration.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure system.snmp feature and community category.
      Examples includes all options and need to be adjusted to datasources before usage.
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
            - FortiOS or FortiGate ip adress.
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
        default: false
    system.snmp_community:
        description:
            - SNMP community configuration.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            events:
                description:
                    - SNMP trap events.
                choices:
                    - cpu-high
                    - mem-low
                    - log-full
                    - intf-ip
                    - vpn-tun-up
                    - vpn-tun-down
                    - ha-switch
                    - ha-hb-failure
                    - ips-signature
                    - ips-anomaly
                    - av-virus
                    - av-oversize
                    - av-pattern
                    - av-fragmented
                    - fm-if-change
                    - fm-conf-change
                    - bgp-established
                    - bgp-backward-transition
                    - ha-member-up
                    - ha-member-down
                    - ent-conf-change
                    - av-conserve
                    - av-bypass
                    - av-oversize-passed
                    - av-oversize-blocked
                    - ips-pkg-update
                    - ips-fail-open
                    - faz-disconnect
                    - wc-ap-up
                    - wc-ap-down
                    - fswctl-session-up
                    - fswctl-session-down
                    - load-balance-real-server-down
                    - device-new
                    - per-cpu-high
            hosts:
                description:
                    - Configure IPv4 SNMP managers (hosts).
                suboptions:
                    ha-direct:
                        description:
                            - Enable/disable direct management of HA cluster members.
                        choices:
                            - enable
                            - disable
                    host-type:
                        description:
                            - Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.
                        choices:
                            - any
                            - query
                            - trap
                    id:
                        description:
                            - Host entry ID.
                        required: true
                    ip:
                        description:
                            - IPv4 address of the SNMP manager (host).
                    source-ip:
                        description:
                            - Source IPv4 address for SNMP traps.
            hosts6:
                description:
                    - Configure IPv6 SNMP managers.
                suboptions:
                    ha-direct:
                        description:
                            - Enable/disable direct management of HA cluster members.
                        choices:
                            - enable
                            - disable
                    host-type:
                        description:
                            - Control whether the SNMP manager sends SNMP queries, receives SNMP traps, or both.
                        choices:
                            - any
                            - query
                            - trap
                    id:
                        description:
                            - Host6 entry ID.
                        required: true
                    ipv6:
                        description:
                            - SNMP manager IPv6 address prefix.
                    source-ipv6:
                        description:
                            - Source IPv6 address for SNMP traps.
            id:
                description:
                    - Community ID.
                required: true
            name:
                description:
                    - Community name.
            query-v1-port:
                description:
                    - SNMP v1 query port (default = 161).
            query-v1-status:
                description:
                    - Enable/disable SNMP v1 queries.
                choices:
                    - enable
                    - disable
            query-v2c-port:
                description:
                    - SNMP v2c query port (default = 161).
            query-v2c-status:
                description:
                    - Enable/disable SNMP v2c queries.
                choices:
                    - enable
                    - disable
            status:
                description:
                    - Enable/disable this SNMP community.
                choices:
                    - enable
                    - disable
            trap-v1-lport:
                description:
                    - SNMP v1 trap local port (default = 162).
            trap-v1-rport:
                description:
                    - SNMP v1 trap remote port (default = 162).
            trap-v1-status:
                description:
                    - Enable/disable SNMP v1 traps.
                choices:
                    - enable
                    - disable
            trap-v2c-lport:
                description:
                    - SNMP v2c trap local port (default = 162).
            trap-v2c-rport:
                description:
                    - SNMP v2c trap remote port (default = 162).
            trap-v2c-status:
                description:
                    - Enable/disable SNMP v2c traps.
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
  - name: SNMP community configuration.
    fortios_system.snmp_community:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      system.snmp_community:
        state: "present"
        events: "cpu-high"
        hosts:
         -
            ha-direct: "enable"
            host-type: "any"
            id:  "7"
            ip: "<your_own_value>"
            source-ip: "84.230.14.43"
        hosts6:
         -
            ha-direct: "enable"
            host-type: "any"
            id:  "13"
            ipv6: "<your_own_value>"
            source-ipv6: "<your_own_value>"
        id:  "16"
        name: "default_name_17"
        query-v1-port: "18"
        query-v1-status: "enable"
        query-v2c-port: "20"
        query-v2c-status: "enable"
        status: "enable"
        trap-v1-lport: "23"
        trap-v1-rport: "24"
        trap-v1-status: "enable"
        trap-v2c-lport: "26"
        trap-v2c-rport: "27"
        trap-v2c-status: "enable"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: string
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: string
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: string
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: string
  sample: "key1"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: string
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: string
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: string
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: string
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: string
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: string
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: string
  sample: "v5.6.3"

'''

from ansible.module_utils.basic import AnsibleModule

fos = None


def login(data):
    host = data['host']
    username = data['username']
    password = data['password']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password)


def filter_system.snmp_community_data(json):
    option_list = ['events', 'hosts', 'hosts6',
                   'id', 'name', 'query-v1-port',
                   'query-v1-status', 'query-v2c-port', 'query-v2c-status',
                   'status', 'trap-v1-lport', 'trap-v1-rport',
                   'trap-v1-status', 'trap-v2c-lport', 'trap-v2c-rport',
                   'trap-v2c-status']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def system.snmp_community(data, fos):
    vdom = data['vdom']
    system.snmp_community_data = data['system.snmp_community']
    filtered_data = filter_system.snmp_community_data(
        system.snmp_community_data)
    if system.snmp_community_data['state'] == "present":
        return fos.set('system.snmp',
                       'community',
                       data=filtered_data,
                       vdom=vdom)

    elif system.snmp_community_data['state'] == "absent":
        return fos.delete('system.snmp',
                          'community',
                          mkey=filtered_data['id'],
                          vdom=vdom)


def fortios_system.snmp(data, fos):
    login(data)

    methodlist = ['system.snmp_community']
    for method in methodlist:
        if data[method]:
            resp = eval(method)(data, fos)
            break

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": "False"},
        "system.snmp_community": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "events": {"required": False, "type": "str",
                           "choices": ["cpu-high", "mem-low", "log-full",
                                       "intf-ip", "vpn-tun-up", "vpn-tun-down",
                                       "ha-switch", "ha-hb-failure", "ips-signature",
                                       "ips-anomaly", "av-virus", "av-oversize",
                                       "av-pattern", "av-fragmented", "fm-if-change",
                                       "fm-conf-change", "bgp-established", "bgp-backward-transition",
                                       "ha-member-up", "ha-member-down", "ent-conf-change",
                                       "av-conserve", "av-bypass", "av-oversize-passed",
                                       "av-oversize-blocked", "ips-pkg-update", "ips-fail-open",
                                       "faz-disconnect", "wc-ap-up", "wc-ap-down",
                                       "fswctl-session-up", "fswctl-session-down", "load-balance-real-server-down",
                                       "device-new", "per-cpu-high"]},
                "hosts": {"required": False, "type": "list",
                          "options": {
                              "ha-direct": {"required": False, "type": "str",
                                            "choices": ["enable", "disable"]},
                              "host-type": {"required": False, "type": "str",
                                            "choices": ["any", "query", "trap"]},
                              "id": {"required": True, "type": "int"},
                              "ip": {"required": False, "type": "str"},
                              "source-ip": {"required": False, "type": "str"}
                          }},
                "hosts6": {"required": False, "type": "list",
                           "options": {
                               "ha-direct": {"required": False, "type": "str",
                                             "choices": ["enable", "disable"]},
                               "host-type": {"required": False, "type": "str",
                                             "choices": ["any", "query", "trap"]},
                               "id": {"required": True, "type": "int"},
                               "ipv6": {"required": False, "type": "str"},
                               "source-ipv6": {"required": False, "type": "str"}
                           }},
                "id": {"required": True, "type": "int"},
                "name": {"required": False, "type": "str"},
                "query-v1-port": {"required": False, "type": "int"},
                "query-v1-status": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "query-v2c-port": {"required": False, "type": "int"},
                "query-v2c-status": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "status": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "trap-v1-lport": {"required": False, "type": "int"},
                "trap-v1-rport": {"required": False, "type": "int"},
                "trap-v1-status": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "trap-v2c-lport": {"required": False, "type": "int"},
                "trap-v2c-rport": {"required": False, "type": "int"},
                "trap-v2c-status": {"required": False, "type": "str",
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

    global fos
    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_system.snmp(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
