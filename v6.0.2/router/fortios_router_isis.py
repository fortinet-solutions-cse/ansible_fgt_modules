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
module: fortios_router_isis
short_description: Configure IS-IS in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify router feature and isis category.
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
    router_isis:
        description:
            - Configure IS-IS.
        default: null
        suboptions:
            adjacency-check:
                description:
                    - Enable/disable adjacency check.
                choices:
                    - enable
                    - disable
            adjacency-check6:
                description:
                    - Enable/disable IPv6 adjacency check.
                choices:
                    - enable
                    - disable
            adv-passive-only:
                description:
                    - Enable/disable IS-IS advertisement of passive interfaces only.
                choices:
                    - enable
                    - disable
            adv-passive-only6:
                description:
                    - Enable/disable IPv6 IS-IS advertisement of passive interfaces only.
                choices:
                    - enable
                    - disable
            auth-keychain-l1:
                description:
                    - Authentication key-chain for level 1 PDUs. Source router.key-chain.name.
            auth-keychain-l2:
                description:
                    - Authentication key-chain for level 2 PDUs. Source router.key-chain.name.
            auth-mode-l1:
                description:
                    - Level 1 authentication mode.
                choices:
                    - password
                    - md5
            auth-mode-l2:
                description:
                    - Level 2 authentication mode.
                choices:
                    - password
                    - md5
            auth-password-l1:
                description:
                    - Authentication password for level 1 PDUs.
            auth-password-l2:
                description:
                    - Authentication password for level 2 PDUs.
            auth-sendonly-l1:
                description:
                    - Enable/disable level 1 authentication send-only.
                choices:
                    - enable
                    - disable
            auth-sendonly-l2:
                description:
                    - Enable/disable level 2 authentication send-only.
                choices:
                    - enable
                    - disable
            default-originate:
                description:
                    - Enable/disable distribution of default route information.
                choices:
                    - enable
                    - disable
            default-originate6:
                description:
                    - Enable/disable distribution of default IPv6 route information.
                choices:
                    - enable
                    - disable
            dynamic-hostname:
                description:
                    - Enable/disable dynamic hostname.
                choices:
                    - enable
                    - disable
            ignore-lsp-errors:
                description:
                    - Enable/disable ignoring of LSP errors with bad checksums.
                choices:
                    - enable
                    - disable
            is-type:
                description:
                    - IS type.
                choices:
                    - level-1-2
                    - level-1
                    - level-2-only
            isis-interface:
                description:
                    - IS-IS interface configuration.
                suboptions:
                    auth-keychain-l1:
                        description:
                            - Authentication key-chain for level 1 PDUs. Source router.key-chain.name.
                    auth-keychain-l2:
                        description:
                            - Authentication key-chain for level 2 PDUs. Source router.key-chain.name.
                    auth-mode-l1:
                        description:
                            - Level 1 authentication mode.
                        choices:
                            - md5
                            - password
                    auth-mode-l2:
                        description:
                            - Level 2 authentication mode.
                        choices:
                            - md5
                            - password
                    auth-password-l1:
                        description:
                            - Authentication password for level 1 PDUs.
                    auth-password-l2:
                        description:
                            - Authentication password for level 2 PDUs.
                    auth-send-only-l1:
                        description:
                            - Enable/disable authentication send-only for level 1 PDUs.
                        choices:
                            - enable
                            - disable
                    auth-send-only-l2:
                        description:
                            - Enable/disable authentication send-only for level 2 PDUs.
                        choices:
                            - enable
                            - disable
                    circuit-type:
                        description:
                            - IS-IS interface's circuit type
                        choices:
                            - level-1-2
                            - level-1
                            - level-2
                    csnp-interval-l1:
                        description:
                            - Level 1 CSNP interval.
                    csnp-interval-l2:
                        description:
                            - Level 2 CSNP interval.
                    hello-interval-l1:
                        description:
                            - Level 1 hello interval.
                    hello-interval-l2:
                        description:
                            - Level 2 hello interval.
                    hello-multiplier-l1:
                        description:
                            - Level 1 multiplier for Hello holding time.
                    hello-multiplier-l2:
                        description:
                            - Level 2 multiplier for Hello holding time.
                    hello-padding:
                        description:
                            - Enable/disable padding to IS-IS hello packets.
                        choices:
                            - enable
                            - disable
                    lsp-interval:
                        description:
                            - LSP transmission interval (milliseconds).
                    lsp-retransmit-interval:
                        description:
                            - LSP retransmission interval (sec).
                    mesh-group:
                        description:
                            - Enable/disable IS-IS mesh group.
                        choices:
                            - enable
                            - disable
                    mesh-group-id:
                        description:
                            - "Mesh group ID <0-4294967295>, 0: mesh-group blocked."
                    metric-l1:
                        description:
                            - Level 1 metric for interface.
                    metric-l2:
                        description:
                            - Level 2 metric for interface.
                    name:
                        description:
                            - IS-IS interface name. Source system.interface.name.
                        required: true
                    network-type:
                        description:
                            - IS-IS interface's network type
                        choices:
                            - broadcast
                            - point-to-point
                            - loopback
                    priority-l1:
                        description:
                            - Level 1 priority.
                    priority-l2:
                        description:
                            - Level 2 priority.
                    status:
                        description:
                            - Enable/disable interface for IS-IS.
                        choices:
                            - enable
                            - disable
                    status6:
                        description:
                            - Enable/disable IPv6 interface for IS-IS.
                        choices:
                            - enable
                            - disable
                    wide-metric-l1:
                        description:
                            - Level 1 wide metric for interface.
                    wide-metric-l2:
                        description:
                            - Level 2 wide metric for interface.
            isis-net:
                description:
                    - IS-IS net configuration.
                suboptions:
                    id:
                        description:
                            - isis-net ID.
                        required: true
                    net:
                        description:
                            - IS-IS net xx.xxxx. ... .xxxx.xx.
            lsp-gen-interval-l1:
                description:
                    - Minimum interval for level 1 LSP regenerating.
            lsp-gen-interval-l2:
                description:
                    - Minimum interval for level 2 LSP regenerating.
            lsp-refresh-interval:
                description:
                    - LSP refresh time in seconds.
            max-lsp-lifetime:
                description:
                    - Maximum LSP lifetime in seconds.
            metric-style:
                description:
                    - Use old-style (ISO 10589) or new-style packet formats
                choices:
                    - narrow
                    - wide
                    - transition
                    - narrow-transition
                    - narrow-transition-l1
                    - narrow-transition-l2
                    - wide-l1
                    - wide-l2
                    - wide-transition
                    - wide-transition-l1
                    - wide-transition-l2
                    - transition-l1
                    - transition-l2
            overload-bit:
                description:
                    - Enable/disable signal other routers not to use us in SPF.
                choices:
                    - enable
                    - disable
            overload-bit-on-startup:
                description:
                    - Overload-bit only temporarily after reboot.
            overload-bit-suppress:
                description:
                    - Suppress overload-bit for the specific prefixes.
                choices:
                    - external
                    - interlevel
            redistribute:
                description:
                    - IS-IS redistribute protocols.
                suboptions:
                    level:
                        description:
                            - Level.
                        choices:
                            - level-1-2
                            - level-1
                            - level-2
                    metric:
                        description:
                            - Metric.
                    metric-type:
                        description:
                            - Metric type.
                        choices:
                            - external
                            - internal
                    protocol:
                        description:
                            - Protocol name.
                        required: true
                    routemap:
                        description:
                            - Route map name. Source router.route-map.name.
                    status:
                        description:
                            - Status.
                        choices:
                            - enable
                            - disable
            redistribute-l1:
                description:
                    - Enable/disable redistribution of level 1 routes into level 2.
                choices:
                    - enable
                    - disable
            redistribute-l1-list:
                description:
                    - Access-list for route redistribution from l1 to l2. Source router.access-list.name.
            redistribute-l2:
                description:
                    - Enable/disable redistribution of level 2 routes into level 1.
                choices:
                    - enable
                    - disable
            redistribute-l2-list:
                description:
                    - Access-list for route redistribution from l2 to l1. Source router.access-list.name.
            redistribute6:
                description:
                    - IS-IS IPv6 redistribution for routing protocols.
                suboptions:
                    level:
                        description:
                            - Level.
                        choices:
                            - level-1-2
                            - level-1
                            - level-2
                    metric:
                        description:
                            - Metric.
                    metric-type:
                        description:
                            - Metric type.
                        choices:
                            - external
                            - internal
                    protocol:
                        description:
                            - Protocol name.
                        required: true
                    routemap:
                        description:
                            - Route map name. Source router.route-map.name.
                    status:
                        description:
                            - Enable/disable redistribution.
                        choices:
                            - enable
                            - disable
            redistribute6-l1:
                description:
                    - Enable/disable redistribution of level 1 IPv6 routes into level 2.
                choices:
                    - enable
                    - disable
            redistribute6-l1-list:
                description:
                    - Access-list for IPv6 route redistribution from l1 to l2. Source router.access-list6.name.
            redistribute6-l2:
                description:
                    - Enable/disable redistribution of level 2 IPv6 routes into level 1.
                choices:
                    - enable
                    - disable
            redistribute6-l2-list:
                description:
                    - Access-list for IPv6 route redistribution from l2 to l1. Source router.access-list6.name.
            spf-interval-exp-l1:
                description:
                    - Level 1 SPF calculation delay.
            spf-interval-exp-l2:
                description:
                    - Level 2 SPF calculation delay.
            summary-address:
                description:
                    - IS-IS summary addresses.
                suboptions:
                    id:
                        description:
                            - Summary address entry ID.
                        required: true
                    level:
                        description:
                            - Level.
                        choices:
                            - level-1-2
                            - level-1
                            - level-2
                    prefix:
                        description:
                            - Prefix.
            summary-address6:
                description:
                    - IS-IS IPv6 summary address.
                suboptions:
                    id:
                        description:
                            - Prefix entry ID.
                        required: true
                    level:
                        description:
                            - Level.
                        choices:
                            - level-1-2
                            - level-1
                            - level-2
                    prefix6:
                        description:
                            - IPv6 prefix.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure IS-IS.
    fortios_router_isis:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      router_isis:
        adjacency-check: "enable"
        adjacency-check6: "enable"
        adv-passive-only: "enable"
        adv-passive-only6: "enable"
        auth-keychain-l1: "<your_own_value> (source router.key-chain.name)"
        auth-keychain-l2: "<your_own_value> (source router.key-chain.name)"
        auth-mode-l1: "password"
        auth-mode-l2: "password"
        auth-password-l1: "<your_own_value>"
        auth-password-l2: "<your_own_value>"
        auth-sendonly-l1: "enable"
        auth-sendonly-l2: "enable"
        default-originate: "enable"
        default-originate6: "enable"
        dynamic-hostname: "enable"
        ignore-lsp-errors: "enable"
        is-type: "level-1-2"
        isis-interface:
         -
            auth-keychain-l1: "<your_own_value> (source router.key-chain.name)"
            auth-keychain-l2: "<your_own_value> (source router.key-chain.name)"
            auth-mode-l1: "md5"
            auth-mode-l2: "md5"
            auth-password-l1: "<your_own_value>"
            auth-password-l2: "<your_own_value>"
            auth-send-only-l1: "enable"
            auth-send-only-l2: "enable"
            circuit-type: "level-1-2"
            csnp-interval-l1: "30"
            csnp-interval-l2: "31"
            hello-interval-l1: "32"
            hello-interval-l2: "33"
            hello-multiplier-l1: "34"
            hello-multiplier-l2: "35"
            hello-padding: "enable"
            lsp-interval: "37"
            lsp-retransmit-interval: "38"
            mesh-group: "enable"
            mesh-group-id: "40"
            metric-l1: "41"
            metric-l2: "42"
            name: "default_name_43 (source system.interface.name)"
            network-type: "broadcast"
            priority-l1: "45"
            priority-l2: "46"
            status: "enable"
            status6: "enable"
            wide-metric-l1: "49"
            wide-metric-l2: "50"
        isis-net:
         -
            id:  "52"
            net: "<your_own_value>"
        lsp-gen-interval-l1: "54"
        lsp-gen-interval-l2: "55"
        lsp-refresh-interval: "56"
        max-lsp-lifetime: "57"
        metric-style: "narrow"
        overload-bit: "enable"
        overload-bit-on-startup: "60"
        overload-bit-suppress: "external"
        redistribute:
         -
            level: "level-1-2"
            metric: "64"
            metric-type: "external"
            protocol: "<your_own_value>"
            routemap: "<your_own_value> (source router.route-map.name)"
            status: "enable"
        redistribute-l1: "enable"
        redistribute-l1-list: "<your_own_value> (source router.access-list.name)"
        redistribute-l2: "enable"
        redistribute-l2-list: "<your_own_value> (source router.access-list.name)"
        redistribute6:
         -
            level: "level-1-2"
            metric: "75"
            metric-type: "external"
            protocol: "<your_own_value>"
            routemap: "<your_own_value> (source router.route-map.name)"
            status: "enable"
        redistribute6-l1: "enable"
        redistribute6-l1-list: "<your_own_value> (source router.access-list6.name)"
        redistribute6-l2: "enable"
        redistribute6-l2-list: "<your_own_value> (source router.access-list6.name)"
        spf-interval-exp-l1: "<your_own_value>"
        spf-interval-exp-l2: "<your_own_value>"
        summary-address:
         -
            id:  "87"
            level: "level-1-2"
            prefix: "<your_own_value>"
        summary-address6:
         -
            id:  "91"
            level: "level-1-2"
            prefix6: "<your_own_value>"
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


def filter_router_isis_data(json):
    option_list = ['adjacency-check', 'adjacency-check6', 'adv-passive-only',
                   'adv-passive-only6', 'auth-keychain-l1', 'auth-keychain-l2',
                   'auth-mode-l1', 'auth-mode-l2', 'auth-password-l1',
                   'auth-password-l2', 'auth-sendonly-l1', 'auth-sendonly-l2',
                   'default-originate', 'default-originate6', 'dynamic-hostname',
                   'ignore-lsp-errors', 'is-type', 'isis-interface',
                   'isis-net', 'lsp-gen-interval-l1', 'lsp-gen-interval-l2',
                   'lsp-refresh-interval', 'max-lsp-lifetime', 'metric-style',
                   'overload-bit', 'overload-bit-on-startup', 'overload-bit-suppress',
                   'redistribute', 'redistribute-l1', 'redistribute-l1-list',
                   'redistribute-l2', 'redistribute-l2-list', 'redistribute6',
                   'redistribute6-l1', 'redistribute6-l1-list', 'redistribute6-l2',
                   'redistribute6-l2-list', 'spf-interval-exp-l1', 'spf-interval-exp-l2',
                   'summary-address', 'summary-address6']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_multilists_attributes(data):
    multilist_attrs = []

    for attr in multilist_attrs:
        try:
            path = "data['" + "']['".join(elem for elem in attr) + "']"
            current_val = eval(path)
            flattened_val = ' '.join(elem for elem in current_val)
            exec(path + '= flattened_val')
        except BaseException:
            pass

    return data


def router_isis(data, fos):
    vdom = data['vdom']
    router_isis_data = data['router_isis']
    flattened_data = flatten_multilists_attributes(router_isis_data)
    filtered_data = filter_router_isis_data(flattened_data)
    return fos.set('router',
                   'isis',
                   data=filtered_data,
                   vdom=vdom)


def fortios_router(data, fos):
    login(data, fos)

    if data['router_isis']:
        resp = router_isis(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "router_isis": {
            "required": False, "type": "dict",
            "options": {
                "adjacency-check": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "adjacency-check6": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "adv-passive-only": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "adv-passive-only6": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]},
                "auth-keychain-l1": {"required": False, "type": "str"},
                "auth-keychain-l2": {"required": False, "type": "str"},
                "auth-mode-l1": {"required": False, "type": "str",
                                 "choices": ["password", "md5"]},
                "auth-mode-l2": {"required": False, "type": "str",
                                 "choices": ["password", "md5"]},
                "auth-password-l1": {"required": False, "type": "str"},
                "auth-password-l2": {"required": False, "type": "str"},
                "auth-sendonly-l1": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "auth-sendonly-l2": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "default-originate": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]},
                "default-originate6": {"required": False, "type": "str",
                                       "choices": ["enable", "disable"]},
                "dynamic-hostname": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "ignore-lsp-errors": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]},
                "is-type": {"required": False, "type": "str",
                            "choices": ["level-1-2", "level-1", "level-2-only"]},
                "isis-interface": {"required": False, "type": "list",
                                   "options": {
                                       "auth-keychain-l1": {"required": False, "type": "str"},
                                       "auth-keychain-l2": {"required": False, "type": "str"},
                                       "auth-mode-l1": {"required": False, "type": "str",
                                                        "choices": ["md5", "password"]},
                                       "auth-mode-l2": {"required": False, "type": "str",
                                                        "choices": ["md5", "password"]},
                                       "auth-password-l1": {"required": False, "type": "str"},
                                       "auth-password-l2": {"required": False, "type": "str"},
                                       "auth-send-only-l1": {"required": False, "type": "str",
                                                             "choices": ["enable", "disable"]},
                                       "auth-send-only-l2": {"required": False, "type": "str",
                                                             "choices": ["enable", "disable"]},
                                       "circuit-type": {"required": False, "type": "str",
                                                        "choices": ["level-1-2", "level-1", "level-2"]},
                                       "csnp-interval-l1": {"required": False, "type": "int"},
                                       "csnp-interval-l2": {"required": False, "type": "int"},
                                       "hello-interval-l1": {"required": False, "type": "int"},
                                       "hello-interval-l2": {"required": False, "type": "int"},
                                       "hello-multiplier-l1": {"required": False, "type": "int"},
                                       "hello-multiplier-l2": {"required": False, "type": "int"},
                                       "hello-padding": {"required": False, "type": "str",
                                                         "choices": ["enable", "disable"]},
                                       "lsp-interval": {"required": False, "type": "int"},
                                       "lsp-retransmit-interval": {"required": False, "type": "int"},
                                       "mesh-group": {"required": False, "type": "str",
                                                      "choices": ["enable", "disable"]},
                                       "mesh-group-id": {"required": False, "type": "int"},
                                       "metric-l1": {"required": False, "type": "int"},
                                       "metric-l2": {"required": False, "type": "int"},
                                       "name": {"required": True, "type": "str"},
                                       "network-type": {"required": False, "type": "str",
                                                        "choices": ["broadcast", "point-to-point", "loopback"]},
                                       "priority-l1": {"required": False, "type": "int"},
                                       "priority-l2": {"required": False, "type": "int"},
                                       "status": {"required": False, "type": "str",
                                                  "choices": ["enable", "disable"]},
                                       "status6": {"required": False, "type": "str",
                                                   "choices": ["enable", "disable"]},
                                       "wide-metric-l1": {"required": False, "type": "int"},
                                       "wide-metric-l2": {"required": False, "type": "int"}
                                   }},
                "isis-net": {"required": False, "type": "list",
                             "options": {
                                 "id": {"required": True, "type": "int"},
                                 "net": {"required": False, "type": "str"}
                             }},
                "lsp-gen-interval-l1": {"required": False, "type": "int"},
                "lsp-gen-interval-l2": {"required": False, "type": "int"},
                "lsp-refresh-interval": {"required": False, "type": "int"},
                "max-lsp-lifetime": {"required": False, "type": "int"},
                "metric-style": {"required": False, "type": "str",
                                 "choices": ["narrow", "wide", "transition",
                                             "narrow-transition", "narrow-transition-l1", "narrow-transition-l2",
                                             "wide-l1", "wide-l2", "wide-transition",
                                             "wide-transition-l1", "wide-transition-l2", "transition-l1",
                                             "transition-l2"]},
                "overload-bit": {"required": False, "type": "str",
                                 "choices": ["enable", "disable"]},
                "overload-bit-on-startup": {"required": False, "type": "int"},
                "overload-bit-suppress": {"required": False, "type": "str",
                                          "choices": ["external", "interlevel"]},
                "redistribute": {"required": False, "type": "list",
                                 "options": {
                                     "level": {"required": False, "type": "str",
                                               "choices": ["level-1-2", "level-1", "level-2"]},
                                     "metric": {"required": False, "type": "int"},
                                     "metric-type": {"required": False, "type": "str",
                                                     "choices": ["external", "internal"]},
                                     "protocol": {"required": True, "type": "str"},
                                     "routemap": {"required": False, "type": "str"},
                                     "status": {"required": False, "type": "str",
                                                "choices": ["enable", "disable"]}
                                 }},
                "redistribute-l1": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "redistribute-l1-list": {"required": False, "type": "str"},
                "redistribute-l2": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "redistribute-l2-list": {"required": False, "type": "str"},
                "redistribute6": {"required": False, "type": "list",
                                  "options": {
                                      "level": {"required": False, "type": "str",
                                                "choices": ["level-1-2", "level-1", "level-2"]},
                                      "metric": {"required": False, "type": "int"},
                                      "metric-type": {"required": False, "type": "str",
                                                      "choices": ["external", "internal"]},
                                      "protocol": {"required": True, "type": "str"},
                                      "routemap": {"required": False, "type": "str"},
                                      "status": {"required": False, "type": "str",
                                                 "choices": ["enable", "disable"]}
                                  }},
                "redistribute6-l1": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "redistribute6-l1-list": {"required": False, "type": "str"},
                "redistribute6-l2": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "redistribute6-l2-list": {"required": False, "type": "str"},
                "spf-interval-exp-l1": {"required": False, "type": "str"},
                "spf-interval-exp-l2": {"required": False, "type": "str"},
                "summary-address": {"required": False, "type": "list",
                                    "options": {
                                        "id": {"required": True, "type": "int"},
                                        "level": {"required": False, "type": "str",
                                                  "choices": ["level-1-2", "level-1", "level-2"]},
                                        "prefix": {"required": False, "type": "str"}
                                    }},
                "summary-address6": {"required": False, "type": "list",
                                     "options": {
                                         "id": {"required": True, "type": "int"},
                                         "level": {"required": False, "type": "str",
                                                   "choices": ["level-1-2", "level-1", "level-2"]},
                                         "prefix6": {"required": False, "type": "str"}
                                     }}

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

    is_error, has_changed, result = fortios_router(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
