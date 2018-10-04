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
module: fortios_system_link_monitor
short_description: Configure Link Health Monitor.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure system feature and link_monitor category.
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
    system_link_monitor:
        description:
            - Configure Link Health Monitor.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            addr-mode:
                description:
                    - Address mode (IPv4 or IPv6).
                choices:
                    - ipv4
                    - ipv6
            failtime:
                description:
                    - Number of retry attempts before the server is considered down (1 - 10, default = 5)
            gateway-ip:
                description:
                    - Gateway IP address used to probe the server.
            gateway-ip6:
                description:
                    - Gateway IPv6 address used to probe the server.
            ha-priority:
                description:
                    - HA election priority (1 - 50).
            http-get:
                description:
                    - If you are monitoring an HTML server you can send an HTTP-GET request with a custom string. Use this option to define the string.
            http-match:
                description:
                    - String that you expect to see in the HTTP-GET requests of the traffic to be monitored.
            interval:
                description:
                    - Detection interval (1 - 3600 sec, default = 5).
            name:
                description:
                    - Link monitor name.
                required: true
            packet-size:
                description:
                    - Packet size of a twamp test session,
            password:
                description:
                    - Twamp controller password in authentication mode
            port:
                description:
                    - Port number of the traffic to be used to monitor the server.
            protocol:
                description:
                    - Protocols used to monitor the server.
                choices:
                    - ping
                    - tcp-echo
                    - udp-echo
                    - http
                    - twamp
                    - ping6
            recoverytime:
                description:
                    - Number of successful responses received before server is considered recovered (1 - 10, default = 5).
            security-mode:
                description:
                    - Twamp controller security mode.
                choices:
                    - none
                    - authentication
            server:
                description:
                    - IP address of the server(s) to be monitored.
                suboptions:
                    address:
                        description:
                            - Server address.
                        required: true
            source-ip:
                description:
                    - Source IP address used in packet to the server.
            source-ip6:
                description:
                    - Source IPv6 address used in packet to the server.
            srcintf:
                description:
                    - Interface that receives the traffic to be monitored. Source system.interface.name.
            status:
                description:
                    - Enable/disable this link monitor.
                choices:
                    - enable
                    - disable
            update-cascade-interface:
                description:
                    - Enable/disable update cascade interface.
                choices:
                    - enable
                    - disable
            update-static-route:
                description:
                    - Enable/disable updating the static route.
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
  - name: Configure Link Health Monitor.
    fortios_system_link_monitor:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      system_link_monitor:
        state: "present"
        addr-mode: "ipv4"
        failtime: "4"
        gateway-ip: "<your_own_value>"
        gateway-ip6: "<your_own_value>"
        ha-priority: "7"
        http-get: "<your_own_value>"
        http-match: "<your_own_value>"
        interval: "10"
        name: "default_name_11"
        packet-size: "12"
        password: "<your_own_value>"
        port: "14"
        protocol: "ping"
        recoverytime: "16"
        security-mode: "none"
        server:
         -
            address: "<your_own_value>"
        source-ip: "84.230.14.43"
        source-ip6: "<your_own_value>"
        srcintf: "<your_own_value> (source system.interface.name)"
        status: "enable"
        update-cascade-interface: "enable"
        update-static-route: "enable"
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


def filter_system_link_monitor_data(json):
    option_list = ['addr-mode', 'failtime', 'gateway-ip',
                   'gateway-ip6', 'ha-priority', 'http-get',
                   'http-match', 'interval', 'name',
                   'packet-size', 'password', 'port',
                   'protocol', 'recoverytime', 'security-mode',
                   'server', 'source-ip', 'source-ip6',
                   'srcintf', 'status', 'update-cascade-interface',
                   'update-static-route']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def system_link_monitor(data, fos):
    vdom = data['vdom']
    system_link_monitor_data = data['system_link_monitor']
    filtered_data = filter_system_link_monitor_data(system_link_monitor_data)
    if system_link_monitor_data['state'] == "present":
        return fos.set('system',
                       'link-monitor',
                       data=filtered_data,
                       vdom=vdom)

    elif system_link_monitor_data['state'] == "absent":
        return fos.delete('system',
                          'link-monitor',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data)

    methodlist = ['system_link_monitor']
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
        "system_link_monitor": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "addr-mode": {"required": False, "type": "str",
                              "choices": ["ipv4", "ipv6"]},
                "failtime": {"required": False, "type": "int"},
                "gateway-ip": {"required": False, "type": "str"},
                "gateway-ip6": {"required": False, "type": "str"},
                "ha-priority": {"required": False, "type": "int"},
                "http-get": {"required": False, "type": "str"},
                "http-match": {"required": False, "type": "str"},
                "interval": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "packet-size": {"required": False, "type": "int"},
                "password": {"required": False, "type": "str"},
                "port": {"required": False, "type": "int"},
                "protocol": {"required": False, "type": "str",
                             "choices": ["ping", "tcp-echo", "udp-echo",
                                         "http", "twamp", "ping6"]},
                "recoverytime": {"required": False, "type": "int"},
                "security-mode": {"required": False, "type": "str",
                                  "choices": ["none", "authentication"]},
                "server": {"required": False, "type": "list",
                           "options": {
                               "address": {"required": True, "type": "str"}
                           }},
                "source-ip": {"required": False, "type": "str"},
                "source-ip6": {"required": False, "type": "str"},
                "srcintf": {"required": False, "type": "str"},
                "status": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "update-cascade-interface": {"required": False, "type": "str",
                                             "choices": ["enable", "disable"]},
                "update-static-route": {"required": False, "type": "str",
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

    is_error, has_changed, result = fortios_system(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
