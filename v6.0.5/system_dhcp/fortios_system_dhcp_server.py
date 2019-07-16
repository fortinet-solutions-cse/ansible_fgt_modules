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
module: fortios_system_dhcp_server
short_description: Configure DHCP servers in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS device by allowing the
      user to set and modify system_dhcp feature and server category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.5
version_added: "2.9"
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
            - FortiOS or FortiGate IP address.
        type: str
        required: true
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: true
    password:
        description:
            - FortiOS or FortiGate password.
        type: str
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS protocol.
        type: bool
        default: true
    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        choices:
            - present
            - absent
    system_dhcp_server:
        description:
            - Configure DHCP servers.
        default: null
        type: dict
        suboptions:
            auto_configuration:
                description:
                    - Enable/disable auto configuration.
                choices:
                    - disable
                    - enable
            conflicted_ip_timeout:
                description:
                    - Time in seconds to wait after a conflicted IP address is removed from the DHCP range before it can be reused.
            ddns_auth:
                description:
                    - DDNS authentication mode.
                choices:
                    - disable
                    - tsig
            ddns_key:
                description:
                    - DDNS update key (base 64 encoding).
            ddns_keyname:
                description:
                    - DDNS update key name.
            ddns_server_ip:
                description:
                    - DDNS server IP.
            ddns_ttl:
                description:
                    - TTL.
            ddns_update:
                description:
                    - Enable/disable DDNS update for DHCP.
                choices:
                    - disable
                    - enable
            ddns_update_override:
                description:
                    - Enable/disable DDNS update override for DHCP.
                choices:
                    - disable
                    - enable
            ddns_zone:
                description:
                    - Zone of your domain name (ex. DDNS.com).
            default_gateway:
                description:
                    - Default gateway IP address assigned by the DHCP server.
            dns_server1:
                description:
                    - DNS server 1.
            dns_server2:
                description:
                    - DNS server 2.
            dns_server3:
                description:
                    - DNS server 3.
            dns_service:
                description:
                    - Options for assigning DNS servers to DHCP clients.
                choices:
                    - local
                    - default
                    - specify
            domain:
                description:
                    - Domain name suffix for the IP addresses that the DHCP server assigns to clients.
            exclude_range:
                description:
                    - Exclude one or more ranges of IP addresses from being assigned to clients.
                suboptions:
                    end_ip:
                        description:
                            - End of IP range.
                    id:
                        description:
                            - ID.
                        required: true
                    start_ip:
                        description:
                            - Start of IP range.
            filename:
                description:
                    - Name of the boot file on the TFTP server.
            forticlient_on_net_status:
                description:
                    - Enable/disable FortiClient_On_Net service for this DHCP server.
                choices:
                    - disable
                    - enable
            id:
                description:
                    - ID.
                required: true
            interface:
                description:
                    - DHCP server can assign IP configurations to clients connected to this interface. Source system.interface.name.
            ip_mode:
                description:
                    - Method used to assign client IP.
                choices:
                    - range
                    - usrgrp
            ip_range:
                description:
                    - DHCP IP range configuration.
                suboptions:
                    end_ip:
                        description:
                            - End of IP range.
                    id:
                        description:
                            - ID.
                        required: true
                    start_ip:
                        description:
                            - Start of IP range.
            ipsec_lease_hold:
                description:
                    - DHCP over IPsec leases expire this many seconds after tunnel down (0 to disable forced_expiry).
            lease_time:
                description:
                    - Lease time in seconds, 0 means unlimited.
            mac_acl_default_action:
                description:
                    - MAC access control default action (allow or block assigning IP settings).
                choices:
                    - assign
                    - block
            netmask:
                description:
                    - Netmask assigned by the DHCP server.
            next_server:
                description:
                    - IP address of a server (for example, a TFTP sever) that DHCP clients can download a boot file from.
            ntp_server1:
                description:
                    - NTP server 1.
            ntp_server2:
                description:
                    - NTP server 2.
            ntp_server3:
                description:
                    - NTP server 3.
            ntp_service:
                description:
                    - Options for assigning Network Time Protocol (NTP) servers to DHCP clients.
                choices:
                    - local
                    - default
                    - specify
            options:
                description:
                    - DHCP options.
                suboptions:
                    code:
                        description:
                            - DHCP option code.
                    id:
                        description:
                            - ID.
                        required: true
                    ip:
                        description:
                            - DHCP option IPs.
                    type:
                        description:
                            - DHCP option type.
                        choices:
                            - hex
                            - string
                            - ip
                            - fqdn
                    value:
                        description:
                            - DHCP option value.
            reserved_address:
                description:
                    - Options for the DHCP server to assign IP settings to specific MAC addresses.
                suboptions:
                    action:
                        description:
                            - Options for the DHCP server to configure the client with the reserved MAC address.
                        choices:
                            - assign
                            - block
                            - reserved
                    description:
                        description:
                            - Description.
                    id:
                        description:
                            - ID.
                        required: true
                    ip:
                        description:
                            - IP address to be reserved for the MAC address.
                    mac:
                        description:
                            - MAC address of the client that will get the reserved IP address.
            server_type:
                description:
                    - DHCP server can be a normal DHCP server or an IPsec DHCP server.
                choices:
                    - regular
                    - ipsec
            status:
                description:
                    - Enable/disable this DHCP configuration.
                choices:
                    - disable
                    - enable
            tftp_server:
                description:
                    - One or more hostnames or IP addresses of the TFTP servers in quotes separated by spaces.
                suboptions:
                    tftp_server:
                        description:
                            - TFTP server.
            timezone:
                description:
                    - Select the time zone to be assigned to DHCP clients.
                choices:
                    - 01
                    - 02
                    - 03
                    - 04
                    - 05
                    - 81
                    - 06
                    - 07
                    - 08
                    - 09
                    - 10
                    - 11
                    - 12
                    - 13
                    - 74
                    - 14
                    - 77
                    - 15
                    - 87
                    - 16
                    - 17
                    - 18
                    - 19
                    - 20
                    - 75
                    - 21
                    - 22
                    - 23
                    - 24
                    - 80
                    - 79
                    - 25
                    - 26
                    - 27
                    - 28
                    - 78
                    - 29
                    - 30
                    - 31
                    - 32
                    - 33
                    - 34
                    - 35
                    - 36
                    - 37
                    - 38
                    - 83
                    - 84
                    - 40
                    - 85
                    - 41
                    - 42
                    - 43
                    - 39
                    - 44
                    - 46
                    - 47
                    - 51
                    - 48
                    - 45
                    - 49
                    - 50
                    - 52
                    - 53
                    - 54
                    - 55
                    - 56
                    - 57
                    - 58
                    - 59
                    - 60
                    - 62
                    - 63
                    - 61
                    - 64
                    - 65
                    - 66
                    - 67
                    - 68
                    - 69
                    - 70
                    - 71
                    - 72
                    - 00
                    - 82
                    - 73
                    - 86
                    - 76
            timezone_option:
                description:
                    - Options for the DHCP server to set the client's time zone.
                choices:
                    - disable
                    - default
                    - specify
            vci_match:
                description:
                    - Enable/disable vendor class identifier (VCI) matching. When enabled only DHCP requests with a matching VCI are served.
                choices:
                    - disable
                    - enable
            vci_string:
                description:
                    - One or more VCI strings in quotes separated by spaces.
                suboptions:
                    vci_string:
                        description:
                            - VCI strings.
            wifi_ac1:
                description:
                    - WiFi Access Controller 1 IP address (DHCP option 138, RFC 5417).
            wifi_ac2:
                description:
                    - WiFi Access Controller 2 IP address (DHCP option 138, RFC 5417).
            wifi_ac3:
                description:
                    - WiFi Access Controller 3 IP address (DHCP option 138, RFC 5417).
            wins_server1:
                description:
                    - WINS server 1.
            wins_server2:
                description:
                    - WINS server 2.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure DHCP servers.
    fortios_system_dhcp_server:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      state: "present"
      system_dhcp_server:
        auto_configuration: "disable"
        conflicted_ip_timeout: "4"
        ddns_auth: "disable"
        ddns_key: "<your_own_value>"
        ddns_keyname: "<your_own_value>"
        ddns_server_ip: "<your_own_value>"
        ddns_ttl: "9"
        ddns_update: "disable"
        ddns_update_override: "disable"
        ddns_zone: "<your_own_value>"
        default_gateway: "<your_own_value>"
        dns_server1: "<your_own_value>"
        dns_server2: "<your_own_value>"
        dns_server3: "<your_own_value>"
        dns_service: "local"
        domain: "<your_own_value>"
        exclude_range:
         -
            end_ip: "<your_own_value>"
            id:  "21"
            start_ip: "<your_own_value>"
        filename: "<your_own_value>"
        forticlient_on_net_status: "disable"
        id:  "25"
        interface: "<your_own_value> (source system.interface.name)"
        ip_mode: "range"
        ip_range:
         -
            end_ip: "<your_own_value>"
            id:  "30"
            start_ip: "<your_own_value>"
        ipsec_lease_hold: "32"
        lease_time: "33"
        mac_acl_default_action: "assign"
        netmask: "<your_own_value>"
        next_server: "<your_own_value>"
        ntp_server1: "<your_own_value>"
        ntp_server2: "<your_own_value>"
        ntp_server3: "<your_own_value>"
        ntp_service: "local"
        options:
         -
            code: "42"
            id:  "43"
            ip: "<your_own_value>"
            type: "hex"
            value: "<your_own_value>"
        reserved_address:
         -
            action: "assign"
            description: "<your_own_value>"
            id:  "50"
            ip: "<your_own_value>"
            mac: "<your_own_value>"
        server_type: "regular"
        status: "disable"
        tftp_server:
         -
            tftp_server: "<your_own_value>"
        timezone: "01"
        timezone_option: "disable"
        vci_match: "disable"
        vci_string:
         -
            vci_string: "<your_own_value>"
        wifi_ac1: "<your_own_value>"
        wifi_ac2: "<your_own_value>"
        wifi_ac3: "<your_own_value>"
        wins_server1: "<your_own_value>"
        wins_server2: "<your_own_value>"
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
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortios.fortios import FortiOSHandler
from ansible.module_utils.network.fortimanager.common import FAIL_SOCKET_MSG


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


def filter_system_dhcp_server_data(json):
    option_list = ['auto_configuration', 'conflicted_ip_timeout', 'ddns_auth',
                   'ddns_key', 'ddns_keyname', 'ddns_server_ip',
                   'ddns_ttl', 'ddns_update', 'ddns_update_override',
                   'ddns_zone', 'default_gateway', 'dns_server1',
                   'dns_server2', 'dns_server3', 'dns_service',
                   'domain', 'exclude_range', 'filename',
                   'forticlient_on_net_status', 'id', 'interface',
                   'ip_mode', 'ip_range', 'ipsec_lease_hold',
                   'lease_time', 'mac_acl_default_action', 'netmask',
                   'next_server', 'ntp_server1', 'ntp_server2',
                   'ntp_server3', 'ntp_service', 'options',
                   'reserved_address', 'server_type', 'status',
                   'tftp_server', 'timezone', 'timezone_option',
                   'vci_match', 'vci_string', 'wifi_ac1',
                   'wifi_ac2', 'wifi_ac3', 'wins_server1',
                   'wins_server2']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for elem in data:
            elem = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def system_dhcp_server(data, fos):
    vdom = data['vdom']
    state = data['state']
    system_dhcp_server_data = data['system_dhcp_server']
    filtered_data = underscore_to_hyphen(filter_system_dhcp_server_data(system_dhcp_server_data))

    if state == "present":
        return fos.set('system.dhcp',
                       'server',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('system.dhcp',
                          'server',
                          mkey=filtered_data['id'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system_dhcp(data, fos):

    if data['system_dhcp_server']:
        resp = system_dhcp_server(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "system_dhcp_server": {
            "required": False, "type": "dict",
            "options": {
                "auto_configuration": {"required": False, "type": "str",
                                       "choices": ["disable", "enable"]},
                "conflicted_ip_timeout": {"required": False, "type": "int"},
                "ddns_auth": {"required": False, "type": "str",
                              "choices": ["disable", "tsig"]},
                "ddns_key": {"required": False, "type": "str"},
                "ddns_keyname": {"required": False, "type": "str"},
                "ddns_server_ip": {"required": False, "type": "str"},
                "ddns_ttl": {"required": False, "type": "int"},
                "ddns_update": {"required": False, "type": "str",
                                "choices": ["disable", "enable"]},
                "ddns_update_override": {"required": False, "type": "str",
                                         "choices": ["disable", "enable"]},
                "ddns_zone": {"required": False, "type": "str"},
                "default_gateway": {"required": False, "type": "str"},
                "dns_server1": {"required": False, "type": "str"},
                "dns_server2": {"required": False, "type": "str"},
                "dns_server3": {"required": False, "type": "str"},
                "dns_service": {"required": False, "type": "str",
                                "choices": ["local", "default", "specify"]},
                "domain": {"required": False, "type": "str"},
                "exclude_range": {"required": False, "type": "list",
                                  "options": {
                                      "end_ip": {"required": False, "type": "str"},
                                      "id": {"required": True, "type": "int"},
                                      "start_ip": {"required": False, "type": "str"}
                                  }},
                "filename": {"required": False, "type": "str"},
                "forticlient_on_net_status": {"required": False, "type": "str",
                                              "choices": ["disable", "enable"]},
                "id": {"required": True, "type": "int"},
                "interface": {"required": False, "type": "str"},
                "ip_mode": {"required": False, "type": "str",
                            "choices": ["range", "usrgrp"]},
                "ip_range": {"required": False, "type": "list",
                             "options": {
                                 "end_ip": {"required": False, "type": "str"},
                                 "id": {"required": True, "type": "int"},
                                 "start_ip": {"required": False, "type": "str"}
                             }},
                "ipsec_lease_hold": {"required": False, "type": "int"},
                "lease_time": {"required": False, "type": "int"},
                "mac_acl_default_action": {"required": False, "type": "str",
                                           "choices": ["assign", "block"]},
                "netmask": {"required": False, "type": "str"},
                "next_server": {"required": False, "type": "str"},
                "ntp_server1": {"required": False, "type": "str"},
                "ntp_server2": {"required": False, "type": "str"},
                "ntp_server3": {"required": False, "type": "str"},
                "ntp_service": {"required": False, "type": "str",
                                "choices": ["local", "default", "specify"]},
                "options": {"required": False, "type": "list",
                            "options": {
                                "code": {"required": False, "type": "int"},
                                "id": {"required": True, "type": "int"},
                                "ip": {"required": False, "type": "str"},
                                "type": {"required": False, "type": "str",
                                         "choices": ["hex", "string", "ip",
                                                     "fqdn"]},
                                "value": {"required": False, "type": "str"}
                            }},
                "reserved_address": {"required": False, "type": "list",
                                     "options": {
                                         "action": {"required": False, "type": "str",
                                                    "choices": ["assign", "block", "reserved"]},
                                         "description": {"required": False, "type": "str"},
                                         "id": {"required": True, "type": "int"},
                                         "ip": {"required": False, "type": "str"},
                                         "mac": {"required": False, "type": "str"}
                                     }},
                "server_type": {"required": False, "type": "str",
                                "choices": ["regular", "ipsec"]},
                "status": {"required": False, "type": "str",
                           "choices": ["disable", "enable"]},
                "tftp_server": {"required": False, "type": "list",
                                "options": {
                                    "tftp_server": {"required": False, "type": "str"}
                                }},
                "timezone": {"required": False, "type": "str",
                             "choices": ["01", "02", "03",
                                         "04", "05", "81",
                                         "06", "07", "08",
                                         "09", "10", "11",
                                         "12", "13", "74",
                                         "14", "77", "15",
                                         "87", "16", "17",
                                         "18", "19", "20",
                                         "75", "21", "22",
                                         "23", "24", "80",
                                         "79", "25", "26",
                                         "27", "28", "78",
                                         "29", "30", "31",
                                         "32", "33", "34",
                                         "35", "36", "37",
                                         "38", "83", "84",
                                         "40", "85", "41",
                                         "42", "43", "39",
                                         "44", "46", "47",
                                         "51", "48", "45",
                                         "49", "50", "52",
                                         "53", "54", "55",
                                         "56", "57", "58",
                                         "59", "60", "62",
                                         "63", "61", "64",
                                         "65", "66", "67",
                                         "68", "69", "70",
                                         "71", "72", "00",
                                         "82", "73", "86",
                                         "76"]},
                "timezone_option": {"required": False, "type": "str",
                                    "choices": ["disable", "default", "specify"]},
                "vci_match": {"required": False, "type": "str",
                              "choices": ["disable", "enable"]},
                "vci_string": {"required": False, "type": "list",
                               "options": {
                                   "vci_string": {"required": False, "type": "str"}
                               }},
                "wifi_ac1": {"required": False, "type": "str"},
                "wifi_ac2": {"required": False, "type": "str"},
                "wifi_ac3": {"required": False, "type": "str"},
                "wins_server1": {"required": False, "type": "str"},
                "wins_server2": {"required": False, "type": "str"}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)

            is_error, has_changed, result = fortios_system_dhcp(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_system_dhcp(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
