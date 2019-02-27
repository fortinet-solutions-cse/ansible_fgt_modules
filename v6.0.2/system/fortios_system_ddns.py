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
module: fortios_system_ddns
short_description: Configure DDNS in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and ddns category.
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
    system_ddns:
        description:
            - Configure DDNS.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            bound-ip:
                description:
                    - Bound IP address.
            clear-text:
                description:
                    - Enable/disable use of clear text connections.
                choices:
                    - disable
                    - enable
            ddns-auth:
                description:
                    - Enable/disable TSIG authentication for your DDNS server.
                choices:
                    - disable
                    - tsig
            ddns-domain:
                description:
                    - Your fully qualified domain name (for example, yourname.DDNS.com).
            ddns-key:
                description:
                    - DDNS update key (base 64 encoding).
            ddns-keyname:
                description:
                    - DDNS update key name.
            ddns-password:
                description:
                    - DDNS password.
            ddns-server:
                description:
                    - Select a DDNS service provider.
                choices:
                    - dyndns.org
                    - dyns.net
                    - tzo.com
                    - vavic.com
                    - dipdns.net
                    - now.net.cn
                    - dhs.org
                    - easydns.com
                    - genericDDNS
                    - FortiGuardDDNS
                    - noip.com
            ddns-server-ip:
                description:
                    - Generic DDNS server IP.
            ddns-sn:
                description:
                    - DDNS Serial Number.
            ddns-ttl:
                description:
                    - Time-to-live for DDNS packets.
            ddns-username:
                description:
                    - DDNS user name.
            ddns-zone:
                description:
                    - Zone of your domain name (for example, DDNS.com).
            ddnsid:
                description:
                    - DDNS ID.
                required: true
            monitor-interface:
                description:
                    - Monitored interface.
                suboptions:
                    interface-name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
            ssl-certificate:
                description:
                    - Name of local certificate for SSL connections. Source certificate.local.name.
            update-interval:
                description:
                    - DDNS update interval (60 - 2592000 sec, default = 300).
            use-public-ip:
                description:
                    - Enable/disable use of public IP address.
                choices:
                    - disable
                    - enable
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure DDNS.
    fortios_system_ddns:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_ddns:
        state: "present"
        bound-ip: "<your_own_value>"
        clear-text: "disable"
        ddns-auth: "disable"
        ddns-domain: "<your_own_value>"
        ddns-key: "<your_own_value>"
        ddns-keyname: "<your_own_value>"
        ddns-password: "<your_own_value>"
        ddns-server: "dyndns.org"
        ddns-server-ip: "<your_own_value>"
        ddns-sn: "<your_own_value>"
        ddns-ttl: "13"
        ddns-username: "<your_own_value>"
        ddns-zone: "<your_own_value>"
        ddnsid: "16"
        monitor-interface:
         -
            interface-name: "<your_own_value> (source system.interface.name)"
        ssl-certificate: "<your_own_value> (source certificate.local.name)"
        update-interval: "20"
        use-public-ip: "disable"
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


def filter_system_ddns_data(json):
    option_list = ['bound-ip', 'clear-text', 'ddns-auth',
                   'ddns-domain', 'ddns-key', 'ddns-keyname',
                   'ddns-password', 'ddns-server', 'ddns-server-ip',
                   'ddns-sn', 'ddns-ttl', 'ddns-username',
                   'ddns-zone', 'ddnsid', 'monitor-interface',
                   'ssl-certificate', 'update-interval', 'use-public-ip']
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


def system_ddns(data, fos):
    vdom = data['vdom']
    system_ddns_data = data['system_ddns']
    flattened_data = flatten_multilists_attributes(system_ddns_data)
    filtered_data = filter_system_ddns_data(flattened_data)
    if system_ddns_data['state'] == "present":
        return fos.set('system',
                       'ddns',
                       data=filtered_data,
                       vdom=vdom)

    elif system_ddns_data['state'] == "absent":
        return fos.delete('system',
                          'ddns',
                          mkey=filtered_data['ddnsid'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data, fos)

    if data['system_ddns']:
        resp = system_ddns(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_ddns": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "bound-ip": {"required": False, "type": "str"},
                "clear-text": {"required": False, "type": "str",
                               "choices": ["disable", "enable"]},
                "ddns-auth": {"required": False, "type": "str",
                              "choices": ["disable", "tsig"]},
                "ddns-domain": {"required": False, "type": "str"},
                "ddns-key": {"required": False, "type": "str"},
                "ddns-keyname": {"required": False, "type": "str"},
                "ddns-password": {"required": False, "type": "str"},
                "ddns-server": {"required": False, "type": "str",
                                "choices": ["dyndns.org", "dyns.net", "tzo.com",
                                            "vavic.com", "dipdns.net", "now.net.cn",
                                            "dhs.org", "easydns.com", "genericDDNS",
                                            "FortiGuardDDNS", "noip.com"]},
                "ddns-server-ip": {"required": False, "type": "str"},
                "ddns-sn": {"required": False, "type": "str"},
                "ddns-ttl": {"required": False, "type": "int"},
                "ddns-username": {"required": False, "type": "str"},
                "ddns-zone": {"required": False, "type": "str"},
                "ddnsid": {"required": True, "type": "int"},
                "monitor-interface": {"required": False, "type": "list",
                                      "options": {
                                          "interface-name": {"required": True, "type": "str"}
                                      }},
                "ssl-certificate": {"required": False, "type": "str"},
                "update-interval": {"required": False, "type": "int"},
                "use-public-ip": {"required": False, "type": "str",
                                  "choices": ["disable", "enable"]}

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

    is_error, has_changed, result = fortios_system(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
