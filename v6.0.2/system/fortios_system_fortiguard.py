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
module: fortios_system_fortiguard
short_description: Configure FortiGuard services in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and fortiguard category.
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
    system_fortiguard:
        description:
            - Configure FortiGuard services.
        default: null
        suboptions:
            antispam-cache:
                description:
                    - Enable/disable FortiGuard antispam request caching. Uses a small amount of memory but improves performance.
                choices:
                    - enable
                    - disable
            antispam-cache-mpercent:
                description:
                    - Maximum percent of FortiGate memory the antispam cache is allowed to use (1 - 15%).
            antispam-cache-ttl:
                description:
                    - Time-to-live for antispam cache entries in seconds (300 - 86400). Lower times reduce the cache size. Higher times may improve
                       performance since the cache will have more entries.
            antispam-expiration:
                description:
                    - Expiration date of the FortiGuard antispam contract.
            antispam-force-off:
                description:
                    - Enable/disable turning off the FortiGuard antispam service.
                choices:
                    - enable
                    - disable
            antispam-license:
                description:
                    - Interval of time between license checks for the FortiGuard antispam contract.
            antispam-timeout:
                description:
                    - Antispam query time out (1 - 30 sec, default = 7).
            auto-join-forticloud:
                description:
                    - Automatically connect to and login to FortiCloud.
                choices:
                    - enable
                    - disable
            ddns-server-ip:
                description:
                    - IP address of the FortiDDNS server.
            ddns-server-port:
                description:
                    - Port used to communicate with FortiDDNS servers.
            load-balance-servers:
                description:
                    - Number of servers to alternate between as first FortiGuard option.
            outbreak-prevention-cache:
                description:
                    - Enable/disable FortiGuard Virus Outbreak Prevention cache.
                choices:
                    - enable
                    - disable
            outbreak-prevention-cache-mpercent:
                description:
                    - Maximum percent of memory FortiGuard Virus Outbreak Prevention cache can use (1 - 15%, default = 2).
            outbreak-prevention-cache-ttl:
                description:
                    - Time-to-live for FortiGuard Virus Outbreak Prevention cache entries (300 - 86400 sec, default = 300).
            outbreak-prevention-expiration:
                description:
                    - Expiration date of FortiGuard Virus Outbreak Prevention contract.
            outbreak-prevention-force-off:
                description:
                    - Turn off FortiGuard Virus Outbreak Prevention service.
                choices:
                    - enable
                    - disable
            outbreak-prevention-license:
                description:
                    - Interval of time between license checks for FortiGuard Virus Outbreak Prevention contract.
            outbreak-prevention-timeout:
                description:
                    - FortiGuard Virus Outbreak Prevention time out (1 - 30 sec, default = 7).
            port:
                description:
                    - Port used to communicate with the FortiGuard servers.
                choices:
                    - 53
                    - 8888
                    - 80
            sdns-server-ip:
                description:
                    - IP address of the FortiDNS server.
            sdns-server-port:
                description:
                    - Port used to communicate with FortiDNS servers.
            service-account-id:
                description:
                    - Service account ID.
            source-ip:
                description:
                    - Source IPv4 address used to communicate with FortiGuard.
            source-ip6:
                description:
                    - Source IPv6 address used to communicate with FortiGuard.
            update-server-location:
                description:
                    - Signature update server location.
                choices:
                    - usa
                    - any
            webfilter-cache:
                description:
                    - Enable/disable FortiGuard web filter caching.
                choices:
                    - enable
                    - disable
            webfilter-cache-ttl:
                description:
                    - Time-to-live for web filter cache entries in seconds (300 - 86400).
            webfilter-expiration:
                description:
                    - Expiration date of the FortiGuard web filter contract.
            webfilter-force-off:
                description:
                    - Enable/disable turning off the FortiGuard web filtering service.
                choices:
                    - enable
                    - disable
            webfilter-license:
                description:
                    - Interval of time between license checks for the FortiGuard web filter contract.
            webfilter-timeout:
                description:
                    - Web filter query time out (1 - 30 sec, default = 7).
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure FortiGuard services.
    fortios_system_fortiguard:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_fortiguard:
        antispam-cache: "enable"
        antispam-cache-mpercent: "4"
        antispam-cache-ttl: "5"
        antispam-expiration: "6"
        antispam-force-off: "enable"
        antispam-license: "8"
        antispam-timeout: "9"
        auto-join-forticloud: "enable"
        ddns-server-ip: "<your_own_value>"
        ddns-server-port: "12"
        load-balance-servers: "13"
        outbreak-prevention-cache: "enable"
        outbreak-prevention-cache-mpercent: "15"
        outbreak-prevention-cache-ttl: "16"
        outbreak-prevention-expiration: "17"
        outbreak-prevention-force-off: "enable"
        outbreak-prevention-license: "19"
        outbreak-prevention-timeout: "20"
        port: "53"
        sdns-server-ip: "<your_own_value>"
        sdns-server-port: "23"
        service-account-id: "<your_own_value>"
        source-ip: "84.230.14.43"
        source-ip6: "<your_own_value>"
        update-server-location: "usa"
        webfilter-cache: "enable"
        webfilter-cache-ttl: "29"
        webfilter-expiration: "30"
        webfilter-force-off: "enable"
        webfilter-license: "32"
        webfilter-timeout: "33"
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


def filter_system_fortiguard_data(json):
    option_list = ['antispam-cache', 'antispam-cache-mpercent', 'antispam-cache-ttl',
                   'antispam-expiration', 'antispam-force-off', 'antispam-license',
                   'antispam-timeout', 'auto-join-forticloud', 'ddns-server-ip',
                   'ddns-server-port', 'load-balance-servers', 'outbreak-prevention-cache',
                   'outbreak-prevention-cache-mpercent', 'outbreak-prevention-cache-ttl', 'outbreak-prevention-expiration',
                   'outbreak-prevention-force-off', 'outbreak-prevention-license', 'outbreak-prevention-timeout',
                   'port', 'sdns-server-ip', 'sdns-server-port',
                   'service-account-id', 'source-ip', 'source-ip6',
                   'update-server-location', 'webfilter-cache', 'webfilter-cache-ttl',
                   'webfilter-expiration', 'webfilter-force-off', 'webfilter-license',
                   'webfilter-timeout']
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


def system_fortiguard(data, fos):
    vdom = data['vdom']
    system_fortiguard_data = data['system_fortiguard']
    flattened_data = flatten_multilists_attributes(system_fortiguard_data)
    filtered_data = filter_system_fortiguard_data(flattened_data)
    return fos.set('system',
                   'fortiguard',
                   data=filtered_data,
                   vdom=vdom)


def fortios_system(data, fos):
    login(data, fos)

    if data['system_fortiguard']:
        resp = system_fortiguard(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_fortiguard": {
            "required": False, "type": "dict",
            "options": {
                "antispam-cache": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "antispam-cache-mpercent": {"required": False, "type": "int"},
                "antispam-cache-ttl": {"required": False, "type": "int"},
                "antispam-expiration": {"required": False, "type": "int"},
                "antispam-force-off": {"required": False, "type": "str",
                                       "choices": ["enable", "disable"]},
                "antispam-license": {"required": False, "type": "int"},
                "antispam-timeout": {"required": False, "type": "int"},
                "auto-join-forticloud": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "ddns-server-ip": {"required": False, "type": "str"},
                "ddns-server-port": {"required": False, "type": "int"},
                "load-balance-servers": {"required": False, "type": "int"},
                "outbreak-prevention-cache": {"required": False, "type": "str",
                                              "choices": ["enable", "disable"]},
                "outbreak-prevention-cache-mpercent": {"required": False, "type": "int"},
                "outbreak-prevention-cache-ttl": {"required": False, "type": "int"},
                "outbreak-prevention-expiration": {"required": False, "type": "int"},
                "outbreak-prevention-force-off": {"required": False, "type": "str",
                                                  "choices": ["enable", "disable"]},
                "outbreak-prevention-license": {"required": False, "type": "int"},
                "outbreak-prevention-timeout": {"required": False, "type": "int"},
                "port": {"required": False, "type": "str",
                         "choices": ["53", "8888", "80"]},
                "sdns-server-ip": {"required": False, "type": "str"},
                "sdns-server-port": {"required": False, "type": "int"},
                "service-account-id": {"required": False, "type": "str"},
                "source-ip": {"required": False, "type": "str"},
                "source-ip6": {"required": False, "type": "str"},
                "update-server-location": {"required": False, "type": "str",
                                           "choices": ["usa", "any"]},
                "webfilter-cache": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "webfilter-cache-ttl": {"required": False, "type": "int"},
                "webfilter-expiration": {"required": False, "type": "int"},
                "webfilter-force-off": {"required": False, "type": "str",
                                        "choices": ["enable", "disable"]},
                "webfilter-license": {"required": False, "type": "int"},
                "webfilter-timeout": {"required": False, "type": "int"}

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
