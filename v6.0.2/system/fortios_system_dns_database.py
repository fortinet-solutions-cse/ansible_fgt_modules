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
module: fortios_system_dns_database
short_description: Configure DNS databases in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure system feature and dns_database category.
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
    system_dns_database:
        description:
            - Configure DNS databases.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            allow-transfer:
                description:
                    - DNS zone transfer IP address list.
            authoritative:
                description:
                    - Enable/disable authoritative zone.
                choices:
                    - enable
                    - disable
            contact:
                description:
                    - Email address of the administrator for this zone.
    		You can specify only the username (e.g. admin) or full email address (e.g. admin@test.com)
    		When using a simple username, the domain of the email will be this zone.
            dns-entry:
                description:
                    - DNS entry.
                suboptions:
                    canonical-name:
                        description:
                            - Canonical name of the host.
                    hostname:
                        description:
                            - Name of the host.
                    id:
                        description:
                            - DNS entry ID.
                        required: true
                    ip:
                        description:
                            - IPv4 address of the host.
                    ipv6:
                        description:
                            - IPv6 address of the host.
                    preference:
                        description:
                            - DNS entry preference, 0 is the highest preference (0 - 65535, default = 10)
                    status:
                        description:
                            - Enable/disable resource record status.
                        choices:
                            - enable
                            - disable
                    ttl:
                        description:
                            - Time-to-live for this entry (0 to 2147483647 sec, default = 0).
                    type:
                        description:
                            - Resource record type.
                        choices:
                            - A
                            - NS
                            - CNAME
                            - MX
                            - AAAA
                            - PTR
                            - PTR_V6
            domain:
                description:
                    - Domain name.
            forwarder:
                description:
                    - DNS zone forwarder IP address list.
            ip-master:
                description:
                    - IP address of master DNS server. Entries in this master DNS server and imported into the DNS zone.
            name:
                description:
                    - Zone name.
                required: true
            primary-name:
                description:
                    - Domain name of the default DNS server for this zone.
            source-ip:
                description:
                    - Source IP for forwarding to DNS server.
            status:
                description:
                    - Enable/disable this DNS zone.
                choices:
                    - enable
                    - disable
            ttl:
                description:
                    - Default time-to-live value for the entries of this DNS zone (0 - 2147483647 sec, default = 86400).
            type:
                description:
                    - Zone type (master to manage entries directly, slave to import entries from other zones).
                choices:
                    - master
                    - slave
            view:
                description:
                    - Zone view (public to serve public clients, shadow to serve internal clients).
                choices:
                    - shadow
                    - public
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure DNS databases.
    fortios_system_dns_database:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      system_dns_database:
        state: "present"
        allow-transfer: "<your_own_value>"
        authoritative: "enable"
        contact: "<your_own_value>"
        dns-entry:
         -
            canonical-name: "<your_own_value>"
            hostname: "myhostname"
            id:  "9"
            ip: "<your_own_value>"
            ipv6: "<your_own_value>"
            preference: "12"
            status: "enable"
            ttl: "14"
            type: "A"
        domain: "<your_own_value>"
        forwarder: "<your_own_value>"
        ip-master: "<your_own_value>"
        name: "default_name_19"
        primary-name: "<your_own_value>"
        source-ip: "84.230.14.43"
        status: "enable"
        ttl: "23"
        type: "master"
        view: "shadow"
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


def filter_system_dns_database_data(json):
    option_list = ['allow-transfer', 'authoritative', 'contact',
                   'dns-entry', 'domain', 'forwarder',
                   'ip-master', 'name', 'primary-name',
                   'source-ip', 'status', 'ttl',
                   'type', 'view']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def system_dns_database(data, fos):
    vdom = data['vdom']
    system_dns_database_data = data['system_dns_database']
    filtered_data = filter_system_dns_database_data(system_dns_database_data)
    if system_dns_database_data['state'] == "present":
        return fos.set('system',
                       'dns-database',
                       data=filtered_data,
                       vdom=vdom)

    elif system_dns_database_data['state'] == "absent":
        return fos.delete('system',
                          'dns-database',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data)

    methodlist = ['system_dns_database']
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
        "system_dns_database": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "allow-transfer": {"required": False, "type": "str"},
                "authoritative": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "contact": {"required": False, "type": "str"},
                "dns-entry": {"required": False, "type": "list",
                              "options": {
                                  "canonical-name": {"required": False, "type": "str"},
                                  "hostname": {"required": False, "type": "str"},
                                  "id": {"required": True, "type": "int"},
                                  "ip": {"required": False, "type": "str"},
                                  "ipv6": {"required": False, "type": "str"},
                                  "preference": {"required": False, "type": "int"},
                                  "status": {"required": False, "type": "str",
                                             "choices": ["enable", "disable"]},
                                  "ttl": {"required": False, "type": "int"},
                                  "type": {"required": False, "type": "str",
                                           "choices": ["A", "NS", "CNAME",
                                                       "MX", "AAAA", "PTR",
                                                       "PTR_V6"]}
                              }},
                "domain": {"required": False, "type": "str"},
                "forwarder": {"required": False, "type": "str"},
                "ip-master": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "primary-name": {"required": False, "type": "str"},
                "source-ip": {"required": False, "type": "str"},
                "status": {"required": False, "type": "str",
                           "choices": ["enable", "disable"]},
                "ttl": {"required": False, "type": "int"},
                "type": {"required": False, "type": "str",
                         "choices": ["master", "slave"]},
                "view": {"required": False, "type": "str",
                         "choices": ["shadow", "public"]}

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
