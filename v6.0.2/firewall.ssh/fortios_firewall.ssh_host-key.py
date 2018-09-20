#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.basic import AnsibleModule
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
module: fortios_firewall.ssh_host-key
short_description: SSH proxy host public keys.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure firewall.ssh feature and host-key category.
      Examples includes all options and need to be adjusted to datasources before usage.
      Tested with FOS: v6.0.2
version_added: "2.6"
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
        default: "root"
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS
              protocol
    firewall.ssh_host-key:
        description:
            - SSH proxy host public keys.
        default: null
        suboptions:
            hostname:
                description:
                    - Hostname of the SSH server.
            ip:
                description:
                    - IP address of the SSH server.
            name:
                description:
                    - SSH public key name.
                required: true
            nid:
                description:
                    - Set the nid of the ECDSA key.
                choices:
                    - 256
                    - 384
                    - 521
            port:
                description:
                    - Port of the SSH server.
            public-key:
                description:
                    - SSH public key.
            status:
                description:
                    - Set the trust status of the public key.
                choices:
                    - trusted
                    - revoked
            type:
                description:
                    - Set the type of the public key.
                choices:
                    - RSA
                    - DSA
                    - ECDSA
                    - ED25519
                    - RSA-CA
                    - DSA-CA
                    - ECDSA-CA
                    - ED25519-CA
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: SSH proxy host public keys.
    fortios_firewall.ssh_host-key:
      host:  "{{  host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      firewall.ssh_host-key:
        state: "present"
        hostname: "myhostname"
        ip: "<your_own_value>"
        name: "default_name_5"
        nid: "256"
        port: "7"
        public-key: "<your_own_value>"
        status: "trusted"
        type: "RSA"
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


def filter_firewall.ssh_host-key_data(json):
    option_list = ['hostname', 'ip', 'name',
                   'nid', 'port', 'public-key',
                   'status', 'type']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def firewall.ssh_host-key(data, fos):
    vdom = data['vdom']
    firewall.ssh_host-key_data = data['firewall.ssh_host-key']
    filtered_data = filter_firewall.ssh_host - \
        key_data(firewall.ssh_host-key_data)

    if firewall.ssh_host-key_data['state'] == "present":
        return fos.set('firewall.ssh',
                       'host-key',
                       data=filtered_data,
                       vdom=vdom)

    elif firewall.ssh_host-key_data['state'] == "absent":
        return fos.delete('firewall.ssh',
                          'host-key',
                          mkey=filtered_data['id'],
                          vdom=vdom)


def fortios_firewall.ssh(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    fos.https('off')
    fos.login(host, username, password)

    methodlist = ['firewall.ssh_host-key']
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
        "https": {"required": False, "type": "bool", "default": "True"},
        "firewall.ssh_host-key": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str"},
                "hostname": {"required": False, "type": "str"},
                "ip": {"required": False, "type": "ipv4-address-any"},
                "name": {"required": True, "type": "str"},
                "nid": {"required": False, "type": "str",
                        "choices": ["256", "384", "521"]},
                "port": {"required": False, "type": "int"},
                "public-key": {"required": False, "type": "str"},
                "status": {"required": False, "type": "str",
                           "choices": ["trusted", "revoked"]},
                "type": {"required": False, "type": "str",
                         "choices": ["RSA", "DSA", "ECDSA",
                                     "ED25519", "RSA-CA", "DSA-CA",
                                     "ECDSA-CA", "ED25519-CA"]}

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

    is_error, has_changed, result = fortios_firewall.ssh(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
