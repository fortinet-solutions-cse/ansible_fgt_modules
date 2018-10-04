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
module: fortios_certificate_local
short_description: Local keys and certificates.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure certificate feature and local category.
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
    certificate_local:
        description:
            - Local keys and certificates.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            auto-regenerate-days:
                description:
                    - Number of days to wait before expiry of an updated local certificate is requested (0 = disabled).
            auto-regenerate-days-warning:
                description:
                    - Number of days to wait before an expiry warning message is generated (0 = disabled).
            ca-identifier:
                description:
                    - CA identifier of the CA server for signing via SCEP.
            certificate:
                description:
                    - PEM format certificate.
            cmp-path:
                description:
                    - Path location inside CMP server.
            cmp-regeneration-method:
                description:
                    - CMP auto-regeneration method.
                choices:
                    - keyupate
                    - renewal
            cmp-server:
                description:
                    - "'ADDRESS:PORT' for CMP server."
            cmp-server-cert:
                description:
                    - CMP server certificate. Source certificate.ca.name.
            comments:
                description:
                    - Comment.
            csr:
                description:
                    - Certificate Signing Request.
            enroll-protocol:
                description:
                    - Certificate enrollment protocol.
                choices:
                    - none
                    - scep
                    - cmpv2
            ike-localid:
                description:
                    - Local ID the FortiGate uses for authentication as a VPN client.
            ike-localid-type:
                description:
                    - IKE local ID type.
                choices:
                    - asn1dn
                    - fqdn
            last-updated:
                description:
                    - Time at which certificate was last updated.
            name:
                description:
                    - Name.
                required: true
            name-encoding:
                description:
                    - Name encoding method for auto-regeneration.
                choices:
                    - printable
                    - utf8
            password:
                description:
                    - Password as a PEM file.
            private-key:
                description:
                    - PEM format key, encrypted with a password.
            range:
                description:
                    - Either a global or VDOM IP address range for the certificate.
                choices:
                    - global
                    - vdom
            scep-password:
                description:
                    - SCEP server challenge password for auto-regeneration.
            scep-url:
                description:
                    - SCEP server URL.
            source:
                description:
                    - Certificate source type.
                choices:
                    - factory
                    - user
                    - bundle
                    - fortiguard
            source-ip:
                description:
                    - Source IP address for communications to the SCEP server.
            state:
                description:
                    - Certificate Signing Request State.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Local keys and certificates.
    fortios_certificate_local:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      certificate_local:
        state: "present"
        auto-regenerate-days: "3"
        auto-regenerate-days-warning: "4"
        ca-identifier:  "myId_5"
        certificate: "<your_own_value>"
        cmp-path: "<your_own_value>"
        cmp-regeneration-method: "keyupate"
        cmp-server: "<your_own_value>"
        cmp-server-cert: "<your_own_value> (source certificate.ca.name)"
        comments: "<your_own_value>"
        csr: "<your_own_value>"
        enroll-protocol: "none"
        ike-localid: "<your_own_value>"
        ike-localid-type: "asn1dn"
        last-updated: "16"
        name: "default_name_17"
        name-encoding: "printable"
        password: "<your_own_value>"
        private-key: "<your_own_value>"
        range: "global"
        scep-password: "<your_own_value>"
        scep-url: "<your_own_value>"
        source: "factory"
        source-ip: "84.230.14.43"
        state: "<your_own_value>"
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


def filter_certificate_local_data(json):
    option_list = ['auto-regenerate-days', 'auto-regenerate-days-warning', 'ca-identifier',
                   'certificate', 'cmp-path', 'cmp-regeneration-method',
                   'cmp-server', 'cmp-server-cert', 'comments',
                   'csr', 'enroll-protocol', 'ike-localid',
                   'ike-localid-type', 'last-updated', 'name',
                   'name-encoding', 'password', 'private-key',
                   'range', 'scep-password', 'scep-url',
                   'source', 'source-ip', 'state']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def certificate_local(data, fos):
    vdom = data['vdom']
    certificate_local_data = data['certificate_local']
    filtered_data = filter_certificate_local_data(certificate_local_data)
    if certificate_local_data['state'] == "present":
        return fos.set('certificate',
                       'local',
                       data=filtered_data,
                       vdom=vdom)

    elif certificate_local_data['state'] == "absent":
        return fos.delete('certificate',
                          'local',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_certificate(data, fos):
    login(data)

    methodlist = ['certificate_local']
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
        "certificate_local": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "auto-regenerate-days": {"required": False, "type": "int"},
                "auto-regenerate-days-warning": {"required": False, "type": "int"},
                "ca-identifier": {"required": False, "type": "str"},
                "certificate": {"required": False, "type": "str"},
                "cmp-path": {"required": False, "type": "str"},
                "cmp-regeneration-method": {"required": False, "type": "str",
                                            "choices": ["keyupate", "renewal"]},
                "cmp-server": {"required": False, "type": "str"},
                "cmp-server-cert": {"required": False, "type": "str"},
                "comments": {"required": False, "type": "str"},
                "csr": {"required": False, "type": "str"},
                "enroll-protocol": {"required": False, "type": "str",
                                    "choices": ["none", "scep", "cmpv2"]},
                "ike-localid": {"required": False, "type": "str"},
                "ike-localid-type": {"required": False, "type": "str",
                                     "choices": ["asn1dn", "fqdn"]},
                "last-updated": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "name-encoding": {"required": False, "type": "str",
                                  "choices": ["printable", "utf8"]},
                "password": {"required": False, "type": "str"},
                "private-key": {"required": False, "type": "str"},
                "range": {"required": False, "type": "str",
                          "choices": ["global", "vdom"]},
                "scep-password": {"required": False, "type": "str"},
                "scep-url": {"required": False, "type": "str"},
                "source": {"required": False, "type": "str",
                           "choices": ["factory", "user", "bundle",
                                       "fortiguard"]},
                "source-ip": {"required": False, "type": "str"},
                "state": {"required": False, "type": "str"}

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

    is_error, has_changed, result = fortios_certificate(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
