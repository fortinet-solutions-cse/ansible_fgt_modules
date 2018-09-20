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
module: fortios_wireless-controller.hotspot20_anqp-nai-realm
short_description: Configure network access identifier (NAI) realm.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure wireless-controller.hotspot20 feature and anqp-nai-realm category.
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
    wireless-controller.hotspot20_anqp-nai-realm:
        description:
            - Configure network access identifier (NAI) realm.
        default: null
        suboptions:
            nai-list:
                description:
                    - NAI list.
                suboptions:
                    eap-method:
                        description:
                            - EAP Methods.
                        suboptions:
                            auth-param:
                                description:
                                    - EAP auth param.
                                choices:
                                suboptions:
                                    id:
                                        description:
                                            - ID of authentication parameter.
                                        required: true
                                        choices:
                                            - non-eap-inner-auth
                                            - inner-auth-eap
                                            - credential
                                            - tunneled-credential
                                    index:
                                        description:
                                            - Param index.
                                    val:
                                        description:
                                            - Value of authentication parameter.
                                        choices:
                                            - eap-identity
                                            - eap-md5
                                            - eap-tls
                                            - eap-ttls
                                            - eap-peap
                                            - eap-sim
                                            - eap-aka
                                            - eap-aka-prime
                                            - non-eap-pap
                                            - non-eap-chap
                                            - non-eap-mschap
                                            - non-eap-mschapv2
                                            - cred-sim
                                            - cred-usim
                                            - cred-nfc
                                            - cred-hardware-token
                                            - cred-softoken
                                            - cred-certificate
                                            - cred-user-pwd
                                            - cred-none
                                            - cred-vendor-specific
                                            - tun-cred-sim
                                            - tun-cred-usim
                                            - tun-cred-nfc
                                            - tun-cred-hardware-token
                                            - tun-cred-softoken
                                            - tun-cred-certificate
                                            - tun-cred-user-pwd
                                            - tun-cred-anonymous
                                            - tun-cred-vendor-specific
                            index:
                                description:
                                    - EAP method index.
                            method:
                                description:
                                    - EAP method type.
                                choices:
                                    - eap-identity
                                    - eap-md5
                                    - eap-tls
                                    - eap-ttls
                                    - eap-peap
                                    - eap-sim
                                    - eap-aka
                                    - eap-aka-prime
                    encoding:
                        description:
                            - Enable/disable format in accordance with IETF RFC 4282.
                        choices:
                            - disable
                            - enable
                    nai-realm:
                        description:
                            - Configure NAI realms (delimited by a semi-colon character).
                    name:
                        description:
                            - NAI realm name.
                        required: true
            name:
                description:
                    - NAI realm list name.
                required: true
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure network access identifier (NAI) realm.
    fortios_wireless-controller.hotspot20_anqp-nai-realm:
      host:  "{{  host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{  vdom }}"
      wireless-controller.hotspot20_anqp-nai-realm:
        state: "present"
        nai-list:
         -
            eap-method:
             -
                auth-param:
                 -
                    id:  "6"
                    index: "7"
                    val: "eap-identity"
                index: "9"
                method: "eap-identity"
            encoding: "disable"
            nai-realm: "<your_own_value>"
            name: "default_name_13"
        name: "default_name_14"
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


def filter_wireless-controller.hotspot20_anqp-nai-realm_data(json):
    option_list = ['nai-list', 'name']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def wireless-controller.hotspot20_anqp-nai-realm(data, fos):
    vdom = data['vdom']
    wireless-controller.hotspot20_anqp-nai-realm_data = data['wireless-controller.hotspot20_anqp-nai-realm']
    filtered_data = filter_wireless-controller.hotspot20_anqp-nai - \
        realm_data(wireless-controller.hotspot20_anqp-nai-realm_data)

    if wireless-controller.hotspot20_anqp-nai-realm_data['state'] == "present":
        return fos.set('wireless-controller.hotspot20',
                       'anqp-nai-realm',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless-controller.hotspot20_anqp-nai-realm_data['state'] == "absent":
        return fos.delete('wireless-controller.hotspot20',
                          'anqp-nai-realm',
                          mkey=filtered_data['id'],
                          vdom=vdom)


def fortios_wireless-controller.hotspot20(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    fos.https('off')
    fos.login(host, username, password)

    methodlist = ['wireless-controller.hotspot20_anqp-nai-realm']
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
        "wireless-controller.hotspot20_anqp-nai-realm": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str"},
                "nai-list": {"required": False, "type": "list",
                             "options": {
                                 "eap-method": {"required": False, "type": "list",
                                                "options": {
                                                    "auth-param": {"required": False, "type": "str",
                                                                   "choices": [],
                                                                   "options": {
                                                                       "id": {"required": True, "type": "str",
                                                                              "choices": ["non-eap-inner-auth", "inner-auth-eap", "credential",
                                                                                          "tunneled-credential"]},
                                                                       "index": {"required": False, "type": "int"},
                                                                       "val": {"required": False, "type": "str",
                                                                               "choices": ["eap-identity", "eap-md5", "eap-tls",
                                                                                           "eap-ttls", "eap-peap", "eap-sim",
                                                                                           "eap-aka", "eap-aka-prime", "non-eap-pap",
                                                                                           "non-eap-chap", "non-eap-mschap", "non-eap-mschapv2",
                                                                                           "cred-sim", "cred-usim", "cred-nfc",
                                                                                           "cred-hardware-token", "cred-softoken", "cred-certificate",
                                                                                           "cred-user-pwd", "cred-none", "cred-vendor-specific",
                                                                                           "tun-cred-sim", "tun-cred-usim", "tun-cred-nfc",
                                                                                           "tun-cred-hardware-token", "tun-cred-softoken", "tun-cred-certificate",
                                                                                           "tun-cred-user-pwd", "tun-cred-anonymous", "tun-cred-vendor-specific"]}
                                                                   }},
                                                    "index": {"required": False, "type": "int"},
                                                    "method": {"required": False, "type": "str",
                                                               "choices": ["eap-identity", "eap-md5", "eap-tls",
                                                                           "eap-ttls", "eap-peap", "eap-sim",
                                                                           "eap-aka", "eap-aka-prime"]}
                                                }},
                                 "encoding": {"required": False, "type": "str",
                                              "choices": ["disable", "enable"]},
                                 "nai-realm": {"required": False, "type": "str"},
                                 "name": {"required": True, "type": "str"}
                             }},
                "name": {"required": True, "type": "str"}

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

    is_error, has_changed, result = fortios_wireless - \
        controller.hotspot20(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
