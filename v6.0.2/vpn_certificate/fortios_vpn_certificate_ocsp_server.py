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
module: fortios_vpn_certificate_ocsp_server
short_description: OCSP server configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify vpn_certificate feature and ocsp_server category.
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
    vpn_certificate_ocsp_server:
        description:
            - OCSP server configuration.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            cert:
                description:
                    - OCSP server certificate. Source vpn.certificate.remote.name vpn.certificate.ca.name.
            name:
                description:
                    - OCSP server entry name.
                required: true
            secondary-cert:
                description:
                    - Secondary OCSP server certificate. Source vpn.certificate.remote.name vpn.certificate.ca.name.
            secondary-url:
                description:
                    - Secondary OCSP server URL.
            source-ip:
                description:
                    - Source IP address for communications to the OCSP server.
            unavail-action:
                description:
                    - Action when server is unavailable (revoke the certificate or ignore the result of the check).
                choices:
                    - revoke
                    - ignore
            url:
                description:
                    - OCSP server URL.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: OCSP server configuration.
    fortios_vpn_certificate_ocsp_server:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      vpn_certificate_ocsp_server:
        state: "present"
        cert: "<your_own_value> (source vpn.certificate.remote.name vpn.certificate.ca.name)"
        name: "default_name_4"
        secondary-cert: "<your_own_value> (source vpn.certificate.remote.name vpn.certificate.ca.name)"
        secondary-url: "<your_own_value>"
        source-ip: "84.230.14.43"
        unavail-action: "revoke"
        url: "myurl.com"
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


def filter_vpn_certificate_ocsp_server_data(json):
    option_list = ['cert', 'name', 'secondary-cert',
                   'secondary-url', 'source-ip', 'unavail-action',
                   'url']
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


def vpn_certificate_ocsp_server(data, fos):
    vdom = data['vdom']
    vpn_certificate_ocsp_server_data = data['vpn_certificate_ocsp_server']
    flattened_data = flatten_multilists_attributes(vpn_certificate_ocsp_server_data)
    filtered_data = filter_vpn_certificate_ocsp_server_data(flattened_data)
    if vpn_certificate_ocsp_server_data['state'] == "present":
        return fos.set('vpn.certificate',
                       'ocsp-server',
                       data=filtered_data,
                       vdom=vdom)

    elif vpn_certificate_ocsp_server_data['state'] == "absent":
        return fos.delete('vpn.certificate',
                          'ocsp-server',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_vpn_certificate(data, fos):
    login(data, fos)

    if data['vpn_certificate_ocsp_server']:
        resp = vpn_certificate_ocsp_server(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "vpn_certificate_ocsp_server": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "cert": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "secondary-cert": {"required": False, "type": "str"},
                "secondary-url": {"required": False, "type": "str"},
                "source-ip": {"required": False, "type": "str"},
                "unavail-action": {"required": False, "type": "str",
                                   "choices": ["revoke", "ignore"]},
                "url": {"required": False, "type": "str"}

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

    is_error, has_changed, result = fortios_vpn_certificate(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
