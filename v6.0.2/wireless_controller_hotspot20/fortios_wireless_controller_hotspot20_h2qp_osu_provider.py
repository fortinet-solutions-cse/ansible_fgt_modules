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
module: fortios_wireless_controller_hotspot20_h2qp_osu_provider
short_description: Configure online sign up (OSU) provider list in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure wireless_controller_hotspot20 feature and h2qp_osu_provider category.
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
    wireless_controller_hotspot20_h2qp_osu_provider:
        description:
            - Configure online sign up (OSU) provider list.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            friendly-name:
                description:
                    - OSU provider friendly name.
                suboptions:
                    friendly-name:
                        description:
                            - OSU provider friendly name.
                    index:
                        description:
                            - OSU provider friendly name index.
                        required: true
                    lang:
                        description:
                            - Language code.
            icon:
                description:
                    - OSU provider icon. Source wireless-controller.hotspot20.icon.name.
            name:
                description:
                    - OSU provider ID.
                required: true
            osu-method:
                description:
                    - OSU method list.
                choices:
                    - oma-dm
                    - soap-xml-spp
                    - reserved
            osu-nai:
                description:
                    - OSU NAI.
            server-uri:
                description:
                    - Server URI.
            service-description:
                description:
                    - OSU service name.
                suboptions:
                    lang:
                        description:
                            - Language code.
                    service-description:
                        description:
                            - Service description.
                    service-id:
                        description:
                            - OSU service ID.
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
  - name: Configure online sign up (OSU) provider list.
    fortios_wireless_controller_hotspot20_h2qp_osu_provider:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      wireless_controller_hotspot20_h2qp_osu_provider:
        state: "present"
        friendly-name:
         -
            friendly-name: "<your_own_value>"
            index: "5"
            lang: "<your_own_value>"
        icon: "<your_own_value> (source wireless-controller.hotspot20.icon.name)"
        name: "default_name_8"
        osu-method: "oma-dm"
        osu-nai: "<your_own_value>"
        server-uri: "<your_own_value>"
        service-description:
         -
            lang: "<your_own_value>"
            service-description: "<your_own_value>"
            service-id: "15"
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


def filter_wireless_controller_hotspot20_h2qp_osu_provider_data(json):
    option_list = ['friendly-name', 'icon', 'name',
                   'osu-method', 'osu-nai', 'server-uri',
                   'service-description']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def wireless_controller_hotspot20_h2qp_osu_provider(data, fos):
    vdom = data['vdom']
    wireless_controller_hotspot20_h2qp_osu_provider_data = data['wireless_controller_hotspot20_h2qp_osu_provider']
    filtered_data = filter_wireless_controller_hotspot20_h2qp_osu_provider_data(wireless_controller_hotspot20_h2qp_osu_provider_data)
    if wireless_controller_hotspot20_h2qp_osu_provider_data['state'] == "present":
        return fos.set('wireless-controller.hotspot20',
                       'h2qp-osu-provider',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless_controller_hotspot20_h2qp_osu_provider_data['state'] == "absent":
        return fos.delete('wireless-controller.hotspot20',
                          'h2qp-osu-provider',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_wireless_controller_hotspot20(data, fos):
    login(data)

    methodlist = ['wireless_controller_hotspot20_h2qp_osu_provider']
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
        "wireless_controller_hotspot20_h2qp_osu_provider": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "friendly-name": {"required": False, "type": "list",
                                  "options": {
                                      "friendly-name": {"required": False, "type": "str"},
                                      "index": {"required": True, "type": "int"},
                                      "lang": {"required": False, "type": "str"}
                                  }},
                "icon": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "osu-method": {"required": False, "type": "str",
                               "choices": ["oma-dm", "soap-xml-spp", "reserved"]},
                "osu-nai": {"required": False, "type": "str"},
                "server-uri": {"required": False, "type": "str"},
                "service-description": {"required": False, "type": "list",
                                        "options": {
                                            "lang": {"required": False, "type": "str"},
                                            "service-description": {"required": False, "type": "str"},
                                            "service-id": {"required": True, "type": "int"}
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

    global fos
    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_wireless_controller_hotspot20(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
