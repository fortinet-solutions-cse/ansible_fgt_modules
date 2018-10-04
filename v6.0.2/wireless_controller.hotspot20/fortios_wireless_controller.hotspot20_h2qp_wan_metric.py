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
module: fortios_wireless_controller.hotspot20_h2qp_wan_metric
short_description: Configure WAN metrics.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure wireless_controller.hotspot20 feature and h2qp_wan_metric category.
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
    wireless_controller.hotspot20_h2qp_wan_metric:
        description:
            - Configure WAN metrics.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            downlink-load:
                description:
                    - Downlink load.
            downlink-speed:
                description:
                    - Downlink speed (in kilobits/s).
            link-at-capacity:
                description:
                    - Link at capacity.
                choices:
                    - enable
                    - disable
            link-status:
                description:
                    - Link status.
                choices:
                    - up
                    - down
                    - in-test
            load-measurement-duration:
                description:
                    - Load measurement duration (in tenths of a second).
            name:
                description:
                    - WAN metric name.
                required: true
            symmetric-wan-link:
                description:
                    - WAN link symmetry.
                choices:
                    - symmetric
                    - asymmetric
            uplink-load:
                description:
                    - Uplink load.
            uplink-speed:
                description:
                    - Uplink speed (in kilobits/s).
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure WAN metrics.
    fortios_wireless_controller.hotspot20_h2qp_wan_metric:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      wireless_controller.hotspot20_h2qp_wan_metric:
        state: "present"
        downlink-load: "3"
        downlink-speed: "4"
        link-at-capacity: "enable"
        link-status: "up"
        load-measurement-duration: "7"
        name: "default_name_8"
        symmetric-wan-link: "symmetric"
        uplink-load: "10"
        uplink-speed: "11"
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


def filter_wireless_controller.hotspot20_h2qp_wan_metric_data(json):
    option_list = ['downlink-load', 'downlink-speed', 'link-at-capacity',
                   'link-status', 'load-measurement-duration', 'name',
                   'symmetric-wan-link', 'uplink-load', 'uplink-speed']
    dictionary = {}

    for attribute in option_list:
        if attribute in json:
            dictionary[attribute] = json[attribute]

    return dictionary


def wireless_controller.hotspot20_h2qp_wan_metric(data, fos):
    vdom = data['vdom']
    wireless_controller.hotspot20_h2qp_wan_metric_data = data[
        'wireless_controller.hotspot20_h2qp_wan_metric']
    filtered_data = filter_wireless_controller.hotspot20_h2qp_wan_metric_data(
        wireless_controller.hotspot20_h2qp_wan_metric_data)
    if wireless_controller.hotspot20_h2qp_wan_metric_data['state'] == "present":
        return fos.set('wireless-controller.hotspot20',
                       'h2qp-wan-metric',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless_controller.hotspot20_h2qp_wan_metric_data['state'] == "absent":
        return fos.delete('wireless-controller.hotspot20',
                          'h2qp-wan-metric',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_wireless_controller.hotspot20(data, fos):
    login(data)

    methodlist = ['wireless_controller.hotspot20_h2qp_wan_metric']
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
        "wireless_controller.hotspot20_h2qp_wan_metric": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "downlink-load": {"required": False, "type": "int"},
                "downlink-speed": {"required": False, "type": "int"},
                "link-at-capacity": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "link-status": {"required": False, "type": "str",
                                "choices": ["up", "down", "in-test"]},
                "load-measurement-duration": {"required": False, "type": "int"},
                "name": {"required": True, "type": "str"},
                "symmetric-wan-link": {"required": False, "type": "str",
                                       "choices": ["symmetric", "asymmetric"]},
                "uplink-load": {"required": False, "type": "int"},
                "uplink-speed": {"required": False, "type": "int"}

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

    is_error, has_changed, result = fortios_wireless_controller.hotspot20(
        module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
