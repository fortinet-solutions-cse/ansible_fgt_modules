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
module: fortios_wireless_controller_hotspot20_hs_profile
short_description: Configure hotspot profile in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify wireless_controller_hotspot20 feature and hs_profile category.
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
    wireless_controller_hotspot20_hs_profile:
        description:
            - Configure hotspot profile.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            3gpp-plmn:
                description:
                    - 3GPP PLMN name. Source wireless-controller.hotspot20.anqp-3gpp-cellular.name.
            access-network-asra:
                description:
                    - Enable/disable additional step required for access (ASRA).
                choices:
                    - enable
                    - disable
            access-network-esr:
                description:
                    - Enable/disable emergency services reachable (ESR).
                choices:
                    - enable
                    - disable
            access-network-internet:
                description:
                    - Enable/disable connectivity to the Internet.
                choices:
                    - enable
                    - disable
            access-network-type:
                description:
                    - Access network type.
                choices:
                    - private-network
                    - private-network-with-guest-access
                    - chargeable-public-network
                    - free-public-network
                    - personal-device-network
                    - emergency-services-only-network
                    - test-or-experimental
                    - wildcard
            access-network-uesa:
                description:
                    - Enable/disable unauthenticated emergency service accessible (UESA).
                choices:
                    - enable
                    - disable
            anqp-domain-id:
                description:
                    - ANQP Domain ID (0-65535).
            bss-transition:
                description:
                    - Enable/disable basic service set (BSS) transition Support.
                choices:
                    - enable
                    - disable
            conn-cap:
                description:
                    - Connection capability name. Source wireless-controller.hotspot20.h2qp-conn-capability.name.
            deauth-request-timeout:
                description:
                    - Deauthentication request timeout (in seconds).
            dgaf:
                description:
                    - Enable/disable downstream group-addressed forwarding (DGAF).
                choices:
                    - enable
                    - disable
            domain-name:
                description:
                    - Domain name.
            gas-comeback-delay:
                description:
                    - GAS comeback delay (0 or 100 - 4000 milliseconds, default = 500).
            gas-fragmentation-limit:
                description:
                    - GAS fragmentation limit (512 - 4096, default = 1024).
            hessid:
                description:
                    - Homogeneous extended service set identifier (HESSID).
            ip-addr-type:
                description:
                    - IP address type name. Source wireless-controller.hotspot20.anqp-ip-address-type.name.
            l2tif:
                description:
                    - Enable/disable Layer 2 traffic inspection and filtering.
                choices:
                    - enable
                    - disable
            nai-realm:
                description:
                    - NAI realm list name. Source wireless-controller.hotspot20.anqp-nai-realm.name.
            name:
                description:
                    - Hotspot profile name.
                required: true
            network-auth:
                description:
                    - Network authentication name. Source wireless-controller.hotspot20.anqp-network-auth-type.name.
            oper-friendly-name:
                description:
                    - Operator friendly name. Source wireless-controller.hotspot20.h2qp-operator-name.name.
            osu-provider:
                description:
                    - Manually selected list of OSU provider(s).
                suboptions:
                    name:
                        description:
                            - OSU provider name. Source wireless-controller.hotspot20.h2qp-osu-provider.name.
                        required: true
            osu-ssid:
                description:
                    - Online sign up (OSU) SSID.
            pame-bi:
                description:
                    - Enable/disable Pre-Association Message Exchange BSSID Independent (PAME-BI).
                choices:
                    - disable
                    - enable
            proxy-arp:
                description:
                    - Enable/disable Proxy ARP.
                choices:
                    - enable
                    - disable
            qos-map:
                description:
                    - QoS MAP set ID. Source wireless-controller.hotspot20.qos-map.name.
            roaming-consortium:
                description:
                    - Roaming consortium list name. Source wireless-controller.hotspot20.anqp-roaming-consortium.name.
            venue-group:
                description:
                    - Venue group.
                choices:
                    - unspecified
                    - assembly
                    - business
                    - educational
                    - factory
                    - institutional
                    - mercantile
                    - residential
                    - storage
                    - utility
                    - vehicular
                    - outdoor
            venue-name:
                description:
                    - Venue name. Source wireless-controller.hotspot20.anqp-venue-name.name.
            venue-type:
                description:
                    - Venue type.
                choices:
                    - unspecified
                    - arena
                    - stadium
                    - passenger-terminal
                    - amphitheater
                    - amusement-park
                    - place-of-worship
                    - convention-center
                    - library
                    - museum
                    - restaurant
                    - theater
                    - bar
                    - coffee-shop
                    - zoo-or-aquarium
                    - emergency-center
                    - doctor-office
                    - bank
                    - fire-station
                    - police-station
                    - post-office
                    - professional-office
                    - research-facility
                    - attorney-office
                    - primary-school
                    - secondary-school
                    - university-or-college
                    - factory
                    - hospital
                    - long-term-care-facility
                    - rehab-center
                    - group-home
                    - prison-or-jail
                    - retail-store
                    - grocery-market
                    - auto-service-station
                    - shopping-mall
                    - gas-station
                    - private
                    - hotel-or-motel
                    - dormitory
                    - boarding-house
                    - automobile
                    - airplane
                    - bus
                    - ferry
                    - ship-or-boat
                    - train
                    - motor-bike
                    - muni-mesh-network
                    - city-park
                    - rest-area
                    - traffic-control
                    - bus-stop
                    - kiosk
            wan-metrics:
                description:
                    - WAN metric name. Source wireless-controller.hotspot20.h2qp-wan-metric.name.
            wnm-sleep-mode:
                description:
                    - Enable/disable wireless network management (WNM) sleep mode.
                choices:
                    - enable
                    - disable
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure hotspot profile.
    fortios_wireless_controller_hotspot20_hs_profile:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      wireless_controller_hotspot20_hs_profile:
        state: "present"
        3gpp-plmn: "<your_own_value> (source wireless-controller.hotspot20.anqp-3gpp-cellular.name)"
        access-network-asra: "enable"
        access-network-esr: "enable"
        access-network-internet: "enable"
        access-network-type: "private-network"
        access-network-uesa: "enable"
        anqp-domain-id: "9"
        bss-transition: "enable"
        conn-cap: "<your_own_value> (source wireless-controller.hotspot20.h2qp-conn-capability.name)"
        deauth-request-timeout: "12"
        dgaf: "enable"
        domain-name: "<your_own_value>"
        gas-comeback-delay: "15"
        gas-fragmentation-limit: "16"
        hessid: "<your_own_value>"
        ip-addr-type: "<your_own_value> (source wireless-controller.hotspot20.anqp-ip-address-type.name)"
        l2tif: "enable"
        nai-realm: "<your_own_value> (source wireless-controller.hotspot20.anqp-nai-realm.name)"
        name: "default_name_21"
        network-auth: "<your_own_value> (source wireless-controller.hotspot20.anqp-network-auth-type.name)"
        oper-friendly-name: "<your_own_value> (source wireless-controller.hotspot20.h2qp-operator-name.name)"
        osu-provider:
         -
            name: "default_name_25 (source wireless-controller.hotspot20.h2qp-osu-provider.name)"
        osu-ssid: "<your_own_value>"
        pame-bi: "disable"
        proxy-arp: "enable"
        qos-map: "<your_own_value> (source wireless-controller.hotspot20.qos-map.name)"
        roaming-consortium: "<your_own_value> (source wireless-controller.hotspot20.anqp-roaming-consortium.name)"
        venue-group: "unspecified"
        venue-name: "<your_own_value> (source wireless-controller.hotspot20.anqp-venue-name.name)"
        venue-type: "unspecified"
        wan-metrics: "<your_own_value> (source wireless-controller.hotspot20.h2qp-wan-metric.name)"
        wnm-sleep-mode: "enable"
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


def filter_wireless_controller_hotspot20_hs_profile_data(json):
    option_list = ['3gpp-plmn', 'access-network-asra', 'access-network-esr',
                   'access-network-internet', 'access-network-type', 'access-network-uesa',
                   'anqp-domain-id', 'bss-transition', 'conn-cap',
                   'deauth-request-timeout', 'dgaf', 'domain-name',
                   'gas-comeback-delay', 'gas-fragmentation-limit', 'hessid',
                   'ip-addr-type', 'l2tif', 'nai-realm',
                   'name', 'network-auth', 'oper-friendly-name',
                   'osu-provider', 'osu-ssid', 'pame-bi',
                   'proxy-arp', 'qos-map', 'roaming-consortium',
                   'venue-group', 'venue-name', 'venue-type',
                   'wan-metrics', 'wnm-sleep-mode']
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


def wireless_controller_hotspot20_hs_profile(data, fos):
    vdom = data['vdom']
    wireless_controller_hotspot20_hs_profile_data = data['wireless_controller_hotspot20_hs_profile']
    flattened_data = flatten_multilists_attributes(wireless_controller_hotspot20_hs_profile_data)
    filtered_data = filter_wireless_controller_hotspot20_hs_profile_data(flattened_data)
    if wireless_controller_hotspot20_hs_profile_data['state'] == "present":
        return fos.set('wireless-controller.hotspot20',
                       'hs-profile',
                       data=filtered_data,
                       vdom=vdom)

    elif wireless_controller_hotspot20_hs_profile_data['state'] == "absent":
        return fos.delete('wireless-controller.hotspot20',
                          'hs-profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_wireless_controller_hotspot20(data, fos):
    login(data, fos)

    if data['wireless_controller_hotspot20_hs_profile']:
        resp = wireless_controller_hotspot20_hs_profile(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "wireless_controller_hotspot20_hs_profile": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "3gpp-plmn": {"required": False, "type": "str"},
                "access-network-asra": {"required": False, "type": "str",
                                        "choices": ["enable", "disable"]},
                "access-network-esr": {"required": False, "type": "str",
                                       "choices": ["enable", "disable"]},
                "access-network-internet": {"required": False, "type": "str",
                                            "choices": ["enable", "disable"]},
                "access-network-type": {"required": False, "type": "str",
                                        "choices": ["private-network", "private-network-with-guest-access", "chargeable-public-network",
                                                    "free-public-network", "personal-device-network", "emergency-services-only-network",
                                                    "test-or-experimental", "wildcard"]},
                "access-network-uesa": {"required": False, "type": "str",
                                        "choices": ["enable", "disable"]},
                "anqp-domain-id": {"required": False, "type": "int"},
                "bss-transition": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "conn-cap": {"required": False, "type": "str"},
                "deauth-request-timeout": {"required": False, "type": "int"},
                "dgaf": {"required": False, "type": "str",
                         "choices": ["enable", "disable"]},
                "domain-name": {"required": False, "type": "str"},
                "gas-comeback-delay": {"required": False, "type": "int"},
                "gas-fragmentation-limit": {"required": False, "type": "int"},
                "hessid": {"required": False, "type": "str"},
                "ip-addr-type": {"required": False, "type": "str"},
                "l2tif": {"required": False, "type": "str",
                          "choices": ["enable", "disable"]},
                "nai-realm": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "network-auth": {"required": False, "type": "str"},
                "oper-friendly-name": {"required": False, "type": "str"},
                "osu-provider": {"required": False, "type": "list",
                                 "options": {
                                     "name": {"required": True, "type": "str"}
                                 }},
                "osu-ssid": {"required": False, "type": "str"},
                "pame-bi": {"required": False, "type": "str",
                            "choices": ["disable", "enable"]},
                "proxy-arp": {"required": False, "type": "str",
                              "choices": ["enable", "disable"]},
                "qos-map": {"required": False, "type": "str"},
                "roaming-consortium": {"required": False, "type": "str"},
                "venue-group": {"required": False, "type": "str",
                                "choices": ["unspecified", "assembly", "business",
                                            "educational", "factory", "institutional",
                                            "mercantile", "residential", "storage",
                                            "utility", "vehicular", "outdoor"]},
                "venue-name": {"required": False, "type": "str"},
                "venue-type": {"required": False, "type": "str",
                               "choices": ["unspecified", "arena", "stadium",
                                           "passenger-terminal", "amphitheater", "amusement-park",
                                           "place-of-worship", "convention-center", "library",
                                           "museum", "restaurant", "theater",
                                           "bar", "coffee-shop", "zoo-or-aquarium",
                                           "emergency-center", "doctor-office", "bank",
                                           "fire-station", "police-station", "post-office",
                                           "professional-office", "research-facility", "attorney-office",
                                           "primary-school", "secondary-school", "university-or-college",
                                           "factory", "hospital", "long-term-care-facility",
                                           "rehab-center", "group-home", "prison-or-jail",
                                           "retail-store", "grocery-market", "auto-service-station",
                                           "shopping-mall", "gas-station", "private",
                                           "hotel-or-motel", "dormitory", "boarding-house",
                                           "automobile", "airplane", "bus",
                                           "ferry", "ship-or-boat", "train",
                                           "motor-bike", "muni-mesh-network", "city-park",
                                           "rest-area", "traffic-control", "bus-stop",
                                           "kiosk"]},
                "wan-metrics": {"required": False, "type": "str"},
                "wnm-sleep-mode": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]}

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

    is_error, has_changed, result = fortios_wireless_controller_hotspot20(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
