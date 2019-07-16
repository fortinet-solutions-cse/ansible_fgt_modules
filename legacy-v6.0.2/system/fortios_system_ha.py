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
module: fortios_system_ha
short_description: Configure HA in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and ha category.
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
    system_ha:
        description:
            - Configure HA.
        default: null
        suboptions:
            arps:
                description:
                    - Number of gratuitous ARPs (1 - 60). Lower to reduce traffic. Higher to reduce failover time.
            arps-interval:
                description:
                    - Time between gratuitous ARPs  (1 - 20 sec). Lower to reduce failover time. Higher to reduce traffic.
            authentication:
                description:
                    - Enable/disable heartbeat message authentication.
                choices:
                    - enable
                    - disable
            cpu-threshold:
                description:
                    - Dynamic weighted load balancing CPU usage weight and high and low thresholds.
            encryption:
                description:
                    - Enable/disable heartbeat message encryption.
                choices:
                    - enable
                    - disable
            ftp-proxy-threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of FTP proxy sessions.
            gratuitous-arps:
                description:
                    - Enable/disable gratuitous ARPs. Disable if link-failed-signal enabled.
                choices:
                    - enable
                    - disable
            group-id:
                description:
                    - Cluster group ID  (0 - 255). Must be the same for all members.
            group-name:
                description:
                    - Cluster group name. Must be the same for all members.
            ha-direct:
                description:
                    - Enable/disable using ha-mgmt interface for syslog, SNMP, remote authentication (RADIUS), FortiAnalyzer, FortiManager and FortiSandbox.
                choices:
                    - enable
                    - disable
            ha-eth-type:
                description:
                    - HA heartbeat packet Ethertype (4-digit hex).
            ha-mgmt-interfaces:
                description:
                    - Reserve interfaces to manage individual cluster units.
                suboptions:
                    dst:
                        description:
                            - Default route destination for reserved HA management interface.
                    gateway:
                        description:
                            - Default route gateway for reserved HA management interface.
                    gateway6:
                        description:
                            - Default IPv6 gateway for reserved HA management interface.
                    id:
                        description:
                            - Table ID.
                        required: true
                    interface:
                        description:
                            - Interface to reserve for HA management. Source system.interface.name.
            ha-mgmt-status:
                description:
                    - Enable to reserve interfaces to manage individual cluster units.
                choices:
                    - enable
                    - disable
            ha-uptime-diff-margin:
                description:
                    - Normally you would only reduce this value for failover testing.
            hb-interval:
                description:
                    - Time between sending heartbeat packets (1 - 20 (100*ms)). Increase to reduce false positives.
            hb-lost-threshold:
                description:
                    - Number of lost heartbeats to signal a failure (1 - 60). Increase to reduce false positives.
            hbdev:
                description:
                    - Heartbeat interfaces. Must be the same for all members.
            hc-eth-type:
                description:
                    - Transparent mode HA heartbeat packet Ethertype (4-digit hex).
            hello-holddown:
                description:
                    - Time to wait before changing from hello to work state (5 - 300 sec).
            http-proxy-threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of HTTP proxy sessions.
            imap-proxy-threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of IMAP proxy sessions.
            inter-cluster-session-sync:
                description:
                    - Enable/disable synchronization of sessions among HA clusters.
                choices:
                    - enable
                    - disable
            key:
                description:
                    - key
            l2ep-eth-type:
                description:
                    - Telnet session HA heartbeat packet Ethertype (4-digit hex).
            link-failed-signal:
                description:
                    - Enable to shut down all interfaces for 1 sec after a failover. Use if gratuitous ARPs do not update network.
                choices:
                    - enable
                    - disable
            load-balance-all:
                description:
                    - Enable to load balance TCP sessions. Disable to load balance proxy sessions only.
                choices:
                    - enable
                    - disable
            memory-compatible-mode:
                description:
                    - Enable/disable memory compatible mode.
                choices:
                    - enable
                    - disable
            memory-threshold:
                description:
                    - Dynamic weighted load balancing memory usage weight and high and low thresholds.
            mode:
                description:
                    - HA mode. Must be the same for all members. FGSP requires standalone.
                choices:
                    - standalone
                    - a-a
                    - a-p
            monitor:
                description:
                    - Interfaces to check for port monitoring (or link failure). Source system.interface.name.
            multicast-ttl:
                description:
                    - HA multicast TTL on master (5 - 3600 sec).
            nntp-proxy-threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of NNTP proxy sessions.
            override:
                description:
                    - Enable and increase the priority of the unit that should always be primary (master).
                choices:
                    - enable
                    - disable
            override-wait-time:
                description:
                    - Delay negotiating if override is enabled (0 - 3600 sec). Reduces how often the cluster negotiates.
            password:
                description:
                    - Cluster password. Must be the same for all members.
            pingserver-failover-threshold:
                description:
                    - Remote IP monitoring failover threshold (0 - 50).
            pingserver-flip-timeout:
                description:
                    - Time to wait in minutes before renegotiating after a remote IP monitoring failover.
            pingserver-monitor-interface:
                description:
                    - Interfaces to check for remote IP monitoring. Source system.interface.name.
            pingserver-slave-force-reset:
                description:
                    - Enable to force the cluster to negotiate after a remote IP monitoring failover.
                choices:
                    - enable
                    - disable
            pop3-proxy-threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of POP3 proxy sessions.
            priority:
                description:
                    - Increase the priority to select the primary unit (0 - 255).
            route-hold:
                description:
                    - Time to wait between routing table updates to the cluster (0 - 3600 sec).
            route-ttl:
                description:
                    - TTL for primary unit routes (5 - 3600 sec). Increase to maintain active routes during failover.
            route-wait:
                description:
                    - Time to wait before sending new routes to the cluster (0 - 3600 sec).
            schedule:
                description:
                    - Type of A-A load balancing. Use none if you have external load balancers.
                choices:
                    - none
                    - hub
                    - leastconnection
                    - round-robin
                    - weight-round-robin
                    - random
                    - ip
                    - ipport
            secondary-vcluster:
                description:
                    - Configure virtual cluster 2.
                suboptions:
                    monitor:
                        description:
                            - Interfaces to check for port monitoring (or link failure). Source system.interface.name.
                    override:
                        description:
                            - Enable and increase the priority of the unit that should always be primary (master).
                        choices:
                            - enable
                            - disable
                    override-wait-time:
                        description:
                            - Delay negotiating if override is enabled (0 - 3600 sec). Reduces how often the cluster negotiates.
                    pingserver-failover-threshold:
                        description:
                            - Remote IP monitoring failover threshold (0 - 50).
                    pingserver-monitor-interface:
                        description:
                            - Interfaces to check for remote IP monitoring. Source system.interface.name.
                    pingserver-slave-force-reset:
                        description:
                            - Enable to force the cluster to negotiate after a remote IP monitoring failover.
                        choices:
                            - enable
                            - disable
                    priority:
                        description:
                            - Increase the priority to select the primary unit (0 - 255).
                    vcluster-id:
                        description:
                            - Cluster ID.
                    vdom:
                        description:
                            - VDOMs in virtual cluster 2.
            session-pickup:
                description:
                    - Enable/disable session pickup. Enabling it can reduce session down time when fail over happens.
                choices:
                    - enable
                    - disable
            session-pickup-connectionless:
                description:
                    - Enable/disable UDP and ICMP session sync for FGSP.
                choices:
                    - enable
                    - disable
            session-pickup-delay:
                description:
                    - Enable to sync sessions longer than 30 sec. Only longer lived sessions need to be synced.
                choices:
                    - enable
                    - disable
            session-pickup-expectation:
                description:
                    - Enable/disable session helper expectation session sync for FGSP.
                choices:
                    - enable
                    - disable
            session-pickup-nat:
                description:
                    - Enable/disable NAT session sync for FGSP.
                choices:
                    - enable
                    - disable
            session-sync-dev:
                description:
                    - Offload session sync to one or more interfaces to distribute traffic and prevent delays if needed. Source system.interface.name.
            smtp-proxy-threshold:
                description:
                    - Dynamic weighted load balancing weight and high and low number of SMTP proxy sessions.
            standalone-config-sync:
                description:
                    - Enable/disable FGSP configuration synchronization.
                choices:
                    - enable
                    - disable
            standalone-mgmt-vdom:
                description:
                    - Enable/disable standalone management VDOM.
                choices:
                    - enable
                    - disable
            sync-config:
                description:
                    - Enable/disable configuration synchronization.
                choices:
                    - enable
                    - disable
            sync-packet-balance:
                description:
                    - Enable/disable HA packet distribution to multiple CPUs.
                choices:
                    - enable
                    - disable
            unicast-hb:
                description:
                    - Enable/disable unicast heartbeat.
                choices:
                    - enable
                    - disable
            unicast-hb-netmask:
                description:
                    - Unicast heartbeat netmask.
            unicast-hb-peerip:
                description:
                    - Unicast heartbeat peer IP.
            uninterruptible-upgrade:
                description:
                    - Enable to upgrade a cluster without blocking network traffic.
                choices:
                    - enable
                    - disable
            vcluster-id:
                description:
                    - Cluster ID.
            vcluster2:
                description:
                    - Enable/disable virtual cluster 2 for virtual clustering.
                choices:
                    - enable
                    - disable
            vdom:
                description:
                    - VDOMs in virtual cluster 1.
            weight:
                description:
                    - Weight-round-robin weight for each cluster unit. Syntax <priority> <weight>.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure HA.
    fortios_system_ha:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_ha:
        arps: "3"
        arps-interval: "4"
        authentication: "enable"
        cpu-threshold: "<your_own_value>"
        encryption: "enable"
        ftp-proxy-threshold: "<your_own_value>"
        gratuitous-arps: "enable"
        group-id: "10"
        group-name: "<your_own_value>"
        ha-direct: "enable"
        ha-eth-type: "<your_own_value>"
        ha-mgmt-interfaces:
         -
            dst: "<your_own_value>"
            gateway: "<your_own_value>"
            gateway6: "<your_own_value>"
            id:  "18"
            interface: "<your_own_value> (source system.interface.name)"
        ha-mgmt-status: "enable"
        ha-uptime-diff-margin: "21"
        hb-interval: "22"
        hb-lost-threshold: "23"
        hbdev: "<your_own_value>"
        hc-eth-type: "<your_own_value>"
        hello-holddown: "26"
        http-proxy-threshold: "<your_own_value>"
        imap-proxy-threshold: "<your_own_value>"
        inter-cluster-session-sync: "enable"
        key: "<your_own_value>"
        l2ep-eth-type: "<your_own_value>"
        link-failed-signal: "enable"
        load-balance-all: "enable"
        memory-compatible-mode: "enable"
        memory-threshold: "<your_own_value>"
        mode: "standalone"
        monitor: "<your_own_value> (source system.interface.name)"
        multicast-ttl: "38"
        nntp-proxy-threshold: "<your_own_value>"
        override: "enable"
        override-wait-time: "41"
        password: "<your_own_value>"
        pingserver-failover-threshold: "43"
        pingserver-flip-timeout: "44"
        pingserver-monitor-interface: "<your_own_value> (source system.interface.name)"
        pingserver-slave-force-reset: "enable"
        pop3-proxy-threshold: "<your_own_value>"
        priority: "48"
        route-hold: "49"
        route-ttl: "50"
        route-wait: "51"
        schedule: "none"
        secondary-vcluster:
            monitor: "<your_own_value> (source system.interface.name)"
            override: "enable"
            override-wait-time: "56"
            pingserver-failover-threshold: "57"
            pingserver-monitor-interface: "<your_own_value> (source system.interface.name)"
            pingserver-slave-force-reset: "enable"
            priority: "60"
            vcluster-id: "61"
            vdom: "<your_own_value>"
        session-pickup: "enable"
        session-pickup-connectionless: "enable"
        session-pickup-delay: "enable"
        session-pickup-expectation: "enable"
        session-pickup-nat: "enable"
        session-sync-dev: "<your_own_value> (source system.interface.name)"
        smtp-proxy-threshold: "<your_own_value>"
        standalone-config-sync: "enable"
        standalone-mgmt-vdom: "enable"
        sync-config: "enable"
        sync-packet-balance: "enable"
        unicast-hb: "enable"
        unicast-hb-netmask: "<your_own_value>"
        unicast-hb-peerip: "<your_own_value>"
        uninterruptible-upgrade: "enable"
        vcluster-id: "78"
        vcluster2: "enable"
        vdom: "<your_own_value>"
        weight: "<your_own_value>"
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


def filter_system_ha_data(json):
    option_list = ['arps', 'arps-interval', 'authentication',
                   'cpu-threshold', 'encryption', 'ftp-proxy-threshold',
                   'gratuitous-arps', 'group-id', 'group-name',
                   'ha-direct', 'ha-eth-type', 'ha-mgmt-interfaces',
                   'ha-mgmt-status', 'ha-uptime-diff-margin', 'hb-interval',
                   'hb-lost-threshold', 'hbdev', 'hc-eth-type',
                   'hello-holddown', 'http-proxy-threshold', 'imap-proxy-threshold',
                   'inter-cluster-session-sync', 'key', 'l2ep-eth-type',
                   'link-failed-signal', 'load-balance-all', 'memory-compatible-mode',
                   'memory-threshold', 'mode', 'monitor',
                   'multicast-ttl', 'nntp-proxy-threshold', 'override',
                   'override-wait-time', 'password', 'pingserver-failover-threshold',
                   'pingserver-flip-timeout', 'pingserver-monitor-interface', 'pingserver-slave-force-reset',
                   'pop3-proxy-threshold', 'priority', 'route-hold',
                   'route-ttl', 'route-wait', 'schedule',
                   'secondary-vcluster', 'session-pickup', 'session-pickup-connectionless',
                   'session-pickup-delay', 'session-pickup-expectation', 'session-pickup-nat',
                   'session-sync-dev', 'smtp-proxy-threshold', 'standalone-config-sync',
                   'standalone-mgmt-vdom', 'sync-config', 'sync-packet-balance',
                   'unicast-hb', 'unicast-hb-netmask', 'unicast-hb-peerip',
                   'uninterruptible-upgrade', 'vcluster-id', 'vcluster2',
                   'vdom', 'weight']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def system_ha(data, fos):
    vdom = data['vdom']
    system_ha_data = data['system_ha']
    filtered_data = filter_system_ha_data(system_ha_data)

    return fos.set('system',
                   'ha',
                   data=filtered_data,
                   vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_system(data, fos):
    login(data, fos)

    if data['system_ha']:
        resp = system_ha(data, fos)

    fos.logout()
    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_ha": {
            "required": False, "type": "dict",
            "options": {
                "arps": {"required": False, "type": "int"},
                "arps-interval": {"required": False, "type": "int"},
                "authentication": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "cpu-threshold": {"required": False, "type": "str"},
                "encryption": {"required": False, "type": "str",
                               "choices": ["enable", "disable"]},
                "ftp-proxy-threshold": {"required": False, "type": "str"},
                "gratuitous-arps": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "group-id": {"required": False, "type": "int"},
                "group-name": {"required": False, "type": "str"},
                "ha-direct": {"required": False, "type": "str",
                              "choices": ["enable", "disable"]},
                "ha-eth-type": {"required": False, "type": "str"},
                "ha-mgmt-interfaces": {"required": False, "type": "list",
                                       "options": {
                                           "dst": {"required": False, "type": "str"},
                                           "gateway": {"required": False, "type": "str"},
                                           "gateway6": {"required": False, "type": "str"},
                                           "id": {"required": True, "type": "int"},
                                           "interface": {"required": False, "type": "str"}
                                       }},
                "ha-mgmt-status": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "ha-uptime-diff-margin": {"required": False, "type": "int"},
                "hb-interval": {"required": False, "type": "int"},
                "hb-lost-threshold": {"required": False, "type": "int"},
                "hbdev": {"required": False, "type": "str"},
                "hc-eth-type": {"required": False, "type": "str"},
                "hello-holddown": {"required": False, "type": "int"},
                "http-proxy-threshold": {"required": False, "type": "str"},
                "imap-proxy-threshold": {"required": False, "type": "str"},
                "inter-cluster-session-sync": {"required": False, "type": "str",
                                               "choices": ["enable", "disable"]},
                "key": {"required": False, "type": "str"},
                "l2ep-eth-type": {"required": False, "type": "str"},
                "link-failed-signal": {"required": False, "type": "str",
                                       "choices": ["enable", "disable"]},
                "load-balance-all": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "memory-compatible-mode": {"required": False, "type": "str",
                                           "choices": ["enable", "disable"]},
                "memory-threshold": {"required": False, "type": "str"},
                "mode": {"required": False, "type": "str",
                         "choices": ["standalone", "a-a", "a-p"]},
                "monitor": {"required": False, "type": "str"},
                "multicast-ttl": {"required": False, "type": "int"},
                "nntp-proxy-threshold": {"required": False, "type": "str"},
                "override": {"required": False, "type": "str",
                             "choices": ["enable", "disable"]},
                "override-wait-time": {"required": False, "type": "int"},
                "password": {"required": False, "type": "str"},
                "pingserver-failover-threshold": {"required": False, "type": "int"},
                "pingserver-flip-timeout": {"required": False, "type": "int"},
                "pingserver-monitor-interface": {"required": False, "type": "str"},
                "pingserver-slave-force-reset": {"required": False, "type": "str",
                                                 "choices": ["enable", "disable"]},
                "pop3-proxy-threshold": {"required": False, "type": "str"},
                "priority": {"required": False, "type": "int"},
                "route-hold": {"required": False, "type": "int"},
                "route-ttl": {"required": False, "type": "int"},
                "route-wait": {"required": False, "type": "int"},
                "schedule": {"required": False, "type": "str",
                             "choices": ["none", "hub", "leastconnection",
                                         "round-robin", "weight-round-robin", "random",
                                         "ip", "ipport"]},
                "secondary-vcluster": {"required": False, "type": "dict",
                                       "options": {
                                           "monitor": {"required": False, "type": "str"},
                                           "override": {"required": False, "type": "str",
                                                        "choices": ["enable", "disable"]},
                                           "override-wait-time": {"required": False, "type": "int"},
                                           "pingserver-failover-threshold": {"required": False, "type": "int"},
                                           "pingserver-monitor-interface": {"required": False, "type": "str"},
                                           "pingserver-slave-force-reset": {"required": False, "type": "str",
                                                                            "choices": ["enable", "disable"]},
                                           "priority": {"required": False, "type": "int"},
                                           "vcluster-id": {"required": False, "type": "int"},
                                           "vdom": {"required": False, "type": "str"}
                                       }},
                "session-pickup": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "session-pickup-connectionless": {"required": False, "type": "str",
                                                  "choices": ["enable", "disable"]},
                "session-pickup-delay": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "session-pickup-expectation": {"required": False, "type": "str",
                                               "choices": ["enable", "disable"]},
                "session-pickup-nat": {"required": False, "type": "str",
                                       "choices": ["enable", "disable"]},
                "session-sync-dev": {"required": False, "type": "str"},
                "smtp-proxy-threshold": {"required": False, "type": "str"},
                "standalone-config-sync": {"required": False, "type": "str",
                                           "choices": ["enable", "disable"]},
                "standalone-mgmt-vdom": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "sync-config": {"required": False, "type": "str",
                                "choices": ["enable", "disable"]},
                "sync-packet-balance": {"required": False, "type": "str",
                                        "choices": ["enable", "disable"]},
                "unicast-hb": {"required": False, "type": "str",
                               "choices": ["enable", "disable"]},
                "unicast-hb-netmask": {"required": False, "type": "str"},
                "unicast-hb-peerip": {"required": False, "type": "str"},
                "uninterruptible-upgrade": {"required": False, "type": "str",
                                            "choices": ["enable", "disable"]},
                "vcluster-id": {"required": False, "type": "int"},
                "vcluster2": {"required": False, "type": "str",
                              "choices": ["enable", "disable"]},
                "vdom": {"required": False, "type": "str"},
                "weight": {"required": False, "type": "str"}

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
