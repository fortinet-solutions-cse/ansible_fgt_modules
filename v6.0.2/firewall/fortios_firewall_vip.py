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
module: fortios_firewall_vip
short_description: Configure virtual IP for IPv4 in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify firewall feature and vip category.
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
    firewall_vip:
        description:
            - Configure virtual IP for IPv4.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            arp-reply:
                description:
                    - Enable to respond to ARP requests for this virtual IP address. Enabled by default.
                choices:
                    - disable
                    - enable
            color:
                description:
                    - Color of icon on the GUI.
            comment:
                description:
                    - Comment.
            dns-mapping-ttl:
                description:
                    - DNS mapping TTL (Set to zero to use TTL in DNS response, default = 0).
            extaddr:
                description:
                    - External FQDN address name.
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
            extintf:
                description:
                    - Interface connected to the source network that receives the packets that will be forwarded to the destination network. Source system
                      .interface.name.
            extip:
                description:
                    - IP address or address range on the external interface that you want to map to an address or address range on the destination network.
            extport:
                description:
                    - Incoming port number range that you want to map to a port number range on the destination network.
            gratuitous-arp-interval:
                description:
                    - Enable to have the VIP send gratuitous ARPs. 0=disabled. Set from 5 up to 8640000 seconds to enable.
            http-cookie-age:
                description:
                    - Time in minutes that client web browsers should keep a cookie. Default is 60 seconds. 0 = no time limit.
            http-cookie-domain:
                description:
                    - Domain that HTTP cookie persistence should apply to.
            http-cookie-domain-from-host:
                description:
                    - Enable/disable use of HTTP cookie domain from host field in HTTP.
                choices:
                    - disable
                    - enable
            http-cookie-generation:
                description:
                    - Generation of HTTP cookie to be accepted. Changing invalidates all existing cookies.
            http-cookie-path:
                description:
                    - Limit HTTP cookie persistence to the specified path.
            http-cookie-share:
                description:
                    - Control sharing of cookies across virtual servers. same-ip means a cookie from one virtual server can be used by another. Disable stops
                       cookie sharing.
                choices:
                    - disable
                    - same-ip
            http-ip-header:
                description:
                    - For HTTP multiplexing, enable to add the original client IP address in the XForwarded-For HTTP header.
                choices:
                    - enable
                    - disable
            http-ip-header-name:
                description:
                    - For HTTP multiplexing, enter a custom HTTPS header name. The original client IP address is added to this header. If empty,
                       X-Forwarded-For is used.
            http-multiplex:
                description:
                    - Enable/disable HTTP multiplexing.
                choices:
                    - enable
                    - disable
            https-cookie-secure:
                description:
                    - Enable/disable verification that inserted HTTPS cookies are secure.
                choices:
                    - disable
                    - enable
            id:
                description:
                    - Custom defined ID.
            ldb-method:
                description:
                    - Method used to distribute sessions to real servers.
                choices:
                    - static
                    - round-robin
                    - weighted
                    - least-session
                    - least-rtt
                    - first-alive
                    - http-host
            mapped-addr:
                description:
                    - Mapped FQDN address name. Source firewall.address.name.
            mappedip:
                description:
                    - IP address or address range on the destination network to which the external IP address is mapped.
                suboptions:
                    range:
                        description:
                            - Mapped IP range.
                        required: true
            mappedport:
                description:
                    - Port number range on the destination network to which the external port number range is mapped.
            max-embryonic-connections:
                description:
                    - Maximum number of incomplete connections.
            monitor:
                description:
                    - Name of the health check monitor to use when polling to determine a virtual server's connectivity status.
                suboptions:
                    name:
                        description:
                            - Health monitor name. Source firewall.ldb-monitor.name.
                        required: true
            name:
                description:
                    - Virtual IP name.
                required: true
            nat-source-vip:
                description:
                    - Enable to prevent unintended servers from using a virtual IP. Disable to use the actual IP address of the server as the source address.
                choices:
                    - disable
                    - enable
            outlook-web-access:
                description:
                    - Enable to add the Front-End-Https header for Microsoft Outlook Web Access.
                choices:
                    - disable
                    - enable
            persistence:
                description:
                    - Configure how to make sure that clients connect to the same server every time they make a request that is part of the same session.
                choices:
                    - none
                    - http-cookie
                    - ssl-session-id
            portforward:
                description:
                    - Enable/disable port forwarding.
                choices:
                    - disable
                    - enable
            portmapping-type:
                description:
                    - Port mapping type.
                choices:
                    - 1-to-1
                    - m-to-n
            protocol:
                description:
                    - Protocol to use when forwarding packets.
                choices:
                    - tcp
                    - udp
                    - sctp
                    - icmp
            realservers:
                description:
                    - Select the real servers that this server load balancing VIP will distribute traffic to.
                suboptions:
                    client-ip:
                        description:
                            - Only clients in this IP range can connect to this real server.
                    healthcheck:
                        description:
                            - Enable to check the responsiveness of the real server before forwarding traffic.
                        choices:
                            - disable
                            - enable
                            - vip
                    holddown-interval:
                        description:
                            - Time in seconds that the health check monitor continues to monitor and unresponsive server that should be active.
                    http-host:
                        description:
                            - HTTP server domain name in HTTP header.
                    id:
                        description:
                            - Real server ID.
                        required: true
                    ip:
                        description:
                            - IP address of the real server.
                    max-connections:
                        description:
                            - Max number of active connections that can be directed to the real server. When reached, sessions are sent to other real servers.
                    monitor:
                        description:
                            - Name of the health check monitor to use when polling to determine a virtual server's connectivity status. Source firewall
                              .ldb-monitor.name.
                    port:
                        description:
                            - Port for communicating with the real server. Required if port forwarding is enabled.
                    status:
                        description:
                            - Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is sent.
                        choices:
                            - active
                            - standby
                            - disable
                    weight:
                        description:
                            - Weight of the real server. If weighted load balancing is enabled, the server with the highest weight gets more connections.
            server-type:
                description:
                    - Protocol to be load balanced by the virtual server (also called the server load balance virtual IP).
                choices:
                    - http
                    - https
                    - imaps
                    - pop3s
                    - smtps
                    - ssl
                    - tcp
                    - udp
                    - ip
            service:
                description:
                    - Service name.
                suboptions:
                    name:
                        description:
                            - Service name. Source firewall.service.custom.name firewall.service.group.name.
                        required: true
            src-filter:
                description:
                    - Source address filter. Each address must be either an IP/subnet (x.x.x.x/n) or a range (x.x.x.x-y.y.y.y). Separate addresses with spaces.
                suboptions:
                    range:
                        description:
                            - Source-filter range.
                        required: true
            srcintf-filter:
                description:
                    - Interfaces to which the VIP applies. Separate the names with spaces.
                suboptions:
                    interface-name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
            ssl-algorithm:
                description:
                    - Permitted encryption algorithms for SSL sessions according to encryption strength.
                choices:
                    - high
                    - medium
                    - low
                    - custom
            ssl-certificate:
                description:
                    - The name of the SSL certificate to use for SSL acceleration. Source vpn.certificate.local.name.
            ssl-cipher-suites:
                description:
                    - SSL/TLS cipher suites acceptable from a client, ordered by priority.
                suboptions:
                    cipher:
                        description:
                            - Cipher suite name.
                        choices:
                            - TLS-RSA-WITH-3DES-EDE-CBC-SHA
                            - TLS-DHE-RSA-WITH-DES-CBC-SHA
                            - TLS-DHE-DSS-WITH-DES-CBC-SHA
                    priority:
                        description:
                            - SSL/TLS cipher suites priority.
                        required: true
                    versions:
                        description:
                            - SSL/TLS versions that the cipher suite can be used with.
                        choices:
                            - ssl-3.0
                            - tls-1.0
                            - tls-1.1
                            - tls-1.2
            ssl-client-fallback:
                description:
                    - Enable/disable support for preventing Downgrade Attacks on client connections (RFC 7507).
                choices:
                    - disable
                    - enable
            ssl-client-renegotiation:
                description:
                    - Allow, deny, or require secure renegotiation of client sessions to comply with RFC 5746.
                choices:
                    - allow
                    - deny
                    - secure
            ssl-client-session-state-max:
                description:
                    - Maximum number of client to FortiGate SSL session states to keep.
            ssl-client-session-state-timeout:
                description:
                    - Number of minutes to keep client to FortiGate SSL session state.
            ssl-client-session-state-type:
                description:
                    - How to expire SSL sessions for the segment of the SSL connection between the client and the FortiGate.
                choices:
                    - disable
                    - time
                    - count
                    - both
            ssl-dh-bits:
                description:
                    - Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                choices:
                    - 768
                    - 1024
                    - 1536
                    - 2048
                    - 3072
                    - 4096
            ssl-hpkp:
                description:
                    - Enable/disable including HPKP header in response.
                choices:
                    - disable
                    - enable
                    - report-only
            ssl-hpkp-age:
                description:
                    - Number of seconds the client should honour the HPKP setting.
            ssl-hpkp-backup:
                description:
                    - Certificate to generate backup HPKP pin from. Source vpn.certificate.local.name vpn.certificate.ca.name.
            ssl-hpkp-include-subdomains:
                description:
                    - Indicate that HPKP header applies to all subdomains.
                choices:
                    - disable
                    - enable
            ssl-hpkp-primary:
                description:
                    - Certificate to generate primary HPKP pin from. Source vpn.certificate.local.name vpn.certificate.ca.name.
            ssl-hpkp-report-uri:
                description:
                    - URL to report HPKP violations to.
            ssl-hsts:
                description:
                    - Enable/disable including HSTS header in response.
                choices:
                    - disable
                    - enable
            ssl-hsts-age:
                description:
                    - Number of seconds the client should honour the HSTS setting.
            ssl-hsts-include-subdomains:
                description:
                    - Indicate that HSTS header applies to all subdomains.
                choices:
                    - disable
                    - enable
            ssl-http-location-conversion:
                description:
                    - Enable to replace HTTP with HTTPS in the reply's Location HTTP header field.
                choices:
                    - enable
                    - disable
            ssl-http-match-host:
                description:
                    - Enable/disable HTTP host matching for location conversion.
                choices:
                    - enable
                    - disable
            ssl-max-version:
                description:
                    - Highest SSL/TLS version acceptable from a client.
                choices:
                    - ssl-3.0
                    - tls-1.0
                    - tls-1.1
                    - tls-1.2
            ssl-min-version:
                description:
                    - Lowest SSL/TLS version acceptable from a client.
                choices:
                    - ssl-3.0
                    - tls-1.0
                    - tls-1.1
                    - tls-1.2
            ssl-mode:
                description:
                    - Apply SSL offloading between the client and the FortiGate (half) or from the client to the FortiGate and from the FortiGate to the
                       server (full).
                choices:
                    - half
                    - full
            ssl-pfs:
                description:
                    - Select the cipher suites that can be used for SSL perfect forward secrecy (PFS). Applies to both client and server sessions.
                choices:
                    - require
                    - deny
                    - allow
            ssl-send-empty-frags:
                description:
                    - Enable/disable sending empty fragments to avoid CBC IV attacks (SSL 3.0 & TLS 1.0 only). May need to be disabled for compatibility with
                       older systems.
                choices:
                    - enable
                    - disable
            ssl-server-algorithm:
                description:
                    - Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                choices:
                    - high
                    - medium
                    - low
                    - custom
                    - client
            ssl-server-cipher-suites:
                description:
                    - SSL/TLS cipher suites to offer to a server, ordered by priority.
                suboptions:
                    cipher:
                        description:
                            - Cipher suite name.
                        choices:
                            - TLS-RSA-WITH-3DES-EDE-CBC-SHA
                            - TLS-DHE-RSA-WITH-DES-CBC-SHA
                            - TLS-DHE-DSS-WITH-DES-CBC-SHA
                    priority:
                        description:
                            - SSL/TLS cipher suites priority.
                        required: true
                    versions:
                        description:
                            - SSL/TLS versions that the cipher suite can be used with.
                        choices:
                            - ssl-3.0
                            - tls-1.0
                            - tls-1.1
                            - tls-1.2
            ssl-server-max-version:
                description:
                    - Highest SSL/TLS version acceptable from a server. Use the client setting by default.
                choices:
                    - ssl-3.0
                    - tls-1.0
                    - tls-1.1
                    - tls-1.2
                    - client
            ssl-server-min-version:
                description:
                    - Lowest SSL/TLS version acceptable from a server. Use the client setting by default.
                choices:
                    - ssl-3.0
                    - tls-1.0
                    - tls-1.1
                    - tls-1.2
                    - client
            ssl-server-session-state-max:
                description:
                    - Maximum number of FortiGate to Server SSL session states to keep.
            ssl-server-session-state-timeout:
                description:
                    - Number of minutes to keep FortiGate to Server SSL session state.
            ssl-server-session-state-type:
                description:
                    - How to expire SSL sessions for the segment of the SSL connection between the server and the FortiGate.
                choices:
                    - disable
                    - time
                    - count
                    - both
            type:
                description:
                    - Configure a static NAT, load balance, server load balance, DNS translation, or FQDN VIP.
                choices:
                    - static-nat
                    - load-balance
                    - server-load-balance
                    - dns-translation
                    - fqdn
            uuid:
                description:
                    - Universally Unique Identifier (UUID; automatically assigned but can be manually reset).
            weblogic-server:
                description:
                    - Enable to add an HTTP header to indicate SSL offloading for a WebLogic server.
                choices:
                    - disable
                    - enable
            websphere-server:
                description:
                    - Enable to add an HTTP header to indicate SSL offloading for a WebSphere server.
                choices:
                    - disable
                    - enable
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure virtual IP for IPv4.
    fortios_firewall_vip:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      firewall_vip:
        state: "present"
        arp-reply: "disable"
        color: "4"
        comment: "Comment."
        dns-mapping-ttl: "6"
        extaddr:
         -
            name: "default_name_8 (source firewall.address.name firewall.addrgrp.name)"
        extintf: "<your_own_value> (source system.interface.name)"
        extip: "<your_own_value>"
        extport: "<your_own_value>"
        gratuitous-arp-interval: "12"
        http-cookie-age: "13"
        http-cookie-domain: "<your_own_value>"
        http-cookie-domain-from-host: "disable"
        http-cookie-generation: "16"
        http-cookie-path: "<your_own_value>"
        http-cookie-share: "disable"
        http-ip-header: "enable"
        http-ip-header-name: "<your_own_value>"
        http-multiplex: "enable"
        https-cookie-secure: "disable"
        id:  "23"
        ldb-method: "static"
        mapped-addr: "<your_own_value> (source firewall.address.name)"
        mappedip:
         -
            range: "<your_own_value>"
        mappedport: "<your_own_value>"
        max-embryonic-connections: "29"
        monitor:
         -
            name: "default_name_31 (source firewall.ldb-monitor.name)"
        name: "default_name_32"
        nat-source-vip: "disable"
        outlook-web-access: "disable"
        persistence: "none"
        portforward: "disable"
        portmapping-type: "1-to-1"
        protocol: "tcp"
        realservers:
         -
            client-ip: "<your_own_value>"
            healthcheck: "disable"
            holddown-interval: "42"
            http-host: "myhostname"
            id:  "44"
            ip: "<your_own_value>"
            max-connections: "46"
            monitor: "<your_own_value> (source firewall.ldb-monitor.name)"
            port: "48"
            status: "active"
            weight: "50"
        server-type: "http"
        service:
         -
            name: "default_name_53 (source firewall.service.custom.name firewall.service.group.name)"
        src-filter:
         -
            range: "<your_own_value>"
        srcintf-filter:
         -
            interface-name: "<your_own_value> (source system.interface.name)"
        ssl-algorithm: "high"
        ssl-certificate: "<your_own_value> (source vpn.certificate.local.name)"
        ssl-cipher-suites:
         -
            cipher: "TLS-RSA-WITH-3DES-EDE-CBC-SHA"
            priority: "62"
            versions: "ssl-3.0"
        ssl-client-fallback: "disable"
        ssl-client-renegotiation: "allow"
        ssl-client-session-state-max: "66"
        ssl-client-session-state-timeout: "67"
        ssl-client-session-state-type: "disable"
        ssl-dh-bits: "768"
        ssl-hpkp: "disable"
        ssl-hpkp-age: "71"
        ssl-hpkp-backup: "<your_own_value> (source vpn.certificate.local.name vpn.certificate.ca.name)"
        ssl-hpkp-include-subdomains: "disable"
        ssl-hpkp-primary: "<your_own_value> (source vpn.certificate.local.name vpn.certificate.ca.name)"
        ssl-hpkp-report-uri: "<your_own_value>"
        ssl-hsts: "disable"
        ssl-hsts-age: "77"
        ssl-hsts-include-subdomains: "disable"
        ssl-http-location-conversion: "enable"
        ssl-http-match-host: "enable"
        ssl-max-version: "ssl-3.0"
        ssl-min-version: "ssl-3.0"
        ssl-mode: "half"
        ssl-pfs: "require"
        ssl-send-empty-frags: "enable"
        ssl-server-algorithm: "high"
        ssl-server-cipher-suites:
         -
            cipher: "TLS-RSA-WITH-3DES-EDE-CBC-SHA"
            priority: "89"
            versions: "ssl-3.0"
        ssl-server-max-version: "ssl-3.0"
        ssl-server-min-version: "ssl-3.0"
        ssl-server-session-state-max: "93"
        ssl-server-session-state-timeout: "94"
        ssl-server-session-state-type: "disable"
        type: "static-nat"
        uuid: "<your_own_value>"
        weblogic-server: "disable"
        websphere-server: "disable"
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


def filter_firewall_vip_data(json):
    option_list = ['arp-reply', 'color', 'comment',
                   'dns-mapping-ttl', 'extaddr', 'extintf',
                   'extip', 'extport', 'gratuitous-arp-interval',
                   'http-cookie-age', 'http-cookie-domain', 'http-cookie-domain-from-host',
                   'http-cookie-generation', 'http-cookie-path', 'http-cookie-share',
                   'http-ip-header', 'http-ip-header-name', 'http-multiplex',
                   'https-cookie-secure', 'id', 'ldb-method',
                   'mapped-addr', 'mappedip', 'mappedport',
                   'max-embryonic-connections', 'monitor', 'name',
                   'nat-source-vip', 'outlook-web-access', 'persistence',
                   'portforward', 'portmapping-type', 'protocol',
                   'realservers', 'server-type', 'service',
                   'src-filter', 'srcintf-filter', 'ssl-algorithm',
                   'ssl-certificate', 'ssl-cipher-suites', 'ssl-client-fallback',
                   'ssl-client-renegotiation', 'ssl-client-session-state-max', 'ssl-client-session-state-timeout',
                   'ssl-client-session-state-type', 'ssl-dh-bits', 'ssl-hpkp',
                   'ssl-hpkp-age', 'ssl-hpkp-backup', 'ssl-hpkp-include-subdomains',
                   'ssl-hpkp-primary', 'ssl-hpkp-report-uri', 'ssl-hsts',
                   'ssl-hsts-age', 'ssl-hsts-include-subdomains', 'ssl-http-location-conversion',
                   'ssl-http-match-host', 'ssl-max-version', 'ssl-min-version',
                   'ssl-mode', 'ssl-pfs', 'ssl-send-empty-frags',
                   'ssl-server-algorithm', 'ssl-server-cipher-suites', 'ssl-server-max-version',
                   'ssl-server-min-version', 'ssl-server-session-state-max', 'ssl-server-session-state-timeout',
                   'ssl-server-session-state-type', 'type', 'uuid',
                   'weblogic-server', 'websphere-server']
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


def firewall_vip(data, fos):
    vdom = data['vdom']
    firewall_vip_data = data['firewall_vip']
    flattened_data = flatten_multilists_attributes(firewall_vip_data)
    filtered_data = filter_firewall_vip_data(flattened_data)
    if firewall_vip_data['state'] == "present":
        return fos.set('firewall',
                       'vip',
                       data=filtered_data,
                       vdom=vdom)

    elif firewall_vip_data['state'] == "absent":
        return fos.delete('firewall',
                          'vip',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_firewall(data, fos):
    login(data)

    if data['firewall_vip']:
        resp = firewall_vip(data, fos)

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "firewall_vip": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "arp-reply": {"required": False, "type": "str",
                              "choices": ["disable", "enable"]},
                "color": {"required": False, "type": "int"},
                "comment": {"required": False, "type": "str"},
                "dns-mapping-ttl": {"required": False, "type": "int"},
                "extaddr": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "extintf": {"required": False, "type": "str"},
                "extip": {"required": False, "type": "str"},
                "extport": {"required": False, "type": "str"},
                "gratuitous-arp-interval": {"required": False, "type": "int"},
                "http-cookie-age": {"required": False, "type": "int"},
                "http-cookie-domain": {"required": False, "type": "str"},
                "http-cookie-domain-from-host": {"required": False, "type": "str",
                                                 "choices": ["disable", "enable"]},
                "http-cookie-generation": {"required": False, "type": "int"},
                "http-cookie-path": {"required": False, "type": "str"},
                "http-cookie-share": {"required": False, "type": "str",
                                      "choices": ["disable", "same-ip"]},
                "http-ip-header": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "http-ip-header-name": {"required": False, "type": "str"},
                "http-multiplex": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "https-cookie-secure": {"required": False, "type": "str",
                                        "choices": ["disable", "enable"]},
                "id": {"required": False, "type": "int"},
                "ldb-method": {"required": False, "type": "str",
                               "choices": ["static", "round-robin", "weighted",
                                           "least-session", "least-rtt", "first-alive",
                                           "http-host"]},
                "mapped-addr": {"required": False, "type": "str"},
                "mappedip": {"required": False, "type": "list",
                             "options": {
                                 "range": {"required": True, "type": "str"}
                             }},
                "mappedport": {"required": False, "type": "str"},
                "max-embryonic-connections": {"required": False, "type": "int"},
                "monitor": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "name": {"required": True, "type": "str"},
                "nat-source-vip": {"required": False, "type": "str",
                                   "choices": ["disable", "enable"]},
                "outlook-web-access": {"required": False, "type": "str",
                                       "choices": ["disable", "enable"]},
                "persistence": {"required": False, "type": "str",
                                "choices": ["none", "http-cookie", "ssl-session-id"]},
                "portforward": {"required": False, "type": "str",
                                "choices": ["disable", "enable"]},
                "portmapping-type": {"required": False, "type": "str",
                                     "choices": ["1-to-1", "m-to-n"]},
                "protocol": {"required": False, "type": "str",
                             "choices": ["tcp", "udp", "sctp",
                                         "icmp"]},
                "realservers": {"required": False, "type": "list",
                                "options": {
                                    "client-ip": {"required": False, "type": "str"},
                                    "healthcheck": {"required": False, "type": "str",
                                                    "choices": ["disable", "enable", "vip"]},
                                    "holddown-interval": {"required": False, "type": "int"},
                                    "http-host": {"required": False, "type": "str"},
                                    "id": {"required": True, "type": "int"},
                                    "ip": {"required": False, "type": "str"},
                                    "max-connections": {"required": False, "type": "int"},
                                    "monitor": {"required": False, "type": "str"},
                                    "port": {"required": False, "type": "int"},
                                    "status": {"required": False, "type": "str",
                                               "choices": ["active", "standby", "disable"]},
                                    "weight": {"required": False, "type": "int"}
                                }},
                "server-type": {"required": False, "type": "str",
                                "choices": ["http", "https", "imaps",
                                            "pop3s", "smtps", "ssl",
                                            "tcp", "udp", "ip"]},
                "service": {"required": False, "type": "list",
                            "options": {
                                "name": {"required": True, "type": "str"}
                            }},
                "src-filter": {"required": False, "type": "list",
                               "options": {
                                   "range": {"required": True, "type": "str"}
                               }},
                "srcintf-filter": {"required": False, "type": "list",
                                   "options": {
                                       "interface-name": {"required": True, "type": "str"}
                                   }},
                "ssl-algorithm": {"required": False, "type": "str",
                                  "choices": ["high", "medium", "low",
                                              "custom"]},
                "ssl-certificate": {"required": False, "type": "str"},
                "ssl-cipher-suites": {"required": False, "type": "list",
                                      "options": {
                                          "cipher": {"required": False, "type": "str",
                                                     "choices": ["TLS-RSA-WITH-3DES-EDE-CBC-SHA", "TLS-DHE-RSA-WITH-DES-CBC-SHA", "TLS-DHE-DSS-WITH-DES-CBC-SHA"]},
                                          "priority": {"required": True, "type": "int"},
                                          "versions": {"required": False, "type": "str",
                                                       "choices": ["ssl-3.0", "tls-1.0", "tls-1.1",
                                                                   "tls-1.2"]}
                                      }},
                "ssl-client-fallback": {"required": False, "type": "str",
                                        "choices": ["disable", "enable"]},
                "ssl-client-renegotiation": {"required": False, "type": "str",
                                             "choices": ["allow", "deny", "secure"]},
                "ssl-client-session-state-max": {"required": False, "type": "int"},
                "ssl-client-session-state-timeout": {"required": False, "type": "int"},
                "ssl-client-session-state-type": {"required": False, "type": "str",
                                                  "choices": ["disable", "time", "count",
                                                              "both"]},
                "ssl-dh-bits": {"required": False, "type": "str",
                                "choices": ["768", "1024", "1536",
                                            "2048", "3072", "4096"]},
                "ssl-hpkp": {"required": False, "type": "str",
                             "choices": ["disable", "enable", "report-only"]},
                "ssl-hpkp-age": {"required": False, "type": "int"},
                "ssl-hpkp-backup": {"required": False, "type": "str"},
                "ssl-hpkp-include-subdomains": {"required": False, "type": "str",
                                                "choices": ["disable", "enable"]},
                "ssl-hpkp-primary": {"required": False, "type": "str"},
                "ssl-hpkp-report-uri": {"required": False, "type": "str"},
                "ssl-hsts": {"required": False, "type": "str",
                             "choices": ["disable", "enable"]},
                "ssl-hsts-age": {"required": False, "type": "int"},
                "ssl-hsts-include-subdomains": {"required": False, "type": "str",
                                                "choices": ["disable", "enable"]},
                "ssl-http-location-conversion": {"required": False, "type": "str",
                                                 "choices": ["enable", "disable"]},
                "ssl-http-match-host": {"required": False, "type": "str",
                                        "choices": ["enable", "disable"]},
                "ssl-max-version": {"required": False, "type": "str",
                                    "choices": ["ssl-3.0", "tls-1.0", "tls-1.1",
                                                "tls-1.2"]},
                "ssl-min-version": {"required": False, "type": "str",
                                    "choices": ["ssl-3.0", "tls-1.0", "tls-1.1",
                                                "tls-1.2"]},
                "ssl-mode": {"required": False, "type": "str",
                             "choices": ["half", "full"]},
                "ssl-pfs": {"required": False, "type": "str",
                            "choices": ["require", "deny", "allow"]},
                "ssl-send-empty-frags": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "ssl-server-algorithm": {"required": False, "type": "str",
                                         "choices": ["high", "medium", "low",
                                                     "custom", "client"]},
                "ssl-server-cipher-suites": {"required": False, "type": "list",
                                             "options": {
                                                 "cipher": {"required": False, "type": "str",
                                                            "choices": ["TLS-RSA-WITH-3DES-EDE-CBC-SHA", "TLS-DHE-RSA-WITH-DES-CBC-SHA", "TLS-DHE-DSS-WITH-DES-CBC-SHA"]},
                                                 "priority": {"required": True, "type": "int"},
                                                 "versions": {"required": False, "type": "str",
                                                              "choices": ["ssl-3.0", "tls-1.0", "tls-1.1",
                                                                          "tls-1.2"]}
                                             }},
                "ssl-server-max-version": {"required": False, "type": "str",
                                           "choices": ["ssl-3.0", "tls-1.0", "tls-1.1",
                                                       "tls-1.2", "client"]},
                "ssl-server-min-version": {"required": False, "type": "str",
                                           "choices": ["ssl-3.0", "tls-1.0", "tls-1.1",
                                                       "tls-1.2", "client"]},
                "ssl-server-session-state-max": {"required": False, "type": "int"},
                "ssl-server-session-state-timeout": {"required": False, "type": "int"},
                "ssl-server-session-state-type": {"required": False, "type": "str",
                                                  "choices": ["disable", "time", "count",
                                                              "both"]},
                "type": {"required": False, "type": "str",
                         "choices": ["static-nat", "load-balance", "server-load-balance",
                                     "dns-translation", "fqdn"]},
                "uuid": {"required": False, "type": "str"},
                "weblogic-server": {"required": False, "type": "str",
                                    "choices": ["disable", "enable"]},
                "websphere-server": {"required": False, "type": "str",
                                     "choices": ["disable", "enable"]}

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

    is_error, has_changed, result = fortios_firewall(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
