# USB Tether

USB Tether is an application to automatically manage and maintain a tethered connection. It is capable of automatically switching networks and keeping a tether operation going despite USB and connectivity events. This has many uses, but was mainly designed for tethering directly to a router to serve a larger network. It is highly recommended to use charge control apps like [Battery Charge Limit](https://play.google.com/store/apps/details?id=com.slash.batterychargelimit&hl=en_US&gl=US) or [Advanced Charging Controller](https://forum.xda-developers.com/t/advanced-charging-controller-acc.3668427/) for dedicated modems.

 - Lets you tether to any interface or lock on to your phone's primary internet source.
 - Supports split CLAT "v4-" interfaces in Auto mode
 - Does not require APN modification to avoid classification
 - Built-in dnsmasq with support for DHCP, DHCP6, and SLAAC
 - Ability to set the IPv4 address (and /24 subnet)
 - IPv6 NAT supporting both Masquerading, SNAT, and TPROXY
 - IPv6 Prefix selection to set IPv6 priority
 - TTL/HL modification to make packets look like they came from your device
 - DPI Circumvention for bypassing traffic throttling
 - VPN Autostart and watchdog support to ensure your VPN stays connected
 - IP-based bandwidth control to help manage larger networks
 - Cellular watchdog to detect and fix broken cellular connections
 - Watchdog for restarting crashed services

## Kernel Prerequisites:

Some features require your kernel to be compiled with specific options to be usable. This is up to you or your kernel maintainer to enable them at compile time. Distros Like Lineage OS may have none of these enabled by default, requiring you to obtain the sources and recompile the kernel yourself. You can either rebuild and flash the entire kernel or just build the modules and insmod them on startup.

#### For Modify TTL/HL:

- CONFIG_NETFILTER_XT_TARGET_HL - modify TTL and HL hoplimit

#### For IPv6 TPROXY:

- NETFILTER_XT_TARGET_TPROXY - tproxy target support

#### For IPv6 SNAT:

- CONFIG_NF_NAT_IPV6 - IPv6 NAT
- CONFIG_IP6_NF_NAT - IPv6 NAT IPTables

#### For IPv6 Masquerading:

- CONFIG_NF_NAT_IPV6 - IPv6 NAT
- CONFIG_IP6_NF_NAT - IPv6 NAT IPTables
- CONFIG_NF_NAT_MASQUERADE_IPV6 - IPv6 Masquerading
- CONFIG_IP6_NF_TARGET_MASQUERADE - IPv6 Masquerading target

Note: CONFIG_NF_NAT_MASQUERADE_IPV6 cannot be built as a module since kernel 4.18. The entire kernel must be rebuilt for masquerade support. 

Note:If your target kernel uses CONFIG_MODULE_SIG_FORCE, learn how to disable it [here](https://forum.xda-developers.com/t/guide-kernel-mod-patching-out-config_module_sig_force-on-stock-kernels.4278981/).

## Q&A:

#### Why does USB Tether require root?

We need to be able to access Android ndc for network configuration, the Linux firewall to manage packets, and bind to ports for DNSMasq. USB Tether sets everything up manually and needs escalated privileges to do so.

#### Can you do the same thing with wireless Hotspotting?

I think it's possible, but would require framework patches to get signature-level permissions. [VPN Hotspot](https://github.com/Mygod/VPNHotspot) is a great option, though it does not support IPv6 and should always be used with a local or remote VPN.

#### What if I have a locked down phone?

There are a bunch of paid apps that tunnel data through adb, but they all have their downsides. Running a Shadowsocks server ideally through a tether or alternatively tunneled through adb to a router would work well. There are also a few socks proxies written in Go that would probably be easy to port. The most difficult roadblock is UDP support, otherwise any proxy would do.

#### What if I can't build the kernel modules mentioned?

USB Tether can still be used to tether IPv4 traffic. Wifi and VPN tethers will work fine, but mobile data will be easily detectable through TTL. You use a local VPN like ADGuard, manually set the TTL on your device(s), or use this firewall rule to set the TTL on the bridged traffic passing through your router:

    iptables -t mangle -I POSTROUTING -m physdev --physdev-out usb0 -j TTL --ttl-set 65

#### Why does IPv6 require NAT support?

Using NAT allows us to tether to any interface, modify traffic as it passes, and hide network topology. Standard IPv6 tethering has every device is addressed individually in the tunnel and requires a double NAT to modify hoplimit from my testing.

#### Can carriers detect this?

Hiding devices behind NATs and setting the TTL/HL goes a long way towards avoiding being easily flagged, but does nothing to hide packet structure or your activity. A remote VPN is highly recommended and has the added benefit avoiding throttling and peering issues, while at the same time, long-running VPN tunnels are a prime target for throttling themselves.

## Router Setup:

These setups typically use the phone as the router bridged to a consumer router configured as a wireless AP to avoid double NAT. Try to avoid any Broadcom MIPS routers as their USB support is very poor. Something like a RPi should be used as a bridge device when tethering with an otherwise unsuitable router. OpenWRT devices are highly recommended, Qualcomm IPQ Linksys routers go for pretty cheap and are well suited to this task. OpenWRT makes it possible to run the DHCP server on the router and offers many other powerful resources for managing your network.

You must also be prepaired for testing and problem solving software/hardware quirks. As an example, on my EA6350v3 I had to:

 - Lock CPU frequency scaling to workaround a IPQ kernel bug
 - Replace wireless calibration data to improve preformance
 - Write [a script](https://forum.openwrt.org/t/optimized-build-for-ipq40xx-devices/44125/341) to reset USB when it fails(IPQ kernel bug)
 - Mirror configuration on both partitions to servive multiple resets

#### Example OpenWRT Setup:

Requires kernel RNDIS support:

    opkg update
    opkg install kmod-usb-net-rndis
    
Settings as of 19.07 (router handles DHCP and uses ULA prefix):

    Network -> Interfaces -> LAN
    -> General Settings
    Protocol: Static Address
    IPv4 address: 192.168.42.1
    IPv4 netmask: 255.255.255.0
    IPv4 gateway: 192.168.42.129
    IPv6 assignment length: disabled
    IPv6 address: fd00::2/64
    IPv6 gateway: fd00::1
    IPv6 routed prefix: fd00::/64
    -> Physical Settings
    Interface: add usb0
    -> DHCP Server
    --> General Setup
    Start: 100
    Limit: 150
    -->Advanced Settings
    Force: enabled
    --> IPv6 Settings
    Always announce default router: enabled

Be sure to set your preferred DNS servers as appropriate:

    Network -> Interfaces -> LAN -> General Settings -> Use custom DNS servers
    Network -> Interfaces -> LAN -> DHCP Server -> IPv6 Settings -> Announced DNS servers
    DHCP and DNS -> General Settings -> DNS forwardings

## TODO:

 - **Static Assignments** - It would be nice if we could reserve addresses for specific devices.
 - **Downstream Watchdog** - We should have a periodic check that traffic can pass to a downstream router or server.
 - **VPN Bypass** - Make part of the private range route outgoing traffic to a secondary interface

## DEPENDENCIES:

 - dnsmasq - https://github.com/worstperson/dnsmasq
 - tpws - https://github.com/bol-van/zapret
 - hev-socks5-server - https://github.com/heiher/hev-socks5-server
 - hev-socks5-tproxy - https://github.com/heiher/hev-socks5-tproxy