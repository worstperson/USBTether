/*
        Copyright 2023 worstperson

        Licensed under the Apache License, Version 2.0 (the "License");
        you may not use this file except in compliance with the License.
        You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

        Unless required by applicable law or agreed to in writing, software
        distributed under the License is distributed on an "AS IS" BASIS,
        WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
        See the License for the specific language governing permissions and
        limitations under the License.
*/

package com.worstperson.usbtether;

import android.os.Build;
import android.util.Log;
import com.topjohnwu.superuser.Shell;

public class Script {

    static {
        Shell.enableVerboseLogging = BuildConfig.DEBUG;
        Shell.setDefaultBuilder(Shell.Builder.create()
                .setFlags(Shell.FLAG_REDIRECT_STDERR)
                .setTimeout(10));
    }

    private static boolean shellCommand(String command) {
        Shell.Result result = Shell.cmd(command).exec();
        for (String message : result.getOut()) {
            Log.i("USBTether", message);
        }
        return result.isSuccess();
    }
    
    static String testWait() {
        String cmd = "";
        if (shellCommand("iptables -w 0 --help > /dev/null")) {
            cmd = "-w 2 ";
        } else if (shellCommand("iptables -w --help > /dev/null")) { // Early versions do not have the timeout
            cmd = "-w ";
        }
        return cmd;
    }
    
    static String hasWait = testWait();
    static boolean hasTable = shellCommand("ip6tables " + hasWait + "--table nat --list > /dev/null");

    // iptables can lie, inject test rules to verify the the modules are actually available
    static boolean hasNFQUEUE = shellCommand("iptables " + hasWait + "-t mangle -A FORWARD -j NFQUEUE --queue-num 0") && shellCommand("iptables " + hasWait + "-t mangle -D FORWARD -j NFQUEUE --queue-num 0");
    static boolean hasTPROXY = shellCommand("ip6tables " + hasWait + "-t mangle -A PREROUTING -p tcp -j TPROXY --on-ip :: --on-port 0 --tproxy-mark 0") && shellCommand("ip6tables " + hasWait + "-t mangle -D PREROUTING -p tcp -j TPROXY --on-ip :: --on-port 0 --tproxy-mark 0");
    static boolean hasTTL = shellCommand("iptables " + hasWait + "-t mangle -I FORWARD -j TTL --ttl-set 64") && shellCommand("iptables " + hasWait + "-t mangle -D FORWARD -j TTL --ttl-set 64");
    static boolean hasSNAT = hasTable && shellCommand("ip6tables " + hasWait + "-t nat -I POSTROUTING -j SNAT --to [::]") && shellCommand("ip6tables " + hasWait + "-t nat -D POSTROUTING -j SNAT --to [::]");
    static boolean hasMASQUERADE = hasTable && shellCommand("ip6tables " + hasWait + "-t nat -A POSTROUTING -j MASQUERADE") && shellCommand("ip6tables " + hasWait + "-t nat -D POSTROUTING -j MASQUERADE");

    //static boolean hasCURL = shellCommand("command -v curl > /dev/null");

    static boolean isUSBConfigured() {
        return Shell.cmd("[ \"$(cat /sys/class/android_usb/android0/state)\" = \"CONFIGURED\" ]").exec().isSuccess();
    }

    static void killProcess(String pidFile) {
        if ( Shell.cmd("[ -f " + pidFile + " -a -d /proc/$(cat " + pidFile + ") ]").exec().isSuccess()) {
            shellCommand("kill -s 9 $(cat " + pidFile + ")");
        }
    }

    static void iptables(boolean isIPv6, String table, String operation, String rule) {
        String command = isIPv6 ? "ip6tables" : "iptables";
        boolean exists = Shell.cmd(command + " " + hasWait + "-t " + table + " -C " + rule).exec().isSuccess();
        if ((!exists && (operation.equals("N") || operation.equals("I") || operation.equals("A"))) ||
                (exists && (operation.equals("D") || operation.equals("F") || operation.equals("X")))) {
            shellCommand(command + " " + hasWait + "-t " + table + " -" + operation + " " + rule);
        }
    }

    static void createBridge(String tetherInterface) {
        shellCommand("ip link add name " + tetherInterface + " type bridge");
        shellCommand("ip link set " + tetherInterface + " up");
        shellCommand("echo 0 > /proc/sys/net/ipv6/conf/" + tetherInterface + "/accept_ra");
    }

    static void bindBridge(String tetherInterface, String usbInterface) {
        if (shellCommand("ip link set " + usbInterface + " up")) {
            shellCommand("ip link set " + usbInterface + " master " + tetherInterface);
        }
    }

    static void destroyBridge(String tetherInterface) {
        shellCommand("ip link delete " + tetherInterface + " type bridge");
    }

    static boolean[] getTetherConfig() {
        boolean adbEnabled = false;
        if (Shell.cmd("getprop persist.sys.usb.config").exec().getOut().get(0).contains("adb")) {
            adbEnabled = true;
        }

        boolean useService = false;
        if (Build.VERSION.SDK_INT >= 34 && !shellCommand("service check android.hardware.usb.gadget.IUsbGadget/default | grep \"not found\" > /dev/null")) {
            useService = true;
        }

        // sys.config.state is left undefined with GadgetHal impl
        boolean useGadget = false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && !shellCommand("getprop | grep sys.usb.state > /dev/null")) {
            useGadget = true;
        }

        // getGadgetHalVersion was added to svc in Android 12
        // Need to use root service with reflection to properly support Android 11
        boolean hasNCM = false;
        if (useGadget && Build.VERSION.SDK_INT >= 31) {
            Shell.Result shell = Shell.cmd("svc usb getGadgetHalVersion").exec();
            if (shell.isSuccess()) {
                String version = shell.getOut().get(0);
                // State should never be "unknown", but we know it's not LegacyHal, so just ignore it
                if (!(version.equals("unknown") || version.equals("V1_0") || version.equals("V1_1"))) {
                    hasNCM = true;
                }
            }
        }

        return new boolean[] { adbEnabled, useService, useGadget, hasNCM };
    }

    static String configureRNDIS(String libDIR) {

        boolean[] config = getTetherConfig();
        boolean adbEnabled = config[0];
        boolean useService = config[1];
        boolean useGadget = config[2];
        boolean hasNCM = config[3];

        int NONE = 0;
        int ADB = 1 << 0;
        int RNDIS = 1 << 5;
        int NCM = 1 << 10;
        String gagdetFunctions = Integer.toString((adbEnabled ? ADB : NONE) + (hasNCM ? NCM : RNDIS));

        String functionName = hasNCM ? "ncm" : "rndis";
        if (useService) {
            // This is untested, who knows if it works as expected
            Log.i("USBTether", "Configuring " + functionName + " via IUsbGadget");
            shellCommand("service call android.hardware.usb.gadget.IUsbGadget/default 1 i64 " + gagdetFunctions + " null i64 0 i64 1");
        } else if (useGadget) {
            Log.i("USBTether", "Configuring " + functionName + " via GadgetHal");
            shellCommand(libDIR + "/libusbgadget.so " + gagdetFunctions);
        } else {
            // LegacyHal can impl ncm, but we have no way to check
            Log.i("USBTether", "Configuring rndis via LegacyHal");
            // Some broken HAL impls need none to be set or the gadget will not reset
            shellCommand("setprop sys.usb.config none");
            if (adbEnabled) {
                shellCommand("setprop sys.usb.config rndis,adb");
            } else {
                shellCommand("setprop sys.usb.config rndis");
            }
        }
        shellCommand("n=0; while [[ $n -lt 10 ]]; do if [[ -d /sys/class/net/" + functionName + "0 ]]; then break; fi; n=$((n+1)); echo \"waiting for usb... $n\"; sleep 1; done");

        return functionName + "0";
    }

    static void unconfigureRNDIS(String libDIR) {
        boolean[] config = getTetherConfig();
        boolean adbEnabled = config[0];
        boolean useService = config[1];
        boolean useGadget = config[2];

        int NONE = 0;
        int ADB = 1 << 0;
        String gagdetFunctions = Integer.toString(adbEnabled ? ADB : NONE);

        if (useService) {
            Log.i("USBTether", "Configuring default USB state via IUsbGadget");
            shellCommand("service call android.hardware.usb.gadget.IUsbGadget/default 1 i64 " + gagdetFunctions + " null i64 0 i64 1");
        } else if (useGadget) {
            Log.i("USBTether", "Configuring default USB state via GadgetHal");
            shellCommand(libDIR + "/libusbgadget.so " + gagdetFunctions);
        } else {
            Log.i("USBTether", "Configuring default USB state via LegacyHal");
            shellCommand("setprop sys.usb.config none");
            if (adbEnabled) {
                shellCommand("setprop sys.usb.config adb");
            }
        }
    }

    private static boolean configureAddresses(String tetherInterface, String ipv4Addr, String ipv6Prefix) {
        Log.i("USBTether", "Setting IP addresses");
        String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
        return shellCommand("ip link set dev " + tetherInterface + " up")
                && shellCommand("ip address add local " + ipv4Addr + "/24 broadcast " + ipv4Prefix + ".255 scope global dev " + tetherInterface)
                && shellCommand("ip -6 addr add " + ipv6Prefix + "1/64 dev " + tetherInterface + " scope global");
    }

    private static void unconfigureAddresses(String tetherInterface) {
        Log.i("USBTether", "Clearing IP addresses");
        shellCommand("ip address flush dev " + tetherInterface);
        shellCommand("ip -6 address flush dev " + tetherInterface);
        shellCommand("ip link set " + tetherInterface + " down");
    }

    static boolean configureRoutes(String tetherInterface, String tetherLocalPrefix, String ipv4Addr, String ipv6Prefix) {
        Log.i("USBTether", "Setting IP routes");
        String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
        return shellCommand("ip route add " + ipv4Prefix + ".0/24 dev " + tetherInterface + " table local_network proto static scope link")
                && shellCommand("ip -6 route add " + ipv6Prefix + "/64 dev " + tetherInterface + " table local_network proto static scope link")
                && shellCommand("ip -6 route add " + tetherLocalPrefix + "::/64 dev " + tetherInterface + " table local_network proto static scope link");
    }

    static void unconfigureRoutes(String tetherInterface) {
        Log.i("USBTether", "Removing IP routes");
        shellCommand("ip route flush dev " + tetherInterface);
        shellCommand("ip -6 route flush dev " + tetherInterface);
    }

    static boolean configureRules(String tetherInterface, String ipv4Interface, String ipv6Interface) {
        Log.i("USBTether", "Setting IP rules");
        return shellCommand("ip rule add pref 500 from all iif lo oif " + tetherInterface + " uidrange 0-0 lookup local_network")
                && shellCommand("ip rule add pref 510 from all iif lo oif " + tetherInterface + " lookup local_network")
                && shellCommand("ip rule add pref 540 from all iif " + tetherInterface + " lookup " + ipv4Interface)
                && shellCommand("ip -6 rule add pref 500 from all iif lo oif " + tetherInterface + " uidrange 0-0 lookup local_network")
                && shellCommand("ip -6 rule add pref 510 from all iif lo oif " + tetherInterface + " lookup local_network")
                && shellCommand("ip -6 rule add pref 540 from all iif " + tetherInterface + " lookup " + ipv6Interface);
    }

    static void unconfigureRules() {
        Log.i("USBTether", "Removing IP rules");
        shellCommand("ip rule del pref 500");
        shellCommand("ip rule del pref 510");
        shellCommand("ip rule del pref 540");
        shellCommand("ip -6 rule del pref 500");
        shellCommand("ip -6 rule del pref 510");
        shellCommand("ip -6 rule del pref 540");
    }

    static boolean configureInterface(String tetherInterface, String tetherLocalPrefix, String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix) {
        Log.i("USBTether", "Configuring interface");
        return shellCommand("ip link set dev " + tetherInterface + " down")
                && configureAddresses(tetherInterface, ipv4Addr, ipv6Prefix)
                && configureRoutes(tetherInterface, tetherLocalPrefix, ipv4Addr, ipv6Prefix)
                && configureRules(tetherInterface, ipv4Interface, ipv6Interface);
    }

    static void unconfigureInterface(String tetherInterface) {
        Log.i("USBTether", "Unconfiguring interface");
        unconfigureRules();
        unconfigureRoutes(tetherInterface);
        unconfigureAddresses(tetherInterface);
    }

    static private void configureNAT(boolean isIPv6, String tetherInterface, String upstreamInterface, String upstreamIP, boolean useSNAT) {
        // Used to find the names of chains
        String prefix = "natctrl";
        String counter = prefix + "_tether";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            prefix = "tetherctrl";
            counter = prefix;
        }

        // Add conntrack helpers - android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N
        iptables(isIPv6, "raw", "A", prefix + "_raw_PREROUTING -i " + tetherInterface + " -p tcp -m tcp --dport 21 -j CT --helper ftp");
        iptables(isIPv6, "raw", "A", prefix + "_raw_PREROUTING -i " + tetherInterface + " -p tcp -m tcp --dport 1723 -j CT --helper pptp");

        // Enable MSS Clamping
        iptables(isIPv6, "mangle", "A", prefix + "_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");

        // Insert forwarding rules
        iptables(isIPv6, "filter", "I", prefix + "_FORWARD -i " + tetherInterface + " -o " + upstreamInterface + " -g " + counter + "_counters");
        iptables(isIPv6, "filter", "I", prefix + "_FORWARD -i " + tetherInterface + " -o " + upstreamInterface + " -m state --state INVALID -j DROP");
        iptables(isIPv6, "filter", "I", prefix + "_FORWARD -i " + upstreamInterface + " -o " + tetherInterface + " -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
        iptables(isIPv6, "filter", "A", prefix + "_FORWARD -j DROP");
        // Remove rule that forwards all packets if it exists
        iptables(isIPv6, "filter", "D", prefix + "_FORWARD -g " + counter + "_counters");

        // Add MASQUERADE/SNAT rule
        if (isIPv6) {
            // Android will not create the NAT6 chain for us
            iptables(true, "nat", "N", prefix + "_nat_POSTROUTING");
            iptables(true, "nat", "A", "POSTROUTING -j " + prefix + "_nat_POSTROUTING");
        }
        if (useSNAT) {
            iptables(isIPv6, "nat", "A", prefix + "_nat_POSTROUTING -o " + upstreamInterface + " -j SNAT --to " + upstreamIP);
        } else {
            iptables(isIPv6, "nat", "A", prefix + "_nat_POSTROUTING -o " + upstreamInterface + " -j MASQUERADE");
        }
    }

    static private void unconfigureNAT(boolean isIPv6, String tetherInterface, String upstreamInterface, String upstreamIP, boolean useSNAT) {
        String prefix = "natctrl";
        String counter = prefix + "_tether";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            prefix = "tetherctrl";
            counter = prefix;
        }

        iptables(isIPv6, "raw", "D", prefix + "_raw_PREROUTING -i " + tetherInterface + " -p tcp -m tcp --dport 21 -j CT --helper ftp");
        iptables(isIPv6, "raw", "D", prefix + "_raw_PREROUTING -i " + tetherInterface + " -p tcp -m tcp --dport 1723 -j CT --helper pptp");

        iptables(isIPv6, "filter", "D", prefix + "_FORWARD -i " + tetherInterface + " -o " + upstreamInterface + " -g " + counter + "_counters");
        iptables(isIPv6, "filter", "D", prefix + "_FORWARD -i " + tetherInterface + " -o " + upstreamInterface + " -m state --state INVALID -j DROP");
        iptables(isIPv6, "filter", "D", prefix + "_FORWARD -i " + upstreamInterface + " -o " + tetherInterface + " -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");

        if (useSNAT) {
            iptables(isIPv6, "nat", "D", prefix + "_nat_POSTROUTING -o " + upstreamInterface + " -j SNAT --to " + upstreamIP);
        } else {
            iptables(isIPv6, "nat", "D", prefix + "_nat_POSTROUTING -o " + upstreamInterface + " -j MASQUERADE");
        }
    }

    static private void configureTPROXY() {
        iptables(true, "mangle", "N", "TPROXY_ROUTE_PREROUTING");
        iptables(true, "mangle", "A", "PREROUTING -j TPROXY_ROUTE_PREROUTING");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d :: -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d ::1 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d ::ffff:0:0:0/96 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d 64:ff9b::/96 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d 100::/64 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d 2001::/32 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d 2001:20::/28 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d 2001:db8::/32 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d 2002::/16 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d fc00::/7 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d fe80::/10 -j RETURN");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -d ff00::/8 -j RETURN");
        iptables(true, "mangle", "N", "TPROXY_MARK_PREROUTING");
        iptables(true, "mangle", "A", "TPROXY_ROUTE_PREROUTING -j TPROXY_MARK_PREROUTING");
        iptables(true, "mangle", "A", "TPROXY_MARK_PREROUTING -p tcp -j TPROXY --on-ip ::1 --on-port 1088 --tproxy-mark 1088");
        iptables(true, "mangle", "A", "TPROXY_MARK_PREROUTING -p udp -j TPROXY --on-ip ::1 --on-port 1088 --tproxy-mark 1088");
        shellCommand("ip -6 rule add pref 530 fwmark 1088 table 999");
        shellCommand("ip -6 route add local default dev lo table 999");
    }

    static private void unconfigureTPROXY() {
        iptables(true, "mangle", "D", "TPROXY_ROUTE_PREROUTING -j TPROXY_MARK_PREROUTING");
        iptables(true, "mangle", "F", "TPROXY_MARK_PREROUTING");
        iptables(true, "mangle", "X", "TPROXY_MARK_PREROUTING");
        iptables(true, "mangle", "D", "PREROUTING -j TPROXY_ROUTE_PREROUTING");
        iptables(true, "mangle", "F", "TPROXY_ROUTE_PREROUTING");
        iptables(true, "mangle", "X", "TPROXY_ROUTE_PREROUTING");
        shellCommand("ip -6 rule delete pref 530 fwmark 1088 table 999");
        shellCommand("ip -6 route delete local default dev lo table 999");
    }

    static void setTPROXYRoute(String prefix) {
        iptables(true, "mangle", "I", "TPROXY_ROUTE_PREROUTING -d " + prefix + "::/64 -j RETURN");
    }

    static boolean configureTether(String tetherInterface, String tetherLocalPrefix, String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, String ipv6TYPE,/* upstreamIPv4,*/ String upstreamIPv6, boolean mangleTTL, boolean dnsmasq, String libDIR, String appData, String clientBandwidth, boolean dpiCircumvention) {
        if (configureInterface(tetherInterface, tetherLocalPrefix, ipv4Interface, ipv6Interface, ipv4Addr, ipv6Prefix)) {
            Log.i("USBTether", "Enabling IP forwarding");
            shellCommand("echo 1 > /proc/sys/net/ipv4/ip_forward");
            shellCommand("echo 1 > /proc/sys/net/ipv6/conf/all/forwarding");
            Log.i("USBTether", "Setting up NAT");
            configureNAT(false, tetherInterface, ipv4Interface, "", false);
            if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                configureNAT(true, tetherInterface, ipv6Interface, upstreamIPv6, ipv6TYPE.equals("SNAT"));
            } else if (ipv6TYPE.equals("TPROXY")) {
                configureTPROXY();
            }
            String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
            if (Integer.parseInt(clientBandwidth) > 0) { // Set the maximum allowed bandwidth per IP address
                iptables(false, "filter", "A", "FORWARD -i " + ipv4Interface + " -o " + tetherInterface + " -d " + ipv4Prefix + ".0/24 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) { // Not supported by TPROXY
                    iptables(true, "filter", "A", "FORWARD -i " + ipv6Interface + " -o " + tetherInterface + " -d " + ipv6Prefix + "/64 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
                }
            }
            if (dnsmasq) {
                // DNSMasq has a bug with --port when an interface is lost and restored, it will lose it's UDP binding and will never restore it
                shellCommand("rm " + appData + "/dnsmasq.pid");
                if (ipv6TYPE.equals("None")) {
                    shellCommand(libDIR + "/libdnsmasq.so --bind-interfaces --interface=" + tetherInterface + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --server=8.8.8.8 --server=8.8.4.4 --leasefile-ro --pid-file=" + appData + "/dnsmasq.pid &");
                } else {
                    shellCommand(libDIR + "/libdnsmasq.so --bind-interfaces --interface=" + tetherInterface + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --server=8.8.8.8 --server=8.8.4.4 --server=2001:4860:4860::8888 --server=2001:4860:4860::8844 --leasefile-ro --pid-file=" + appData + "/dnsmasq.pid &");
                }
            }
            if (ipv6TYPE.equals("TPROXY")) {
                shellCommand("rm " + appData + "/socks.pid");
                shellCommand("rm " + appData + "/tproxy.pid");
                shellCommand(libDIR + "/libhevserver.so " + appData + "/socks.yml &");
                shellCommand(libDIR + "/libhevtproxy.so " + appData + "/tproxy.yml &");
            }
            if (mangleTTL && hasTTL) {
                iptables(false, "mangle", "A", "FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -j TTL --ttl-set 64");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                    iptables(true, "mangle", "A", "FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -j HL --hl-set 64");
                }
            }
            // TODO use connbytes where available to avoid desync on subsequent packets in a connection
            if (hasNFQUEUE && ((mangleTTL && !hasTTL) || dpiCircumvention)) {
                iptables(false, "mangle", "A", "FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -j NFQUEUE --queue-num 6465");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                    iptables(true, "mangle", "A", "FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -j NFQUEUE --queue-num 6465");
                }
                String optTTL = "";
                if (mangleTTL && !hasTTL) {
                    optTTL = "--force-ttl ";
                }
                String optDPI = "";
                if (dpiCircumvention) {
                    optDPI = "--dpi-desync=multisplit ";
                }
                shellCommand("rm " + appData + "/nfqws.pid");
                shellCommand(libDIR + "/libnfqws.so " + optTTL + optDPI + "--qnum=6465 --pidfile=" + appData + "/nfqws.pid &");
            }
            if (dpiCircumvention && (!hasNFQUEUE || ipv6TYPE.equals("TPROXY"))) {
                if (!hasNFQUEUE) {
                    iptables(false, "nat", "I", "PREROUTING -i " + tetherInterface + " -p tcp --dport 80 -j DNAT --to " + ipv4Addr + ":8123");
                    iptables(false, "nat", "I", "PREROUTING -i " + tetherInterface + " -p tcp --dport 443 -j DNAT --to " + ipv4Addr + ":8123");
                    if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                        iptables(true, "nat", "I", "PREROUTING -i " + tetherInterface + " -p tcp --dport 80 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                        iptables(true, "nat", "I", "PREROUTING -i " + tetherInterface + " -p tcp --dport 443 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                    }
                }
                if (ipv6TYPE.equals("TPROXY")) {
                    // Huh, only need the IP_TRANSPARENT patch for IPv4?
                    iptables(true, "mangle", "I", "TPROXY_MARK_PREROUTING -p tcp --dport 80 -j TPROXY --on-ip " + ipv6Prefix + "1 --on-port 8123 --tproxy-mark 8123");
                    iptables(true, "mangle", "I", "TPROXY_MARK_PREROUTING -p tcp --dport 443 -j TPROXY --on-ip " + ipv6Prefix + "1 --on-port 8123 --tproxy-mark 8123");
                    shellCommand("ip -6 rule add pref 520 fwmark 8123 table 998");
                    shellCommand("ip -6 route add local default dev lo table 998");
                }
                shellCommand("rm " + appData + "/tpws.pid");
                shellCommand(libDIR + "/libtpws.so --bind-addr=" + ipv4Addr + " --bind-addr=" + ipv6Prefix + "1 --port=8123 --pidfile=" + appData + "/tpws.pid --split-pos=3 --uid 1:3003 &");
            }
        } else {
            Log.w("USBTether",  tetherInterface + " unavailable, aborting tether...");
            return false;
        }
        return true;
    }

    static void unconfigureTether(String tetherInterface, String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, String ipv6TYPE,/* upstreamIPv4,*/ String upstreamIPv6, boolean mangleTTL, boolean dnsmasq, String appData, String clientBandwidth, boolean dpiCircumvention) {
        String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
        Log.i("USBTether", "Restoring tether interface state");
        if (dnsmasq) {
            killProcess(appData + "/dnsmasq.pid");
        }
        if (ipv6TYPE.equals("TPROXY")) {
            killProcess(appData + "/socks.pid");
            killProcess(appData + "/tproxy.pid");
        }
        if (mangleTTL && hasTTL) {
            iptables(false, "mangle", "D", "FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -j TTL --ttl-set 64");
            if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) { // Won't work with encapsulated traffic
                iptables(true, "mangle", "D", "FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -j HL --hl-set 64");
            }
        }
        if (hasNFQUEUE && ((mangleTTL && !hasTTL) || dpiCircumvention)) {
            killProcess(appData + "/nfqws.pid");
            iptables(false, "mangle", "D", "FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -j NFQUEUE --queue-num 6465");
            if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                iptables(true, "mangle", "D", "FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -j NFQUEUE --queue-num 6465");
            }
        }
        if (dpiCircumvention && (!hasNFQUEUE || ipv6TYPE.equals("TPROXY"))) {
            killProcess(appData + "/tpws.pid");
            if (!hasNFQUEUE) {
                iptables(false, "nat", "D", "PREROUTING -i " + tetherInterface + " -p tcp --dport 80 -j DNAT --to " + ipv4Addr + ":8123");
                iptables(false, "nat", "D", "PREROUTING -i " + tetherInterface + " -p tcp --dport 443 -j DNAT --to " + ipv4Addr + ":8123");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                    iptables(true, "nat", "D", "PREROUTING -i " + tetherInterface + " -p tcp --dport 80 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                    iptables(true, "nat", "D", "PREROUTING -i " + tetherInterface + " -p tcp --dport 443 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                }
            }
            if (ipv6TYPE.equals("TPROXY")) {
                iptables(true, "mangle", "D", "TPROXY_MARK_PREROUTING -p tcp --dport 80 -j TPROXY --on-ip " + ipv6Prefix + "1 --on-port 8123 --tproxy-mark 8123");
                iptables(true, "mangle", "D", "TPROXY_MARK_PREROUTING -p tcp --dport 443 -j TPROXY --on-ip " + ipv6Prefix + "1 --on-port 8123 --tproxy-mark 8123");
                shellCommand("ip -6 rule delete pref 520 fwmark 8123 table 998");
                shellCommand("ip -6 route delete local default dev lo table 998");
            }
        }
        if (Integer.parseInt(clientBandwidth) > 0) {
            iptables(false, "filter", "D", "FORWARD -i " + ipv4Interface + " -o " + tetherInterface + " -d " + ipv4Prefix + ".0/24 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
            if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) { // Not supported by TPROXY
                iptables(true, "filter", "D", "FORWARD -i " + ipv6Interface + " -o " + tetherInterface + " -d " + ipv6Prefix + "/64 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
            }
        }
        unconfigureNAT(false, tetherInterface, ipv4Interface, "", false);
        if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
            unconfigureNAT(true, tetherInterface, ipv6Interface, upstreamIPv6, ipv6TYPE.equals("SNAT"));
        } else if (ipv6TYPE.equals("TPROXY")) {
            unconfigureTPROXY();
        }
        unconfigureInterface(tetherInterface);
        shellCommand("echo 0 > /proc/sys/net/ipv4/ip_forward");
        shellCommand("echo 0 > /proc/sys/net/ipv6/conf/all/forwarding");
    }

    static void checkProcesses(String tetherInterface, String ipv4Addr, String ipv6Prefix, String ipv6TYPE, boolean mangleTTL, boolean dnsmasq, boolean dpiCircumvention, String libDIR, String appData) {
        if (dnsmasq) {
            if (!shellCommand("[ -f " + appData + "/dnsmasq.pid -a -d /proc/$(cat " + appData + "/dnsmasq.pid) ]")) {
                String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
                Log.w("USBTether", "No dnsmasq process, restarting");
                shellCommand("rm " + appData + "/dnsmasq.pid");
                if (ipv6TYPE.equals("None")) {
                    shellCommand(libDIR + "/libdnsmasq.so --bind-interfaces --interface=" + tetherInterface + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --server=8.8.8.8 --server=8.8.4.4 --leasefile-ro --pid-file=" + appData + "/dnsmasq.pid &");
                } else {
                    shellCommand(libDIR + "/libdnsmasq.so --bind-interfaces --interface=" + tetherInterface + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --server=8.8.8.8 --server=8.8.4.4 --server=2001:4860:4860::8888 --server=2001:4860:4860::8844 --leasefile-ro --pid-file=" + appData + "/dnsmasq.pid &");
                }
            }
        }
        if (hasNFQUEUE && ((mangleTTL && !hasTTL) || dpiCircumvention)) {
            if (!shellCommand("[ -f " + appData + "/nfqws.pid -a -d /proc/$(cat " + appData + "/nfqws.pid) ]")) {
                Log.w("USBTether", "No nfqws process, restarting");
                String optTTL = "";
                if (mangleTTL && !hasTTL) {
                    optTTL = "--force-ttl ";
                }
                String optDPI = "";
                if (dpiCircumvention) {
                    optDPI = "--dpi-desync=multisplit ";
                }
                shellCommand("rm " + appData + "/nfqws.pid");
                shellCommand(libDIR + "/libnfqws.so " + optTTL + optDPI + "--qnum=6465 --pidfile=" + appData + "/nfqws.pid &");
            }
        }
        if (dpiCircumvention && (!hasNFQUEUE || ipv6TYPE.equals("TPROXY"))) {
            if (!shellCommand("[ -f " + appData + "/tpws.pid -a -d /proc/$(cat " + appData + "/tpws.pid) ]")) {
                Log.w("USBTether", "No tpws process, restarting");
                shellCommand("rm " + appData + "/tpws.pid");
                shellCommand(libDIR + "/libtpws.so --bind-addr=" + ipv4Addr + " --bind-addr=" + ipv6Prefix + "1 --port=8123 --pidfile=" + appData + "/tpws.pid --split-pos=3 --uid 1:3003 &");
            }
        }
        if (ipv6TYPE.equals("TPROXY")) {
            if (!shellCommand("[ -f " + appData + "/socks.pid -a -d /proc/$(cat " + appData + "/socks.pid) ]")) {
                Log.w("USBTether", "No socks process, restarting");
                shellCommand("rm " + appData + "/socks.pid");
                shellCommand(libDIR + "/libhevserver.so " + appData + "/socks.yml &");
            }
            if (!shellCommand("[ -f " + appData + "/tproxy.pid -a -d /proc/$(cat " + appData + "/tproxy.pid) ]")) {
                Log.w("USBTether", "No tproxy process, restarting");
                shellCommand("rm " + appData + "/tproxy.pid");
                shellCommand(libDIR + "/libhevtproxy.so " + appData + "/tproxy.yml &");
            }
        }
    }

    // FIXME!!!!!! need to update IPv4 SNAT too!!!!!
    static void refreshSNAT(String tetherInterface, String ipv6Addr, String newAddr) {
        Log.w("USBTether", "Refreshing SNAT IPTables Rule");
        String prefix = "natctrl";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            prefix = "tetherctrl";
        }
        iptables(true, "nat", "D", prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + ipv6Addr);
        iptables(true, "nat", "A", prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + newAddr);
    }

    // FIXME these tests can hang on name resolution, fix this and supply binaries if needed
    //       simple ping tests are not super useful due to false positives
    /*static boolean testConnection(String upstreamInterface, boolean isIPv6) {
        String protocol = isIPv6 ? "IPv6" : "IPv4";
        if (hasCURL) {
            String testSite = "http://connectivitycheck.gstatic.com/generate_204";
            String argument = isIPv6 ? "--ipv6" : "--ipv4";
            if (Shell.cmd("curl " + argument + " --interface " + upstreamInterface + " --retry 2 --retry-max-time 5 " + testSite).exec().isSuccess()) {
                Log.i("USBTether", upstreamInterface + " " + protocol + " is online");
                return true;
            }
        } else {
            String testSite = "connectivitycheck.gstatic.com";
            String command = isIPv6 ? "ping6" : "ping";
            if (Shell.cmd(command + " -c 1 -w 3 -I " + upstreamInterface + " " + testSite).exec().isSuccess()
                    || Shell.cmd(command + " -c 1 -w 3 -I " + upstreamInterface + " " + testSite).exec().isSuccess()) {
                Log.i("USBTether", upstreamInterface + " " + protocol + " is online");
                return true;
            }
        }
        Log.w("USBTether", upstreamInterface + " " + protocol + " is offline");
        return false;
    }*/

    static boolean testConnection(String upstreamInterface, boolean isIPv6) {
        String protocol = isIPv6 ? "IPv6" : "IPv4";
        String command = isIPv6 ? "ping6" : "ping";
        if (Shell.cmd(command + " -c 1 -w 3 -I " + upstreamInterface + " " + (isIPv6 ? "2001:4860:4860::8888" : "8.8.8.8")).exec().isSuccess()
                || Shell.cmd(command + " -c 1 -w 3 -I " + upstreamInterface + " " + (isIPv6 ? "2606:4700:4700::1111" : "1.1.1.1")).exec().isSuccess()) {
            Log.i("USBTether", upstreamInterface + " " + protocol + " is online");
            return true;
        }
        Log.w("USBTether", upstreamInterface + " " + protocol + " is offline");
        return false;
    }

    static void startGoogleOneVPN() {
        Log.w("USBTether", "Starting Google One VPN");
        shellCommand("input keyevent KEYCODE_WAKEUP");
        shellCommand("am start -W com.google.android.apps.subscriptions.red/com.google.android.apps.subscriptions.red.main.MainActivity");
        shellCommand("am startservice com.google.android.apps.subscriptions.red/com.google.android.libraries.privacy.ppn.PpnVpnService");
    }

    static void stopGoogleOneVPN() {
        Log.w("USBTether", "Stopping Google One VPN");
        shellCommand("am force-stop com.google.android.apps.subscriptions.red");
    }

    // FIXME - this still has trouble launching on failure, even with no lockscreen
    static void startCloudflare1111Warp() {
        Log.w("USBTether", "Starting Cloudflare 1.1.1.1 Warp");
        shellCommand("input keyevent KEYCODE_WAKEUP");
        shellCommand("am start -W com.cloudflare.onedotonedotonedotone/com.cloudflare.app.presentation.main.MainActivity");
        shellCommand("am startservice com.cloudflare.onedotonedotonedotone/com.cloudflare.app.vpnservice.CloudflareVpnService");
    }

    static void stopCloudflare1111Warp() {
        Log.w("USBTether", "Stopping Cloudflare 1.1.1.1 Warp");
        shellCommand("am force-stop com.cloudflare.onedotonedotonedotone");
    }

    static void recoverDataConnection() {
        Log.w("USBTether", "Restarting mobile data");
        // get current id, mcc, mnc
        Shell.Result command = Shell.cmd("content query --uri content://telephony/carriers/preferapn --projection _id:mcc:mnc | awk -F '[=,]' '{print $2,$4,$6}'").exec();
        if ( command.isSuccess() ) {
            String[] parts = command.getOut().get(0).split(" ");
            if ( parts.length == 3) {
                // insert dummy apn
                shellCommand("content insert --uri content://telephony/carriers --bind name:s:usbt_dummy --bind numeric:s:" + parts[1] + parts[2] + " --bind mcc:s:" + parts[1] + " --bind mnc:s:" + parts[2] + " --bind type:s:default --bind current:s:1 --bind apn:s:test --bind edited:s:1");
                // get dummy id
                command = Shell.cmd("content query --uri content://telephony/carriers --where \"name='usbt_dummy'\" --projection _id | awk -F '=' '{print $2}'").exec();
                if ( command.isSuccess() ) {
                    String id = command.getOut().get(0);
                    // select dummy apn
                    shellCommand("content insert --uri content://telephony/carriers/preferapn --bind apn_id:i:" + id);
                    // restart data
                    shellCommand("svc data disable");
                    shellCommand("svc data enable");
                    // select preferred apn
                    shellCommand("content insert --uri content://telephony/carriers/preferapn --bind apn_id:i:" + parts[0]);
                    // restart data again
                    shellCommand("svc data disable");
                    shellCommand("svc data enable");
                }
                // delete dummy apn
                shellCommand("content delete --uri content://telephony/carriers --where \"name='usbt_dummy'\"");
            }
        }
    }
}
