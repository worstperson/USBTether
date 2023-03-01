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

    static private void shellCommand(String command) {
        for (String message : Shell.cmd(command).exec().getOut()) {
            Log.i("USBTether", message);
        }
    }

    static boolean hasTTL() {
        return Shell.cmd("iptables -j TTL --help | grep \"TTL\"").exec().isSuccess();
    }

    static boolean hasTPROXY() {
        return Shell.cmd("ip6tables -j TPROXY --help | grep \"TPROXY\"").exec().isSuccess();
    }

    static boolean hasTable() {
        return Shell.cmd("ip6tables --table nat --list").exec().isSuccess();
    }

    static boolean hasSNAT() {
        return Shell.cmd("ip6tables -j SNAT --help | grep \"SNAT\"").exec().isSuccess();
    }

    static boolean hasMASQUERADE() {
        return Shell.cmd("ip6tables -j MASQUERADE --help | grep \"MASQUERADE\"").exec().isSuccess();
    }

    static boolean isUSBConfigured() {
        return Shell.cmd("[ \"$(cat /sys/class/android_usb/android0/state)\" = \"CONFIGURED\" ]").exec().isSuccess();
    }

    static void killProcess(String pidFile) {
        if ( Shell.cmd("[ -f " + pidFile + " -a -d /proc/$(cat " + pidFile + ") ]").exec().isSuccess()) {
            shellCommand("kill -s 9 $(cat " + pidFile + ")");
        }
    }

    static void addIPT(String table, boolean append, String rule) {
        String tab = table.equals("") ? " " : " -t " + table + " ";
        String op = append ? "-A " : "-I ";
        if (!Shell.cmd("iptables" + tab + "-C " + rule).exec().isSuccess()) {
            shellCommand("iptables" + tab + op + rule);
        }
    }

    static void addIP6T(String table, boolean append, String rule) {
        String tab = table.equals("") ? " " : " -t " + table + " ";
        String op = append ? "-A " : "-I ";
        if (!Shell.cmd("ip6tables" + tab + "-C " + rule).exec().isSuccess()) {
            shellCommand("ip6tables" + tab + op + rule);
        }
    }

    static String[] gadgetVars() {
        String[] result = new String[]{ null, null, null };
        Shell.Result command = Shell.cmd("find /config/usb_gadget/* -maxdepth 0 -type d").exec();
        if ( command.isSuccess() ) {
            for (String result1 : command.getOut()) {
                result[0] = result1;
                if (Shell.cmd("[ \"$(cat " + result[0] + "/UDC )\" = \"$(getprop sys.usb.controller)\" ]").exec().isSuccess()) {
                    Shell.Result command2 = Shell.cmd("find " + result[0] + "/configs/* -maxdepth 0 -type d").exec();
                    if ( command2.isSuccess() ) {
                        for (String result2 : command2.getOut()) {
                            result[1] = result2;
                            break;
                        }
                    }
                    command2 = Shell.cmd("find " + result[0] + "/functions/rndis.* -maxdepth 0 -type d").exec();
                    if ( command2.isSuccess() ) {
                        for (String result2 : command2.getOut()) {
                            if (Shell.cmd("ls -A " + result2).exec().isSuccess()) {
                                result[2] = result2;
                                break;
                            }
                        }
                    }
                    if (result[2] == null) {
                        command2 = Shell.cmd("find " + result[0] + "/functions/*.rndis -maxdepth 0 -type d").exec();
                        if (command2.isSuccess()) {
                            for (String result2 : command2.getOut()) {
                                if (Shell.cmd("ls -A " + result2).exec().isSuccess()) {
                                    result[2] = result2;
                                    break;
                                }
                            }
                        }
                    }
                    if (result[0] != null && result[1] != null && result[2] != null) {
                        break;
                    }
                }
                result = new String[]{null, null, null};
            }
        }
        return result;
    }

    static private boolean configureAddresses(String ipv4Addr, String ipv6Prefix, String ipv6TYPE) {
        Log.i("USBTether", "Setting IP addresses");
        if (ipv6TYPE.equals("None")) {
            shellCommand("ndc interface setcfg rndis0 " + ipv4Addr + " 24 up");
            return true;
        }
        shellCommand("ip -6 addr add " + ipv6Prefix + "1/64 dev rndis0 scope global");
        shellCommand("ndc interface setcfg rndis0 " + ipv4Addr + " 24 up");
        Log.i("USBTether", "Waiting for interface to come up");
        for (int waitTime = 1; waitTime <= 5; waitTime++) {
            if (Shell.cmd("[ \"$(cat /sys/class/net/rndis0/operstate)\" = \"up\" ]").exec().isSuccess()) {
                break;
            }
            Log.i("USBTether", "waiting... " + waitTime);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        if (Shell.cmd("[ \"$(cat /sys/class/net/rndis0/operstate)\" = \"up\" ]").exec().isSuccess()) {
            shellCommand("ip -6 route add " + ipv6Prefix + "/64 dev rndis0 src " + ipv6Prefix + "1");
            return true;
        } else {
            return false;
        }
    }

    static boolean configureRoutes(String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, String ipv6TYPE) {
        if (!Shell.cmd("ip link set dev rndis0 down").exec().isSuccess()) {
            Log.w("usbtether", "No tether interface...");
        } else {
            forwardInterface(ipv4Interface, ipv6Interface);
            if (configureAddresses(ipv4Addr, ipv6Prefix, ipv6TYPE)) {
                String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
                Log.i("USBTether", "Adding marked routes");
                shellCommand("ndc network interface add 99 rndis0");
                shellCommand("ndc network route add 99 rndis0 " + ipv4Prefix + ".0/24");
                shellCommand("ndc network route add 99 rndis0 " + ipv6Prefix + "/64");
                shellCommand("ndc network route add 99 rndis0 fe80::/64");
                return true;
            }
        }
        return false;
    }

    static void unconfigureRoutes(String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix) {
        String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
        unforwardInterface(ipv4Interface, ipv6Interface);
        shellCommand("ip -6 route del " + ipv6Prefix  + "/64 dev rndis0 src " + ipv6Prefix  + "1");
        shellCommand("ndc interface clearaddrs rndis0");
        shellCommand("ndc interface setcfg rndis0 down");
        Log.i("USBTether", "Removing marked routes");
        shellCommand("ndc network route remove 99 rndis0 " + ipv4Prefix + ".0/24");
        shellCommand("ndc network route remove 99 rndis0 " + ipv6Prefix + "/64");
        shellCommand("ndc network route remove 99 rndis0 fe80::/64");
        shellCommand("ndc network interface remove 99 rndis0");
    }

    static void forwardInterface(String ipv4Interface, String ipv6Interface) {
        shellCommand("ndc ipfwd add rndis0 " + ipv6Interface);
        if (!ipv6Interface.equals(ipv4Interface)) {
            shellCommand("ndc ipfwd add rndis0 " + ipv4Interface);
        }
    }

    static void unforwardInterface(String ipv4Interface, String ipv6Interface) {
        shellCommand("ndc ipfwd remove rndis0 " + ipv6Interface);
        if (!ipv6Interface.equals(ipv4Interface)) {
            shellCommand("ndc ipfwd remove rndis0 " + ipv4Interface);
        }
    }

    static private void configureNAT(String ipv4Interface, String ipv6Interface, String ipv6TYPE, String ipv6Addr) {
        Log.i("USBTether", "Setting up NAT");
        shellCommand("ndc nat enable rndis0 " + ipv4Interface + " 99");
        if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
            String prefix = "natctrl";
            String counter = prefix+"_tether";
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                prefix = "tetherctrl";
                counter = prefix;
            }
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -g " + counter + "_counters");
            addIP6T("filter", true, prefix + "_FORWARD -i " + ipv6Interface + " -o rndis0 -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
            addIP6T("filter", true, prefix + "_FORWARD -i rndis0 -o " + ipv6Interface + " -m state --state INVALID -j DROP");
            addIP6T("filter", true, prefix + "_FORWARD -i rndis0 -o " + ipv6Interface + " -g " + counter + "_counters");
            addIP6T("filter", true, prefix + "_FORWARD -j DROP");
            addIP6T("mangle", true, prefix + "_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");
            shellCommand("ip6tables -t nat -N " + prefix + "_nat_POSTROUTING");
            addIP6T("nat", true, "POSTROUTING -j " + prefix + "_nat_POSTROUTING");
            if (ipv6TYPE.equals("SNAT")) {
                addIP6T("nat", true, prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j SNAT --to " + ipv6Addr);
            } else {
                addIP6T("nat", true, prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j MASQUERADE");
            }
        } else if (ipv6TYPE.equals("TPROXY")) {
            shellCommand("ip6tables -t mangle -N TPROXY_ROUTE_PREROUTING");
            addIP6T("mangle", true, "PREROUTING -j TPROXY_ROUTE_PREROUTING");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d :: -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d ::1 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d ::ffff:0:0:0/96 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d 64:ff9b::/96 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d 100::/64 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d 2001::/32 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d 2001:20::/28 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d 2001:db8::/32 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d 2002::/16 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d fc00::/7 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d fe80::/10 -j RETURN");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -d ff00::/8 -j RETURN");
            shellCommand("ip6tables -t mangle -N TPROXY_MARK_PREROUTING");
            addIP6T("mangle", true, "TPROXY_ROUTE_PREROUTING -j TPROXY_MARK_PREROUTING");
            addIP6T("mangle", true, "TPROXY_MARK_PREROUTING -p tcp -j TPROXY --on-ip ::1 --on-port 1088 --tproxy-mark 1088");
            addIP6T("mangle", true, "TPROXY_MARK_PREROUTING -p udp -j TPROXY --on-ip ::1 --on-port 1088 --tproxy-mark 1088");
            shellCommand("ip -6 rule add fwmark 1088 table 999");
            shellCommand("ip -6 route add local default dev lo table 999");
        }
    }

    static private void unconfigureNAT(String ipv4Interface, String ipv6Interface, String ipv6TYPE, String ipv6Addr) {
        if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
            String prefix = "natctrl";
            String counter = prefix + "_tether";
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                prefix = "tetherctrl";
                counter = prefix;
            }
            if (ipv6TYPE.equals("SNAT")) {
                shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j SNAT --to " + ipv6Addr);
            } else {
                shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j MASQUERADE");
            }
            shellCommand("ip6tables -t nat -D POSTROUTING -j " + prefix + "_nat_POSTROUTING");
            shellCommand("ip6tables -t nat -X " + prefix + "_nat_POSTROUTING");
            shellCommand("ip6tables -t mangle -D tetherctrl_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -j DROP");
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i rndis0 -o " + ipv6Interface + " -g " + counter + "_counters");
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i rndis0 -o " + ipv6Interface + " -m state --state INVALID -j DROP");
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i " + ipv6Interface + " -o rndis0 -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
        } else if (ipv6TYPE.equals("TPROXY")) {
            shellCommand("ip6tables -t mangle -D TPROXY_ROUTE_PREROUTING -j TPROXY_MARK_PREROUTING");
            shellCommand("ip6tables -t mangle -F TPROXY_MARK_PREROUTING");
            shellCommand("ip6tables -t mangle -X TPROXY_MARK_PREROUTING");
            shellCommand("ip6tables -t mangle -D PREROUTING -j TPROXY_ROUTE_PREROUTING");
            shellCommand("ip6tables -t mangle -F TPROXY_ROUTE_PREROUTING");
            shellCommand("ip6tables -t mangle -X TPROXY_ROUTE_PREROUTING");
            shellCommand("ip -6 rule delete fwmark 1088 table 999");
            shellCommand("ip -6 route delete local default dev lo table 999");
        }
        shellCommand("ndc nat disable rndis0 " + ipv4Interface + " 99");
    }

    static void setTPROXYRoute(String prefix) {
        addIP6T("mangle", false, "TPROXY_ROUTE_PREROUTING -d " + prefix + "::/64 -j RETURN");
    }

    //    *T-Mobile runs a NAT for IPv4 and open for IPv6.
    //    *AT&T runs a NAT for both IPv4 and IPv6, no port forwarding possible without a tunnel.
    //    *Verizon runs a NAT for both IPv4 and IPv6, no port forwarding possible without a tunnel.
    static private void configureDMZ(String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, String ipv6TYPE) {
        String prefix = "natctrl";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            prefix = "tetherctrl";
        }
        String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
        addIPT("nat", true, "PREROUTING -i " + ipv4Interface + " -p tcp -j DNAT --to-destination " + ipv4Prefix + ".5");
        addIPT("nat", true, "PREROUTING -i " + ipv4Interface + " -p udp -j DNAT --to-destination " + ipv4Prefix + ".5");
        addIPT("", false, prefix + "_FORWARD -p tcp -d " + ipv4Prefix + ".5 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
        if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
            addIP6T("nat", true, "PREROUTING -i " + ipv6Interface + " -p tcp -j DNAT --to-destination " + ipv6Prefix + "5");
            addIP6T("nat", true, "PREROUTING -i " + ipv6Interface + " -p udp -j DNAT --to-destination " + ipv6Prefix + "5");
            addIP6T("", false, prefix + "_FORWARD -p tcp -d " + ipv6Prefix + "5 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
        }
    }

    static private void unconfigureDMZ(String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, String ipv6TYPE) {
        String prefix = "natctrl";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            prefix = "tetherctrl";
        }
        String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
        shellCommand("iptables -t nat -D PREROUTING -i " + ipv4Interface + " -p tcp -j DNAT --to-destination " + ipv4Prefix + ".5");
        shellCommand("iptables -t nat -D PREROUTING -i " + ipv4Interface + " -p udp -j DNAT --to-destination " + ipv4Prefix + ".5");
        shellCommand("iptables -D " + prefix + "_FORWARD -p tcp -d " + ipv4Prefix + ".5 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
        if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
            shellCommand("ip6tables -t nat -D PREROUTING -i " + ipv6Interface + " -p tcp -j DNAT --to-destination " + ipv6Prefix + "5");
            shellCommand("ip6tables -t nat -D PREROUTING -i " + ipv6Interface + " -p udp -j DNAT --to-destination " + ipv6Prefix + "5");
            shellCommand("ip6tables -D " + prefix + "_FORWARD -p tcp -d " + ipv6Prefix + "5 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
        }
    }

    static void configureRNDIS(boolean legacyUSB, String gadgetPath, String configPath, String functionPath, String appData) {
        if (legacyUSB || configPath == null) {
            if (Shell.cmd("[ \"$(getprop sys.usb.state)\" = *\"adb\"* ]").exec().isSuccess()) {
                shellCommand("setprop sys.usb.config rndis,adb");
            } else {
                shellCommand("setprop sys.usb.config rndis");
            }
            shellCommand("n=0; while [[ $n -lt 10 ]]; do if [[ \"$(getprop sys.usb.state)\" == *\"rndis\"* ]]; then break; fi; n=$((n+1)); echo \"waiting for usb... $n\"; sleep 1; done");
        } else {
            shellCommand("echo \"none\" > " + gadgetPath + "/UDC");
            if (Shell.cmd("[ \"$(cat " + configPath + "/strings/0x409/configuration)\" = *\"adb\"* ]").exec().isSuccess()) {
                shellCommand("echo \"rndis_adb\" > " + configPath + "/strings/0x409/configuration");
            } else {
                shellCommand("echo \"rndis\" > " + configPath + "/strings/0x409/configuration");
            }
            shellCommand("ln -s " + functionPath + " " + configPath + "/usbtether");
            shellCommand("getprop sys.usb.controller > " + gadgetPath + "/UDC");
            //shellCommand("svc usb resetUsbGadget");
        }
    }

    static void unconfigureRNDIS(boolean legacyUSB, String gadgetPath, String configPath, String appData) {
        if (legacyUSB || configPath == null) {
            if (Shell.cmd("[ \"$(getprop sys.usb.state)\" = *\"adb\"* ]").exec().isSuccess()) {
                shellCommand("setprop sys.usb.config adb");
            } else {
                shellCommand("setprop sys.usb.config none");
            }
        } else {
            shellCommand("echo \"none\" > " + gadgetPath + "/UDC");
            if (Shell.cmd("[ \"$(cat " + configPath + "/strings/0x409/configuration)\" = *\"adb\"* ]").exec().isSuccess()) {
                shellCommand("echo \"adb\" > " + configPath + "/strings/0x409/configuration");
            } else {
                shellCommand("echo \"none\" > " + configPath + "/strings/0x409/configuration");
            }
            shellCommand("unlink " + configPath + "/usbtether");
            shellCommand("getprop sys.usb.controller > " + gadgetPath + "/UDC");
        }
    }

    static boolean configureTether(String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6TYPE, String ipv6Prefix, String ipv6Addr, Boolean fixTTL, Boolean dnsmasq, String appData, String clientBandwidth, boolean dpiCircumvention, boolean dmz, String configPath, String functionPath) {
        // Check that rndis0 is actually available to avoid wasting time
        if (!Shell.cmd("ip link set dev rndis0 down").exec().isSuccess()) {
            Log.w("usbtether", "rndis0 unavailable, aborting tether...");
            return false;
        } else {
            Log.i("USBTether", "Enabling IP forwarding");
            shellCommand("ndc ipfwd enable tethering");
            configureNAT(ipv4Interface, ipv6Interface, ipv6TYPE, ipv6Addr);
            if (fixTTL) {
                addIPT("mangle", true, "FORWARD -i rndis0 -o " + ipv4Interface + " -j TTL --ttl-set 64");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) { // Won't work with encapsulated traffic
                    addIP6T("mangle", true, "FORWARD -i rndis0 -o " + ipv6Interface + " -j HL --hl-set 64");
                }
            }
            String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
            if (Integer.parseInt(clientBandwidth) > 0) { // Set the maximum allowed bandwidth per IP address
                addIPT("", true, "FORWARD -i " + ipv4Interface + " -o rndis0 -d " + ipv4Prefix + ".0/24 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) { // Not supported by TPROXY
                    addIP6T("", true, "FORWARD -i " + ipv6Interface + " -o rndis0 -d " + ipv6Prefix + "/64 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
                }
            }
            if (dnsmasq) {
                addIPT("nat", false, "PREROUTING -i rndis0 -s 0.0.0.0 -d 255.255.255.255 -p udp --dport 67 -j DNAT --to-destination 255.255.255.255:6767");
                addIPT("nat", false, "PREROUTING -i rndis0 -s " + ipv4Prefix + ".0/24 -d " + ipv4Addr + " -p udp --dport 53 -j DNAT --to-destination " + ipv4Addr + ":5353");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                    addIP6T("nat", false, "PREROUTING -i rndis0 -s " + ipv6Prefix + "/64 -d " + ipv6Prefix + "1 -p udp --dport 53 -j DNAT --to-destination [" + ipv6Prefix + "1]:5353");
                }
                shellCommand("rm " + appData + "/dnsmasq.leases");
                shellCommand("rm " + appData + "/dnsmasq.pid");
                if (ipv6TYPE.equals("None")) {
                    shellCommand(appData + "/dnsmasq." + Build.SUPPORTED_ABIS[0] + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-option=option:dns-server," + ipv4Addr + " --server=8.8.8.8 --server=8.8.4.4 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                } else if (ipv6TYPE.equals("TPROXY")) { // HACK - hevtproxy IPv6 DNS proxying seems unsupported or maybe broken
                    shellCommand(appData + "/dnsmasq." + Build.SUPPORTED_ABIS[0] + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server," + ipv4Addr + " --dhcp-option=option6:dns-server,[2001:4860:4860::8888],[2001:4860:4860::8844] --server=8.8.8.8 --server=8.8.4.4 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                } else {
                    shellCommand(appData + "/dnsmasq." + Build.SUPPORTED_ABIS[0] + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server," + ipv4Addr + " --dhcp-option=option6:dns-server,[" + ipv6Prefix + "1] --server=8.8.8.8 --server=8.8.4.4 --server=2001:4860:4860::8888 --server=2001:4860:4860::8844 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                }
            }
            if (ipv6TYPE.equals("TPROXY")) {
                shellCommand("rm " + appData + "/socks.pid");
                shellCommand("rm " + appData + "/tproxy.pid");
                shellCommand(appData + "/hev-socks5-server." + Build.SUPPORTED_ABIS[0] + " " + appData + "/socks.yml &");
                shellCommand(appData + "/hev-socks5-tproxy." + Build.SUPPORTED_ABIS[0] + " " + appData + "/tproxy.yml &");
            }
            if (dpiCircumvention) {
                addIPT("nat", false, "PREROUTING -i rndis0 -p tcp --dport 80 -j DNAT --to " + ipv4Addr + ":8123");
                addIPT("nat", false, "PREROUTING -i rndis0 -p tcp --dport 443 -j DNAT --to " + ipv4Addr + ":8123");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                    addIP6T("nat", false, "PREROUTING -i rndis0 -p tcp --dport 80 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                    addIP6T("nat", false, "PREROUTING -i rndis0 -p tcp --dport 443 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                } else if (ipv6TYPE.equals("TPROXY")) {
                    // Huh, only need the IP_TRANSPARENT patch for IPv4?
                    addIP6T("mangle", false, "TPROXY_MARK_PREROUTING -p tcp --dport 80 -j TPROXY --on-ip " + ipv6Prefix + "1 --on-port 8123 --tproxy-mark 8123");
                    addIP6T("mangle", false, "TPROXY_MARK_PREROUTING -p tcp --dport 443 -j TPROXY --on-ip " + ipv6Prefix + "1 --on-port 8123 --tproxy-mark 8123");
                    shellCommand("ip -6 rule add fwmark 8123 table 998");
                    shellCommand("ip -6 route add local default dev lo table 998");
                }
            }
            if (dmz) {
                configureDMZ(ipv4Interface, ipv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE);
            }
        }
        return true;
    }

    static void unconfigureTether(String ipv4Interface, String ipv6Interface, String ipv6TYPE, String ipv4Addr, String ipv6Prefix, String ipv6Addr, Boolean fixTTL, Boolean dnsmasq, String appData, String clientBandwidth, boolean dpiCircumvention, boolean dmz) {
        String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
        if (dnsmasq) {
            killProcess(appData + "/dnsmasq.pid");
            shellCommand("iptables -t nat -D PREROUTING -i rndis0 -s " + ipv4Prefix + ".0/24 -d " + ipv4Addr + " -p udp --dport 53 -j DNAT --to-destination " + ipv4Addr + ":5353");
            shellCommand("iptables -t nat -D PREROUTING -i rndis0 -s 0.0.0.0 -d 255.255.255.255 -p udp --dport 67 -j DNAT --to-destination 255.255.255.255:6767");
            if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                shellCommand("ip6tables -t nat -D PREROUTING -i rndis0 -s " + ipv6Prefix + "/64 -d " + ipv6Prefix + "1 -p udp --dport 53 -j DNAT --to-destination [" + ipv6Prefix + "1]:5353");
            }
        }
        if (ipv6TYPE.equals("TPROXY")) {
            killProcess(appData + "/socks.pid");
            killProcess(appData + "/tproxy.pid");
        }
        if (dmz) {
            unconfigureDMZ(ipv4Interface, ipv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE);
        }
        if (dpiCircumvention) {
            killProcess(appData + "/tpws.pid");
            shellCommand("iptables -t nat -D PREROUTING -i rndis0 -p tcp --dport 80 -j DNAT --to " + ipv4Addr + ":8123");
            shellCommand("iptables -t nat -D PREROUTING -i rndis0 -p tcp --dport 443 -j DNAT --to " + ipv4Addr + ":8123");
            if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                shellCommand("ip6tables -t nat -D PREROUTING -i rndis0 -p tcp --dport 80 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                shellCommand("ip6tables -t nat -D PREROUTING -i rndis0 -p tcp --dport 443 -j DNAT --to [" + ipv6Prefix + "1]:8123");
            } else if (ipv6TYPE.equals("TPROXY")) {
                shellCommand("ip -6 rule delete fwmark 8123 table 998");
                shellCommand("ip -6 route delete local default dev lo table 998");
            }
        }
        Log.i("USBTether", "Restoring tether interface state");
        if (Integer.parseInt(clientBandwidth) > 0) {
            shellCommand("iptables -D FORWARD -i " + ipv4Interface + " -o rndis0 -d " + ipv4Prefix + ".0/24 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
            shellCommand("ip6tables -D FORWARD -i " + ipv6Interface + " -o rndis0 -d " + ipv6Prefix + "/64 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
        }
        if (fixTTL) {
            shellCommand("iptables -t mangle -D FORWARD -i rndis0 -o " + ipv4Interface + " -j TTL --ttl-set 64");
            shellCommand("ip6tables -t mangle -D FORWARD -i rndis0 -o " + ipv6Interface + " -j HL --hl-set 64");
        }
        unconfigureNAT(ipv4Interface, ipv6Interface, ipv6TYPE, ipv6Addr);
        unforwardInterface(ipv4Interface, ipv6Interface);
        unconfigureRoutes(ipv4Interface, ipv6Interface, ipv4Addr, ipv6Prefix);
        shellCommand("ndc ipfwd disable tethering");
    }

    static void checkProcesses(String ipv4Addr, String ipv6TYPE, String ipv6Prefix, Boolean dnsmasq, String appData, boolean dpiCircumvention) {
        if (dnsmasq) {
            if (!Shell.cmd("[ -f " + appData + "/dnsmasq.pid -a -d /proc/$(cat " + appData + "/dnsmasq.pid) ]").exec().isSuccess()) {
                String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
                Log.w("USBTether", "No dnsmasq process, restarting");
                shellCommand("rm " + appData + "/dnsmasq.leases");
                shellCommand("rm " + appData + "/dnsmasq.pid");
                if (ipv6TYPE.equals("None")) {
                    shellCommand(appData + "/dnsmasq." + Build.SUPPORTED_ABIS[0] + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-option=option:dns-server," + ipv4Addr + " --server=8.8.8.8 --server=8.8.4.4 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                } else if (ipv6TYPE.equals("TPROXY")) { // HACK - hevtproxy IPv6 DNS proxying seems unsupported or maybe broken
                    shellCommand(appData + "/dnsmasq." + Build.SUPPORTED_ABIS[0] + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server," + ipv4Addr + " --dhcp-option=option6:dns-server,[2001:4860:4860::8888],[2001:4860:4860::8844] --server=8.8.8.8 --server=8.8.4.4 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                } else {
                    shellCommand(appData + "/dnsmasq." + Build.SUPPORTED_ABIS[0] + " --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server," + ipv4Addr + " --dhcp-option=option6:dns-server,[" + ipv6Prefix + "1] --server=8.8.8.8 --server=8.8.4.4 --server=2001:4860:4860::8888 --server=2001:4860:4860::8844 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                }
            }
        }
        if (dpiCircumvention) {
            if (!Shell.cmd("[ -f " + appData + "/tpws.pid -a -d /proc/$(cat " + appData + "/tpws.pid) ]").exec().isSuccess()) {
                Log.w("USBTether", "No tpws process, restarting");
                startTPWS(ipv4Addr, ipv6Prefix, appData);
            }
        }
        if (ipv6TYPE.equals("TPROXY")) {
            if (!Shell.cmd("[ -f " + appData + "/socks.pid -a -d /proc/$(cat " + appData + "/socks.pid) ]").exec().isSuccess()) {
                Log.w("USBTether", "No socks process, restarting");
                shellCommand("rm " + appData + "/socks.pid");
                shellCommand(appData + "/hev-socks5-server." + Build.SUPPORTED_ABIS[0] + " " + appData + "/socks.yml &");
            }
            if (!Shell.cmd("[ -f " + appData + "/tproxy.pid -a -d /proc/$(cat " + appData + "/tproxy.pid) ]").exec().isSuccess()) {
                Log.w("USBTether", "No tproxy process, restarting");
                shellCommand("rm " + appData + "/tproxy.pid");
                shellCommand(appData + "/hev-socks5-tproxy." + Build.SUPPORTED_ABIS[0] + " " + appData + "/tproxy.yml &");
            }
        }
    }

    static void startTPWS(String ipv4Addr, String ipv6Prefix, String appData) {
        killProcess(appData + "/tpws.pid");
        shellCommand("rm " + appData + "/tpws.pid");
        //shellCommand(appData + "/tpws." + Build.SUPPORTED_ABIS[0] + " --bind-iface4=rndis0 --bind-iface6=rndis0 --port=8123 --split-pos=3 --uid 1:3003 &");
        shellCommand(appData + "/tpws." + Build.SUPPORTED_ABIS[0] + " --bind-addr=" + ipv4Addr + " --bind-addr=" + ipv6Prefix + "1 --port=8123 --pidfile=" + appData + "/tpws.pid --split-pos=3 --uid 1:3003 &");
    }

    static void stopTPWS(String appData) {
        killProcess(appData + "/tpws.pid");
    }

    static void refreshSNAT(String tetherInterface, String ipv6Addr, String newAddr) {
        Log.w("USBTether", "Refreshing SNAT IPTables Rule");
        String prefix = "natctrl";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            prefix = "tetherctrl";
        }
        shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + ipv6Addr);
        addIP6T("nat", true, prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + newAddr);
    }

    static Boolean testConnection(String tetherInterface) {
        if (Shell.cmd("ping -c 1 -w 3 -I " + tetherInterface + " 1.1.1.1").exec().isSuccess() || Shell.cmd("ping -c 1 -w 3 -I " + tetherInterface + " 8.8.8.8").exec().isSuccess()) {
            Log.i("usbtether", tetherInterface + " IPv4 is online");
            return true;
        }
        Log.w("usbtether", tetherInterface + " IPv4 is offline");
        return false;
    }

    static Boolean testConnection6(String tetherInterface) {
        if (Shell.cmd("ping6 -c 1 -w 3 -I " + tetherInterface + " 2606:4700:4700::1111").exec().isSuccess() || Shell.cmd("ping6 -c 1 -w 3 -I " + tetherInterface + " 2001:4860:4860::8888").exec().isSuccess()) {
            Log.i("usbtether", tetherInterface + " IPv6 is online");
            return true;
        }
        Log.w("usbtether", tetherInterface + " IPv6 is offline");
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
