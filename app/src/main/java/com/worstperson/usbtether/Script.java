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

    static boolean hasWait = shellCommand("iptables -w --help");
    static boolean hasMASQUERADE = shellCommand("ip6tables " + (hasWait ? "-w 2 " : "") + "-j MASQUERADE --help | grep \"MASQUERADE\"");
    static boolean hasSNAT = shellCommand("ip6tables " + (hasWait ? "-w 2 " : "") + "-j SNAT --help | grep \"SNAT\"");
    static boolean hasTPROXY = shellCommand("ip6tables " + (hasWait ? "-w 2 " : "") + "-j TPROXY --help | grep \"TPROXY\"");
    static boolean hasTTL = shellCommand("iptables " + (hasWait ? "-w 2 " : "") + "-j TTL --help | grep \"TTL\"");
    static boolean hasTable = shellCommand("ip6tables " + (hasWait ? "-w 2 " : "") + "--table nat --list");

    static boolean isUSBConfigured() {
        return Shell.cmd("[ \"$(cat /sys/class/android_usb/android0/state)\" = \"CONFIGURED\" ]").exec().isSuccess();
    }

    static void killProcess(String pidFile) {
        if ( Shell.cmd("[ -f " + pidFile + " -a -d /proc/$(cat " + pidFile + ") ]").exec().isSuccess()) {
            shellCommand("kill -s 9 $(cat " + pidFile + ")");
        }
    }

    static void addIPT(String table, String operation, String rule) {
        if (!Shell.cmd("iptables -t " + table + " -C " + rule).exec().isSuccess()) {
            shellCommand("iptables " + (hasWait ? "-w 2 " : "") + "-t " + table + " -" + operation + " " + rule);
        }
    }

    static void addIP6T(String table, String operation, String rule) {
        if (!Shell.cmd("ip6tables -t " + table + " -C " + rule).exec().isSuccess()) {
            shellCommand("ip6tables " + (hasWait ? "-w 2 " : "") + "-t " + table + " -" + operation + " " + rule);
        }
    }

    ///config/usb_gadget/g1/configs/b.1/f1 # cat ifname
    //ncm0 up
    static String[] gadgetVars() {
        String[] result = new String[]{ null, null, null, null };
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
                    // RNDIS
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
                    // NCM
                    command2 = Shell.cmd("find " + result[0] + "/functions/ncm.* -maxdepth 0 -type d").exec();
                    if ( command2.isSuccess() ) {
                        for (String result2 : command2.getOut()) {
                            if (Shell.cmd("ls -A " + result2).exec().isSuccess()) {
                                result[3] = result2;
                                break;
                            }
                        }
                    }
                    if (result[3] == null) {
                        command2 = Shell.cmd("find " + result[0] + "/functions/*.ncm -maxdepth 0 -type d").exec();
                        if (command2.isSuccess()) {
                            for (String result2 : command2.getOut()) {
                                if (Shell.cmd("ls -A " + result2).exec().isSuccess()) {
                                    result[3] = result2;
                                    break;
                                }
                            }
                        }
                    }
                    if (result[0] != null && result[1] != null && (result[2] != null || result[3] != null)) {
                        break;
                    }
                }
                result = new String[]{null, null, null, null};
            }
        }
        return result;
    }

    static String configureRNDIS(int usbMode, boolean preferNCM, String gadgetPath, String configPath, String rndisPath, String ncmPath) {
        String functionName = "rndis";
        String functionPath = rndisPath;
        if (usbMode == 0 && (configPath == null || (rndisPath == null && ncmPath == null))) {
            usbMode = 1;
        }

        if (usbMode == 1) {
            Log.i("USBTether", "Configuring USB state via legacy setprop");
            if (Shell.cmd("[ \"$(getprop sys.usb.state)\" = *\"adb\"* ]").exec().isSuccess()) {
                shellCommand("setprop sys.usb.config rndis,adb");
            } else {
                shellCommand("setprop sys.usb.config rndis");
            }
        } else if (usbMode == 2) {
            Log.i("USBTether", "Configuring USB state via svc");
            if (preferNCM) {
                functionName = "ncm";
            }
            String postfix = "";
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                postfix = "s";
            }
            if (!Shell.cmd("svc usb getFunction" + postfix).exec().getOut().get(0).contains(functionName)) {
                shellCommand("svc usb setFunction" + postfix + " " + functionName);
            }
        } else {
            Log.i("USBTether", "Configuring USB state via usbgadget");
            if ((preferNCM && ncmPath != null) || rndisPath == null) {
                functionName = "ncm";
                functionPath = ncmPath;
            }
            shellCommand("echo \"none\" > " + gadgetPath + "/UDC");
            if (Shell.cmd("[ \"$(cat " + configPath + "/strings/0x409/configuration)\" = *\"adb\"* ]").exec().isSuccess()) {
                shellCommand("echo \"" + functionName + "_adb\" > " + configPath + "/strings/0x409/configuration");
            } else {
                shellCommand("echo \"" + functionName + "\" > " + configPath + "/strings/0x409/configuration");
            }
            shellCommand("ln -s " + functionPath + " " + configPath + "/usbtether");
            shellCommand("getprop sys.usb.controller > " + gadgetPath + "/UDC");
        }
        shellCommand("n=0; while [[ $n -lt 10 ]]; do if [[ -d /sys/class/net/" + functionName + "0 ]]; then break; fi; n=$((n+1)); echo \"waiting for usb... $n\"; sleep 1; done");
        return functionName + "0";
    }

    static void unconfigureRNDIS(int usbMode, String gadgetPath, String configPath, String rndisPath, String ncmPath) {
        if (usbMode == 0 && (configPath == null || (rndisPath == null && ncmPath == null))) {
            usbMode = 1;
        }

        if (usbMode == 1) {
            Log.i("USBTether", "Unconfiguring rndis state via legacy setprop");
            if (Shell.cmd("[ \"$(getprop sys.usb.state)\" = *\"adb\"* ]").exec().isSuccess()) {
                shellCommand("setprop sys.usb.config adb");
            } else {
                shellCommand("setprop sys.usb.config none");
            }
        } else if (usbMode == 2) {
            Log.i("USBTether", "Unconfiguring rndis state via usbgadget");
            String postfix = "";
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                postfix = "s";
            }
            shellCommand("svc usb setFunction" + postfix);
        } else {
            Log.i("USBTether", "Unconfiguring rndis state via usbgadget");
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

    static boolean configureRoutes(String tetherInterface, String ipv4Addr, String ipv6Prefix) {
        Log.i("USBTether", "Setting IP routes");
        String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
        return shellCommand("ip route add " + ipv4Prefix + ".0/24 dev " + tetherInterface + " table local_network proto static scope link")
                && shellCommand("ip -6 route add " + ipv6Prefix + "/64 dev " + tetherInterface + " table local_network proto static scope link")
                && shellCommand("ip -6 route add fe80::/64 dev " + tetherInterface + " table local_network proto static scope link");
    }

    static void unconfigureRoutes(String tetherInterface) {
        Log.i("USBTether", "Removing IP routes");
        shellCommand("ip route flush dev " + tetherInterface);
        shellCommand("ip -6 route flush dev " + tetherInterface);
    }

    static boolean configureInterface(String tetherInterface, String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, int usbMode) {
        if (usbMode == 2) {
            // svc may configure interface, so clear it first
            unconfigureInterface(tetherInterface);
        }
        Log.i("USBTether", "Configuring interface");
        return shellCommand("ip link set dev " + tetherInterface + " down")
                && configureAddresses(tetherInterface, ipv4Addr, ipv6Prefix)
                && configureRoutes(tetherInterface, ipv4Addr, ipv6Prefix)
                && configureRules(tetherInterface, ipv4Interface, ipv6Interface);
    }

    static void unconfigureInterface(String tetherInterface) {
        Log.i("USBTether", "Unconfiguring interface");
        unconfigureRules();
        unconfigureRoutes(tetherInterface);
        unconfigureAddresses(tetherInterface);
    }

    /*static private void configureIPT(){
        addIPT("filter", "N", "USBT_FORWARD");
        addIPT("filter", "I", "FORWARD -j USBT_FORWARD");
        addIPT("mangle", "N", "USBT_mangle_PREROUTING");
        addIPT("mangle", "I", "PREROUTING -j USBT_mangle_PREROUTING");
        addIPT("mangle", "N", "USBT_mangle_FORWARD");
        addIPT("mangle", "I", "FORWARD -j USBT_mangle_FORWARD");
        addIPT("nat", "N", "USBT_nat_PREROUTING");
        addIPT("nat", "I", "PREROUTING -j USBT_nat_PREROUTING");
        addIPT("nat", "N", "USBT_nat_POSTROUTING");
        addIPT("nat", "I", "POSTROUTING -j USBT_nat_POSTROUTING");
        addIP6T("filter", "N", "USBT_FORWARD");
        addIP6T("filter", "I", "FORWARD -j USBT_FORWARD");
        addIP6T("mangle", "N", "USBT_mangle_PREROUTING");
        addIP6T("mangle", "A", "PREROUTING -j USBT_mangle_PREROUTING");
        addIP6T("mangle", "N", "USBT_mangle_FORWARD");
        addIP6T("mangle", "I", "FORWARD -j USBT_mangle_FORWARD");
        addIP6T("nat", "N", "USBT_nat_PREROUTING");
        addIP6T("nat", "I", "PREROUTING -j USBT_nat_PREROUTING");
        addIP6T("nat", "N", "USBT_nat_POSTROUTING");
        addIP6T("nat", "I", "POSTROUTING -j USBT_nat_POSTROUTING");
    }*/

    static private void configureNAT(String tetherInterface, String ipv4Interface, String ipv6Interface,/* String upstreamIPv4,*/ String upstreamIPv6, String ipv6TYPE) {
        Log.i("USBTether", "Setting up NAT");
        String prefix = "natctrl";
        String counter = prefix + "_tether";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            prefix = "tetherctrl";
            counter = prefix;
        }
        shellCommand("iptables -t filter -D " + prefix + "_FORWARD -j DROP");
        shellCommand("iptables -t filter -D " + prefix + "_FORWARD -g " + counter + "_counters");
        addIPT("filter", "A", prefix + "_FORWARD -i " + ipv4Interface + " -o " + tetherInterface + " -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
        addIPT("filter", "A", prefix + "_FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -m state --state INVALID -j DROP");
        addIPT("filter", "A", prefix + "_FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -g " + counter + "_counters");
        addIPT("filter", "A", prefix + "_FORWARD -j DROP");
        addIPT("mangle", "A", prefix + "_mangle_FORWARD -i " + tetherInterface + " -j MARK --set-xmark 0x30063/0xffefffff");
        addIPT("mangle", "A", prefix + "_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");
        addIPT("nat", "N", prefix + "_nat_POSTROUTING");
        addIPT("nat", "A", "POSTROUTING -j " + prefix + "_nat_POSTROUTING");
        addIPT("raw", "A", prefix + "_raw_PREROUTING -i " + tetherInterface + " -p tcp -m tcp --dport 21 -j CT --helper ftp");
        addIPT("raw", "A", prefix + "_raw_PREROUTING -i " + tetherInterface + " -p tcp -m tcp --dport 1723 -j CT --helper pptp");
        //TODO: add option for this
        /*if (ipv6TYPE.equals("SNAT")) {
            addIPT("nat", "A", prefix + "_nat_POSTROUTING -o " + ipv4Interface + " -j SNAT --to " + upstreamIPv4);
        } else {*/
            addIPT("nat", "A", prefix + "_nat_POSTROUTING -o " + ipv4Interface + " -j MASQUERADE");
        //}
        if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -j DROP");
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -g " + counter + "_counters");
            addIP6T("filter", "A", prefix + "_FORWARD -i " + ipv6Interface + " -o " + tetherInterface + " -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
            addIP6T("filter", "A", prefix + "_FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -m state --state INVALID -j DROP");
            addIP6T("filter", "A", prefix + "_FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -g " + counter + "_counters");
            addIP6T("filter", "A", prefix + "_FORWARD -j DROP");
            addIP6T("mangle", "A", prefix + "_mangle_FORWARD -i " + tetherInterface + " -j MARK --set-xmark 0x30063/0xffefffff");
            addIP6T("mangle", "A", prefix + "_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");
            addIP6T("nat", "N", prefix + "_nat_POSTROUTING");
            addIP6T("nat", "A", "POSTROUTING -j " + prefix + "_nat_POSTROUTING");
            if (ipv6TYPE.equals("SNAT")) {
                addIP6T("nat", "A", prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j SNAT --to " + upstreamIPv6);
            } else {
                addIP6T("nat", "A", prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j MASQUERADE");
            }
        } else if (ipv6TYPE.equals("TPROXY")) {
            addIP6T("mangle", "N", "TPROXY_ROUTE_PREROUTING");
            addIP6T("mangle", "A", "PREROUTING -j TPROXY_ROUTE_PREROUTING");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d :: -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d ::1 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d ::ffff:0:0:0/96 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d 64:ff9b::/96 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d 100::/64 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d 2001::/32 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d 2001:20::/28 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d 2001:db8::/32 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d 2002::/16 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d fc00::/7 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d fe80::/10 -j RETURN");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -d ff00::/8 -j RETURN");
            addIP6T("mangle", "N", "TPROXY_ROUTE_PREROUTING");
            addIP6T("mangle", "A", "TPROXY_ROUTE_PREROUTING -j TPROXY_MARK_PREROUTING");
            addIP6T("mangle", "A", "TPROXY_MARK_PREROUTING -p tcp -j TPROXY --on-ip ::1 --on-port 1088 --tproxy-mark 1088");
            addIP6T("mangle", "A", "TPROXY_MARK_PREROUTING -p udp -j TPROXY --on-ip ::1 --on-port 1088 --tproxy-mark 1088");
            shellCommand("ip -6 rule add pref 530 fwmark 1088 table 999");
            shellCommand("ip -6 route add local default dev lo table 999");
        }
    }

    static private void unconfigureNAT(String tetherInterface, String ipv4Interface, String ipv6Interface,/* String upstreamIPv4,*/ String upstreamIPv6, String ipv6TYPE) {
        String prefix = "natctrl";
        String counter = prefix + "_tether";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            prefix = "tetherctrl";
            counter = prefix;
        }
        /*if (ipv6TYPE.equals("SNAT")) {
            shellCommand("iptables -t nat -D " + prefix + "_nat_POSTROUTING -o " + ipv4Interface + " -j SNAT --to " + upstreamIPv4);
        } else {*/
            shellCommand("iptables -t nat -D " + prefix + "_nat_POSTROUTING -o " + ipv4Interface + " -j MASQUERADE");
        //}
        //shellCommand("iptables -t raw -D " + prefix + "_nat_POSTROUTING -i " + "rndis0" + " -p tcp -m tcp --dport 21 -j CT --helper ftp");
        //shellCommand("iptables -t raw -D " + prefix + "_nat_POSTROUTING -i " + "rndis0" + " -p tcp -m tcp --dport 21 -j CT --helper pptp");
        shellCommand("iptables -t nat -D POSTROUTING -j " + prefix + "_nat_POSTROUTING");
        shellCommand("iptables -t nat -X " + prefix + "_nat_POSTROUTING");
        //shellCommand("iptables -t mangle -D " + prefix + "_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");
        //shellCommand("iptables -t filter -D " + prefix + "_FORWARD -j DROP");
        shellCommand("iptables -t filter -D " + prefix + "_FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -g " + counter + "_counters");
        shellCommand("iptables -t filter -D " + prefix + "_FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -m state --state INVALID -j DROP");
        shellCommand("iptables -t filter -D " + prefix + "_FORWARD -i " + ipv4Interface + " -o " + tetherInterface + " -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
        if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
            if (ipv6TYPE.equals("SNAT")) {
                shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j SNAT --to " + upstreamIPv6);
            } else {
                shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j MASQUERADE");
            }
            shellCommand("ip6tables -t nat -D POSTROUTING -j " + prefix + "_nat_POSTROUTING");
            shellCommand("ip6tables -t nat -X " + prefix + "_nat_POSTROUTING");
            //shellCommand("ip6tables -t mangle -D " + prefix + "_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");
            //shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -j DROP");
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -g " + counter + "_counters");
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -m state --state INVALID -j DROP");
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i " + ipv6Interface + " -o " + tetherInterface + " -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
        } else if (ipv6TYPE.equals("TPROXY")) {
            shellCommand("ip6tables -t mangle -D TPROXY_ROUTE_PREROUTING -j TPROXY_MARK_PREROUTING");
            shellCommand("ip6tables -t mangle -F TPROXY_MARK_PREROUTING");
            shellCommand("ip6tables -t mangle -X TPROXY_MARK_PREROUTING");
            shellCommand("ip6tables -t mangle -D PREROUTING -j TPROXY_ROUTE_PREROUTING");
            shellCommand("ip6tables -t mangle -F TPROXY_ROUTE_PREROUTING");
            shellCommand("ip6tables -t mangle -X TPROXY_ROUTE_PREROUTING");
            shellCommand("ip -6 rule delete pref 530 fwmark 1088 table 999");
            shellCommand("ip -6 route delete local default dev lo table 999");
        }
    }

    static void setTPROXYRoute(String prefix) {
        addIP6T("mangle", "I", "TPROXY_ROUTE_PREROUTING -d " + prefix + "::/64 -j RETURN");
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
        addIPT("nat", "A", "PREROUTING -i " + ipv4Interface + " -p tcp -j DNAT --to-destination " + ipv4Prefix + ".5");
        addIPT("nat", "A", "PREROUTING -i " + ipv4Interface + " -p udp -j DNAT --to-destination " + ipv4Prefix + ".5");
        addIPT("filter", "I", prefix + "_FORWARD -p tcp -d " + ipv4Prefix + ".5 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
        if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
            addIP6T("nat", "A", "PREROUTING -i " + ipv6Interface + " -p tcp -j DNAT --to-destination " + ipv6Prefix + "5");
            addIP6T("nat", "A", "PREROUTING -i " + ipv6Interface + " -p udp -j DNAT --to-destination " + ipv6Prefix + "5");
            addIP6T("filter", "I", prefix + "_FORWARD -p tcp -d " + ipv6Prefix + "5 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
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
        shellCommand("iptables -t filter -D " + prefix + "_FORWARD -p tcp -d " + ipv4Prefix + ".5 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
        if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
            shellCommand("ip6tables -t nat -D PREROUTING -i " + ipv6Interface + " -p tcp -j DNAT --to-destination " + ipv6Prefix + "5");
            shellCommand("ip6tables -t nat -D PREROUTING -i " + ipv6Interface + " -p udp -j DNAT --to-destination " + ipv6Prefix + "5");
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -p tcp -d " + ipv6Prefix + "5 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT");
        }
    }

    static boolean configureTether(String tetherInterface, String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, String ipv6TYPE,/* upstreamIPv4,*/ String upstreamIPv6, Boolean fixTTL, Boolean dnsmasq, String libDIR, String appData, String clientBandwidth, boolean dpiCircumvention, boolean dmz, int usbMode) {
        // Check that tetherInterface is actually available to avoid wasting time
        if (shellCommand("ip link set dev " + tetherInterface + " down")
                && configureInterface(tetherInterface, ipv4Interface, ipv6Interface, ipv4Addr, ipv6Prefix, usbMode)) {
            Log.i("USBTether", "Enabling IP forwarding");
            shellCommand("echo 1 > /proc/sys/net/ipv4/ip_forward");
            shellCommand("echo 1 > /proc/sys/net/ipv6/conf/all/forwarding");
            configureNAT(tetherInterface, ipv4Interface, ipv6Interface,/* upstreamIPv4,*/ upstreamIPv6, ipv6TYPE);
            if (fixTTL) {
                addIPT("mangle", "A", "FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -j TTL --ttl-set 64");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) { // Won't work with encapsulated traffic
                    addIP6T("mangle", "A", "FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -j HL --hl-set 64");
                }
            }
            String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
            if (Integer.parseInt(clientBandwidth) > 0) { // Set the maximum allowed bandwidth per IP address
                addIPT("filter", "A", "FORWARD -i " + ipv4Interface + " -o " + tetherInterface + " -d " + ipv4Prefix + ".0/24 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) { // Not supported by TPROXY
                    addIP6T("filter", "A", "FORWARD -i " + ipv6Interface + " -o " + tetherInterface + " -d " + ipv6Prefix + "/64 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
                }
            }
            //--dhcp-host=46:65:23:9e:c0:c6,192.168.1.2 --dhcp-host=46:65:23:9e:c0:c6,[2001:db8::2]
            if (dnsmasq) {
                addIPT("nat", "I", "PREROUTING -i " + tetherInterface + " -s 0.0.0.0 -d 255.255.255.255 -p udp --dport 67 -j DNAT --to-destination 255.255.255.255:6767");
                addIPT("nat", "I", "PREROUTING -i " + tetherInterface + " -s " + ipv4Prefix + ".0/24 -d " + ipv4Addr + " -p udp --dport 53 -j DNAT --to-destination " + ipv4Addr + ":5353");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                    addIP6T("nat", "I", "PREROUTING -i " + tetherInterface + " -s " + ipv6Prefix + "/64 -d " + ipv6Prefix + "1 -p udp --dport 53 -j DNAT --to-destination [" + ipv6Prefix + "1]:5353");
                }
                shellCommand("rm " + appData + "/dnsmasq.leases");
                shellCommand("rm " + appData + "/dnsmasq.pid");
                if (ipv6TYPE.equals("None")) {
                    shellCommand(libDIR + "/dnsmasq.so --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-option=option:dns-server," + ipv4Addr + " --server=8.8.8.8 --server=8.8.4.4 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                } else if (ipv6TYPE.equals("TPROXY")) { // HACK - hevtproxy IPv6 DNS proxying seems unsupported or maybe broken
                    shellCommand(libDIR + "/dnsmasq.so --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server," + ipv4Addr + " --dhcp-option=option6:dns-server,[2001:4860:4860::8888],[2001:4860:4860::8844] --server=8.8.8.8 --server=8.8.4.4 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                } else {
                    shellCommand(libDIR + "/dnsmasq.so --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server," + ipv4Addr + " --dhcp-option=option6:dns-server,[" + ipv6Prefix + "1] --server=8.8.8.8 --server=8.8.4.4 --server=2001:4860:4860::8888 --server=2001:4860:4860::8844 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                }
            }
            if (ipv6TYPE.equals("TPROXY")) {
                shellCommand("rm " + appData + "/socks.pid");
                shellCommand("rm " + appData + "/tproxy.pid");
                shellCommand(libDIR + "/hev-socks5-server.so " + appData + "/socks.yml &");
                shellCommand(libDIR + "/hev-socks5-tproxy.so " + appData + "/tproxy.yml &");
            }
            if (dpiCircumvention) {
                addIPT("nat", "I", "PREROUTING -i " + tetherInterface + " -p tcp --dport 80 -j DNAT --to " + ipv4Addr + ":8123");
                addIPT("nat", "I", "PREROUTING -i " + tetherInterface + " -p tcp --dport 443 -j DNAT --to " + ipv4Addr + ":8123");
                if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                    addIP6T("nat", "I", "PREROUTING -i " + tetherInterface + " -p tcp --dport 80 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                    addIP6T("nat", "I", "PREROUTING -i " + tetherInterface + " -p tcp --dport 443 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                } else if (ipv6TYPE.equals("TPROXY")) {
                    // Huh, only need the IP_TRANSPARENT patch for IPv4?
                    addIP6T("mangle", "I", "TPROXY_MARK_PREROUTING -p tcp --dport 80 -j TPROXY --on-ip " + ipv6Prefix + "1 --on-port 8123 --tproxy-mark 8123");
                    addIP6T("mangle", "I", "TPROXY_MARK_PREROUTING -p tcp --dport 443 -j TPROXY --on-ip " + ipv6Prefix + "1 --on-port 8123 --tproxy-mark 8123");
                    shellCommand("ip -6 rule add pref 520 fwmark 8123 table 998");
                    shellCommand("ip -6 route add local default dev lo table 998");
                }
            }
            if (dmz) {
                configureDMZ(ipv4Interface, ipv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE);
            }
        } else {
            Log.w("USBTether",  tetherInterface + " unavailable, aborting tether...");
            return false;
        }
        return true;
    }

    static void unconfigureTether(String tetherInterface, String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, String ipv6TYPE,/* upstreamIPv4,*/ String upstreamIPv6, Boolean fixTTL, Boolean dnsmasq, String appData, String clientBandwidth, boolean dpiCircumvention, boolean dmz) {
        String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
        if (dnsmasq) {
            killProcess(appData + "/dnsmasq.pid");
            shellCommand("iptables -t nat -D PREROUTING -i " + tetherInterface + " -s " + ipv4Prefix + ".0/24 -d " + ipv4Addr + " -p udp --dport 53 -j DNAT --to-destination " + ipv4Addr + ":5353");
            shellCommand("iptables -t nat -D PREROUTING -i " + tetherInterface + " -s 0.0.0.0 -d 255.255.255.255 -p udp --dport 67 -j DNAT --to-destination 255.255.255.255:6767");
            if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                shellCommand("ip6tables -t nat -D PREROUTING -i " + tetherInterface + " -s " + ipv6Prefix + "/64 -d " + ipv6Prefix + "1 -p udp --dport 53 -j DNAT --to-destination [" + ipv6Prefix + "1]:5353");
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
            shellCommand("iptables -t nat -D PREROUTING -i " + tetherInterface + " -p tcp --dport 80 -j DNAT --to " + ipv4Addr + ":8123");
            shellCommand("iptables -t nat -D PREROUTING -i " + tetherInterface + " -p tcp --dport 443 -j DNAT --to " + ipv4Addr + ":8123");
            if (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) {
                shellCommand("ip6tables -t nat -D PREROUTING -i " + tetherInterface + " -p tcp --dport 80 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                shellCommand("ip6tables -t nat -D PREROUTING -i " + tetherInterface + " -p tcp --dport 443 -j DNAT --to [" + ipv6Prefix + "1]:8123");
            } else if (ipv6TYPE.equals("TPROXY")) {
                shellCommand("ip -6 rule delete pref 520 fwmark 8123 table 998");
                shellCommand("ip -6 route delete local default dev lo table 998");
            }
        }
        Log.i("USBTether", "Restoring tether interface state");
        if (Integer.parseInt(clientBandwidth) > 0) {
            shellCommand("iptables -D FORWARD -i " + ipv4Interface + " -o " + tetherInterface + " -d " + ipv4Prefix + ".0/24 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
            shellCommand("ip6tables -D FORWARD -i " + ipv6Interface + " -o " + tetherInterface + " -d " + ipv6Prefix + "/64 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
        }
        if (fixTTL) {
            shellCommand("iptables -t mangle -D FORWARD -i " + tetherInterface + " -o " + ipv4Interface + " -j TTL --ttl-set 64");
            shellCommand("ip6tables -t mangle -D FORWARD -i " + tetherInterface + " -o " + ipv6Interface + " -j HL --hl-set 64");
        }
        unconfigureNAT(tetherInterface, ipv4Interface, ipv6Interface, /*upsteamIPv4,*/ upstreamIPv6, ipv6TYPE);
        unconfigureInterface(tetherInterface);
        shellCommand("echo 0 > /proc/sys/net/ipv4/ip_forward");
        shellCommand("echo 0 > /proc/sys/net/ipv6/conf/all/forwarding");
    }

    static void startTPWS(String ipv4Addr, String ipv6Prefix, String libDIR, String appData) {
        killProcess(appData + "/tpws.pid");
        shellCommand("rm " + appData + "/tpws.pid");
        //shellCommand(appData + "/tpws." + Build.SUPPORTED_ABIS[0] + " --bind-iface4=rndis0 --bind-iface6=rndis0 --port=8123 --split-pos=3 --uid 1:3003 &");
        shellCommand(libDIR + "/tpws.so --bind-addr=" + ipv4Addr + " --bind-addr=" + ipv6Prefix + "1 --port=8123 --pidfile=" + appData + "/tpws.pid --split-pos=3 --uid 1:3003 &");
    }

    static void stopTPWS(String appData) {
        killProcess(appData + "/tpws.pid");
    }

    static void checkProcesses(String ipv4Addr, String ipv6Prefix, String ipv6TYPE, Boolean dnsmasq, String libDIR, String appData, boolean dpiCircumvention) {
        if (dnsmasq) {
            if (!shellCommand("[ -f " + appData + "/dnsmasq.pid -a -d /proc/$(cat " + appData + "/dnsmasq.pid) ]")) {
                String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
                Log.w("USBTether", "No dnsmasq process, restarting");
                shellCommand("rm " + appData + "/dnsmasq.leases");
                shellCommand("rm " + appData + "/dnsmasq.pid");
                if (ipv6TYPE.equals("None")) {
                    shellCommand(libDIR + "/dnsmasq.so --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-option=option:dns-server," + ipv4Addr + " --server=8.8.8.8 --server=8.8.4.4 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                } else if (ipv6TYPE.equals("TPROXY")) { // HACK - hevtproxy IPv6 DNS proxying seems unsupported or maybe broken
                    shellCommand(libDIR + "/dnsmasq.so --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server," + ipv4Addr + " --dhcp-option=option6:dns-server,[2001:4860:4860::8888],[2001:4860:4860::8844] --server=8.8.8.8 --server=8.8.4.4 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                } else {
                    shellCommand(libDIR + "/dnsmasq.so --keep-in-foreground --no-resolv --no-poll --domain-needed --bogus-priv --dhcp-authoritative --port=5353 --dhcp-alternate-port=6767,68 --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server," + ipv4Addr + " --dhcp-option=option6:dns-server,[" + ipv6Prefix + "1] --server=8.8.8.8 --server=8.8.4.4 --server=2001:4860:4860::8888 --server=2001:4860:4860::8844 --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                }
            }
        }
        if (dpiCircumvention) {
            if (!shellCommand("[ -f " + appData + "/tpws.pid -a -d /proc/$(cat " + appData + "/tpws.pid) ]")) {
                Log.w("USBTether", "No tpws process, restarting");
                startTPWS(ipv4Addr, ipv6Prefix, libDIR, appData);
            }
        }
        if (ipv6TYPE.equals("TPROXY")) {
            if (!shellCommand("[ -f " + appData + "/socks.pid -a -d /proc/$(cat " + appData + "/socks.pid) ]")) {
                Log.w("USBTether", "No socks process, restarting");
                shellCommand("rm " + appData + "/socks.pid");
                shellCommand(appData + "/hev-socks5-server." + Build.SUPPORTED_ABIS[0] + " " + appData + "/socks.yml &");
            }
            if (!shellCommand("[ -f " + appData + "/tproxy.pid -a -d /proc/$(cat " + appData + "/tproxy.pid) ]")) {
                Log.w("USBTether", "No tproxy process, restarting");
                shellCommand("rm " + appData + "/tproxy.pid");
                shellCommand(appData + "/hev-socks5-tproxy." + Build.SUPPORTED_ABIS[0] + " " + appData + "/tproxy.yml &");
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
        shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + ipv6Addr);
        addIP6T("nat", "A", prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + newAddr);
    }

    static Boolean testConnection(String upstreamInterface) {
        if (Shell.cmd("ping -c 1 -w 3 -I " + upstreamInterface + " 1.1.1.1").exec().isSuccess()
                || Shell.cmd("ping -c 1 -w 3 -I " + upstreamInterface + " 8.8.8.8").exec().isSuccess()) {
            Log.i("USBTether", upstreamInterface + " IPv4 is online");
            return true;
        }
        Log.w("USBTether", upstreamInterface + " IPv4 is offline");
        return false;
    }

    static Boolean testConnection6(String upstreamInterface) {
        if (Shell.cmd("ping6 -c 1 -w 3 -I " + upstreamInterface + " 2606:4700:4700::1111").exec().isSuccess()
                || Shell.cmd("ping6 -c 1 -w 3 -I " + upstreamInterface + " 2001:4860:4860::8888").exec().isSuccess()) {
            Log.i("USBTether", upstreamInterface + " IPv6 is online");
            return true;
        }
        Log.w("USBTether", upstreamInterface + " IPv6 is offline");
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
