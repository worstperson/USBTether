/*
        Copyright 2021 worstperson

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

import java.util.List;

public class Script {

    static {
        Shell.enableVerboseLogging = BuildConfig.DEBUG;
        Shell.setDefaultBuilder(Shell.Builder.create()
                .setFlags(Shell.FLAG_REDIRECT_STDERR)
                .setTimeout(10));
    }

    static private void shellCommand(String command) {
        for (String message : Shell.su(command).exec().getOut()) {
            Log.i("USBTether", message);
        }
    }

    static boolean isUSBConfigured() {
        return Shell.su("[ \"$(cat /sys/class/android_usb/android0/state)\" = \"CONFIGURED\" ]").exec().isSuccess();
    }

    static String[] gadgetVars() {
        String[] result = new String[]{ null, null, null };
        Shell.Result command = Shell.su("find /config/usb_gadget/* -maxdepth 0 -type d").exec();
        if ( command.isSuccess() ) {
            for (String result1 : command.getOut()) {
                result[0] = result1;
                if (Shell.su("[ \"$(cat " + result[0] + "/UDC )\" = \"$(getprop sys.usb.controller)\" ]").exec().isSuccess()) {
                    Shell.Result command2 = Shell.su("find " + result[0] + "/configs/* -maxdepth 0 -type d").exec();
                    if ( command2.isSuccess() ) {
                        for (String result2 : command2.getOut()) {
                            result[1] = result2;
                            break;
                        }
                    }
                    command2 = Shell.su("find " + result[0] + "/functions/rndis.* -maxdepth 0 -type d").exec();
                    if ( command2.isSuccess() ) {
                        for (String result2 : command2.getOut()) {
                            if (Shell.su("ls -A " + result2).exec().isSuccess()) {
                                result[2] = result2;
                                break;
                            }
                        }
                    }
                    if (result[2] == null) {
                        command2 = Shell.su("find " + result[0] + "/functions/*.rndis -maxdepth 0 -type d").exec();
                        if (command2.isSuccess()) {
                            for (String result2 : command2.getOut()) {
                                if (Shell.su("ls -A " + result2).exec().isSuccess()) {
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

    static private boolean set_ip_addresses(String ipv4Addr, String ipv6Prefix, Boolean ipv6Masquerading, Boolean ipv6SNAT) {
        Log.i("USBTether", "Setting IP addresses");
        if (!ipv6Masquerading && !ipv6SNAT) {
            shellCommand("ndc interface setcfg rndis0 " + ipv4Addr + " 24 up");
            return true;
        }
        shellCommand("ip -6 addr add " + ipv6Prefix + "1/64 dev rndis0 scope global");
        shellCommand("ndc interface setcfg rndis0 " + ipv4Addr + " 24 up");
        Log.i("USBTether", "Waiting for interface to come up");
        for (int waitTime = 1; waitTime <= 5; waitTime++) {
            if (Shell.su("[ \"$(cat /sys/class/net/rndis0/operstate)\" = \"up\" ]").exec().isSuccess()) {
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
        if (Shell.su("[ \"$(cat /sys/class/net/rndis0/operstate)\" = \"up\" ]").exec().isSuccess()) {
            shellCommand("ip -6 route add " + ipv6Prefix + "/64 dev rndis0 src " + ipv6Prefix + "1");
            return true;
        } else {
            return false;
        }
    }

    static boolean configureRoutes(String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, Boolean ipv6Masquerading, Boolean ipv6SNAT) {
        if (!Shell.su("ip link set dev rndis0 down").exec().isSuccess()) {
            Log.w("usbtether", "No tether interface...");
        } else {
            forwardInterface(ipv4Interface, ipv6Interface);
            if (set_ip_addresses(ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT)) {
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

    static void unconfigureRoutes(String ipv4Interface, String ipv6Interface, String ipv4Addr, String ipv6Prefix, Boolean ipv6Masquerading, Boolean ipv6SNAT) {
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

    static private void configureNAT(String ipv4Interface, String ipv6Interface, Boolean ipv6Masquerading, Boolean ipv6SNAT, String ipv6Addr) {
        Log.i("USBTether", "Setting up NAT");
        shellCommand("ndc nat enable rndis0 " + ipv4Interface + " 99");
        if (ipv6Masquerading || ipv6SNAT) {
            String prefix = "natctrl";
            String counter = prefix+"_tether";
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                prefix = "tetherctrl";
                counter = prefix;
            }
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -g " + counter + "_counters");
            shellCommand("ip6tables -t filter -A " + prefix + "_FORWARD -i " + ipv6Interface + " -o rndis0 -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
            shellCommand("ip6tables -t filter -A " + prefix + "_FORWARD -i rndis0 -o " + ipv6Interface + " -m state --state INVALID -j DROP");
            shellCommand("ip6tables -t filter -A " + prefix + "_FORWARD -i rndis0 -o " + ipv6Interface + " -g " + counter + "_counters");
            shellCommand("ip6tables -t filter -A " + prefix + "_FORWARD -j DROP");
            shellCommand("ip6tables -t mangle -A tetherctrl_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");
            shellCommand("ip6tables -t nat -N " + prefix + "_nat_POSTROUTING");
            shellCommand("ip6tables -t nat -A POSTROUTING -j " + prefix + "_nat_POSTROUTING");
            if (ipv6SNAT) {
                shellCommand("ip6tables -t nat -A " + prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j SNAT --to " + ipv6Addr);
            } else {
                shellCommand("ip6tables -t nat -A " + prefix + "_nat_POSTROUTING -o " + ipv6Interface + " -j MASQUERADE");
            }
        }
    }

    static void unconfigureNAT(String ipv4Interface, String ipv6Interface, Boolean ipv6Masquerading, Boolean ipv6SNAT, String ipv6Addr) {
        if (ipv6Masquerading || ipv6SNAT) {
            String prefix = "natctrl";
            String counter = prefix + "_tether";
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                prefix = "tetherctrl";
                counter = prefix;
            }
            if (ipv6SNAT) {
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
        }
        shellCommand("ndc nat disable rndis0 " + ipv4Interface + " 99");
    }

    static void configureRNDIS(String gadgetPath, String configPath, String functionPath) {
        if ( !Shell.su("[ \"$(getprop sys.usb.usbtether)\" = \"true\" ]").exec().isSuccess() ) {
            if (configPath == null) {
                shellCommand("setprop sys.usb.config rndis,adb");
                shellCommand("until [[ \"$(getprop sys.usb.state)\" == *\"rndis\"* ]]; do sleep 1; done");
            } else {
                shellCommand("echo \"0x18d1\" > " + gadgetPath + "/idVendor");
                shellCommand("echo \"0x4ee4\" > " + gadgetPath + "/idProduct");
                shellCommand("rm -r " + configPath + "/usbtether");
                shellCommand("ln -s " + functionPath + " " + configPath + "/usbtether");
                //Do it again?
                shellCommand("rm -r " + configPath + "/usbtether");
                shellCommand("ln -s " + functionPath + " " + configPath + "/usbtether");
            }
            shellCommand("setprop sys.usb.usbtether true");
        } else {
            Log.w("USBTether", "Tether interface already configured?!?");
        }
    }

    static boolean configureTether(String ipv4Interface, String ipv6Interface, String ipv4Addr, Boolean ipv6Masquerading, Boolean ipv6SNAT, String ipv6Prefix, String ipv6Addr, Boolean fixTTL, Boolean dnsmasq, String appData, String clientBandwidth, boolean dpiCircumvention, String configPath, String functionPath) {
        // Check that rndis0 is actually available to avoid wasting time
        if (!Shell.su("ip link set dev rndis0 down").exec().isSuccess()) {
            Log.w("usbtether", "Aborting tether...");
            if (configPath == null) {
                shellCommand("setprop sys.usb.config adb");
                shellCommand("until [[ \"$(getprop sys.usb.state)\" != *\"rndis\"* ]]; do sleep 1; done");
                shellCommand("setprop sys.usb.config rndis,adb");
            } else {
                shellCommand("rm -r " + configPath + "/usbtether");
                shellCommand("ln -s " + functionPath + " " + configPath + "/usbtether");
            }
            return false;
        } else {
            Log.i("USBTether", "Enabling IP forwarding");
            shellCommand("ndc ipfwd enable tethering");
            configureNAT(ipv4Interface, ipv6Interface, ipv6Masquerading, ipv6SNAT, ipv6Addr);
            if (fixTTL) {
                shellCommand("iptables -t mangle -A FORWARD -i rndis0 -o " + ipv4Interface + " -j TTL --ttl-set 64");
                if (ipv6Masquerading || ipv6SNAT) { // Won't work with encapsulated traffic
                    shellCommand("ip6tables -t mangle -A FORWARD -i rndis0 -o " + ipv6Interface + " -j HL --hl-set 64");
                }
            }
            String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
            if (Integer.parseInt(clientBandwidth) > 0) { // Set the maximum allowed bandwidth per IP address
                shellCommand("iptables -A FORWARD -i " + ipv4Interface + " -o rndis0 -d " + ipv4Prefix + ".0/24 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
                if (ipv6Masquerading || ipv6SNAT) {
                    shellCommand("ip6tables -A FORWARD -i " + ipv6Interface + " -o rndis0 -d " + ipv6Prefix + "/64 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
                }
            }
            if (dnsmasq) {
                shellCommand("rm " + appData + "/dnsmasq.leases");
                shellCommand("rm " + appData + "/dnsmasq.pid");
                if (ipv6Masquerading || ipv6SNAT) {
                    shellCommand(appData + "/dnsmasq." + Build.SUPPORTED_ABIS[0] + " --keep-in-foreground --no-resolv --no-poll --dhcp-authoritative --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server,8.8.8.8,8.8.4.4 --dhcp-option=option6:dns-server,[2001:4860:4860::8888],[2001:4860:4860::8844] --dhcp-option-force=43,ANDROID_METERED --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                } else {
                    shellCommand(appData + "/dnsmasq." + Build.SUPPORTED_ABIS[0] + " --keep-in-foreground --no-resolv --no-poll --dhcp-authoritative --dhcp-range=" + ipv4Prefix + ".10," + ipv4Prefix + ".99,1h --dhcp-option=option:dns-server,8.8.8.8,8.8.4.4 --dhcp-option-force=43,ANDROID_METERED --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
                }
            }
            if (dpiCircumvention) {
                shellCommand("iptables -t nat -I PREROUTING -i rndis0 -p tcp --dport 80 -j DNAT --to " + ipv4Addr + ":8123");
                shellCommand("iptables -t nat -I PREROUTING -i rndis0 -p tcp --dport 443 -j DNAT --to " + ipv4Addr + ":8123");
                shellCommand("ip6tables -t nat -I PREROUTING -i rndis0 -p tcp --dport 80 -j DNAT --to [" + ipv6Prefix + "1]:8123");
                shellCommand("ip6tables -t nat -I PREROUTING -i rndis0 -p tcp --dport 443 -j DNAT --to [" + ipv6Prefix + "1]:8123");
            }
        }
        return true;
    }

    static void resetInterface(boolean softReset, String ipv4Interface, String ipv6Interface, Boolean ipv6Masquerading, Boolean ipv6SNAT, String ipv4Addr, String ipv6Prefix, String ipv6Addr, Boolean fixTTL, Boolean dnsmasq, String clientBandwidth, boolean dpiCircumvention, String configPath) {
        if (dnsmasq) {
            shellCommand("killall dnsmasq." + Build.SUPPORTED_ABIS[0]);
        }
        if (dpiCircumvention) {
            shellCommand("killall tpws." + Build.SUPPORTED_ABIS[0]);
            shellCommand("iptables -t nat -D PREROUTING -i rndis0 -p tcp --dport 80 -j DNAT --to " + ipv4Addr + ":8123");
            shellCommand("iptables -t nat -D PREROUTING -i rndis0 -p tcp --dport 443 -j DNAT --to " + ipv4Addr + ":8123");
            shellCommand("ip6tables -t nat -D PREROUTING -i rndis0 -p tcp --dport 80 -j DNAT --to [" + ipv6Prefix + "1]:8123");
            shellCommand("ip6tables -t nat -D PREROUTING -i rndis0 -p tcp --dport 443 -j DNAT --to [" + ipv6Prefix + "1]:8123");
        }
        if ( Shell.su("[ \"$(getprop sys.usb.usbtether)\" = \"true\" ]").exec().isSuccess() ) {
            Log.i("USBTether", "Restoring tether interface state");
            String ipv4Prefix = ipv4Addr.substring(0, ipv4Addr.lastIndexOf("."));
            if (Integer.parseInt(clientBandwidth) > 0) {
                shellCommand("iptables -D FORWARD -i " + ipv4Interface + "  -o rndis0 -d " + ipv4Prefix + ".0/24 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
                shellCommand("ip6tables -D FORWARD -i " + ipv6Interface + " -o rndis0 -d " + ipv6Prefix + "/64 -m tcp -p tcp -m hashlimit --hashlimit-mode dstip --hashlimit-above " + clientBandwidth + "kb/s --hashlimit-name max_tether_bandwidth -j DROP");
            }
            if (fixTTL) {
                shellCommand("iptables -t mangle -D FORWARD -i rndis0 -o " + ipv4Interface + " -j TTL --ttl-set 64");
                shellCommand("ip6tables -t mangle -D FORWARD -i rndis0 -o " + ipv6Interface + " -j HL --hl-set 64");
            }
            unconfigureNAT(ipv4Interface, ipv6Interface, ipv6Masquerading, ipv6SNAT, ipv6Addr);
            unforwardInterface(ipv4Interface, ipv6Interface);
            unconfigureRoutes(ipv4Interface, ipv6Interface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT);
            shellCommand("ndc ipfwd disable tethering");
            if (!softReset) {
                shellCommand("setprop sys.usb.usbtether false");
                if (configPath == null) {
                    shellCommand("setprop sys.usb.config adb");
                } else {
                    shellCommand("rm -r " + configPath + "/usbtether");
                }
            }
        } else {
            Log.w("USBTether", "Tether interface not configured");
        }
    }

    static void startTPWS(String ipv4Addr, String ipv6Prefix, String appData) {
        shellCommand("killall tpws." + Build.SUPPORTED_ABIS[0]);
        //shellCommand(appData + "/tpws." + Build.SUPPORTED_ABIS[0] + " --bind-iface4=rndis0 --bind-iface6=rndis0 --port=8123 --split-pos=3 --uid 1:3003 &");
        shellCommand(appData + "/tpws." + Build.SUPPORTED_ABIS[0] + " --bind-addr=" + ipv4Addr + " --bind-addr=" + ipv6Prefix + "1 --port=8123 --split-pos=3 --uid 1:3003 &");
    }

    static void refreshSNAT(String tetherInterface, String ipv6Addr, String newAddr) {
        Log.w("USBTether", "Refreshing SNAT IPTables Rule");
        String prefix = "natctrl";
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            prefix = "tetherctrl";
        }
        shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + ipv6Addr);
        shellCommand("ip6tables -t nat -A " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + newAddr);
    }

    static Boolean testConnection(String tetherInterface) {
        if (Shell.su("ping -c 1 -I " + tetherInterface + " 8.8.8.8").exec().isSuccess() || Shell.su("ping6 -c 1 -I " + tetherInterface + " 2001:4860:4860::8888").exec().isSuccess()) {
            Log.i("usbtether", tetherInterface + " is online");
            return true;
        }
        Log.w("usbtether", tetherInterface + " is offline");
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
}
