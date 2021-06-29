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
        for ( String message : Shell.su(command).exec().getOut() ) {
            Log.i("USBTether", message);
        }
    }

    static private boolean set_ip_addresses(String ipv6Prefix) {
        Log.i("USBTether", "Setting IP addresses");
        shellCommand("ip -6 addr add " + ipv6Prefix + "1/64 dev rndis0 scope global");
        shellCommand("ndc interface setcfg rndis0 192.168.42.129 24 up");
        Log.i("USBTether", "Waiting for interface to come up");
        for (int waitTime = 1; waitTime <= 3; waitTime++) {
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

    static private void add_marked_routes(String ipv6Prefix) {
        Log.i("USBTether", "Adding marked routes");
        shellCommand("ndc network interface add 99 rndis0");
        shellCommand("ndc network route add 99 rndis0 192.168.42.0/24");
        shellCommand("ndc network route add 99 rndis0 " + ipv6Prefix + "/64");
        shellCommand("ndc network route add 99 rndis0 fe80::/64");
    }

    static private void enable_ip_forwarding() {
        Log.i("USBTether", "Enabling IP forwarding");
        shellCommand("ndc ipfwd enable tethering");
    }

    static private void set_up_nat(String tetherInterface, Boolean ipv6Masquerading, Boolean ipv6SNAT, String ipv6Addr) {
        Log.i("USBTether", "Setting up NAT");
        shellCommand("ndc nat enable rndis0 " + tetherInterface + " 99");
        shellCommand("ndc ipfwd add rndis0 " + tetherInterface);
        if (ipv6Masquerading || ipv6SNAT) {
            String prefix = "natctrl";
            String counter = prefix+"_tether";
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                prefix = "tetherctrl";
                counter = prefix;
            }
            shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -g " + counter + "_counters");
            shellCommand("ip6tables -t filter -A " + prefix + "_FORWARD -i " + tetherInterface + " -o rndis0 -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
            shellCommand("ip6tables -t filter -A " + prefix + "_FORWARD -i rndis0 -o " + tetherInterface + " -m state --state INVALID -j DROP");
            shellCommand("ip6tables -t filter -A " + prefix + "_FORWARD -i rndis0 -o " + tetherInterface + " -g " + counter + "_counters");
            shellCommand("ip6tables -t filter -A " + prefix + "_FORWARD -j DROP");
            shellCommand("ip6tables -t mangle -A tetherctrl_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");
            shellCommand("ip6tables -t nat -N " + prefix + "_nat_POSTROUTING");
            shellCommand("ip6tables -t nat -A POSTROUTING -j " + prefix + "_nat_POSTROUTING");
            if (ipv6SNAT) {
                shellCommand("ip6tables -t nat -A " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + ipv6Addr);
            } else {
                shellCommand("ip6tables -t nat -A " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j MASQUERADE");
            }
        }
    }

    static void configureRNDIS() {
        if ( !Shell.su("[ \"$(getprop sys.usb.state)\" = \"rndis,adb\" ]").exec().isSuccess() ) {
            Shell.su("setprop sys.usb.config \"rndis,adb\"").exec();
            Shell.su("until [ \"$(getprop sys.usb.state)\" = \"rndis,adb\" ]; do sleep 1; done").exec();
        } else {
            Log.w("USBTether", "Tether interface already configured?!?");
        }
    }

    static boolean configureNAT(String tetherInterface, Boolean ipv6Masquerading, Boolean ipv6SNAT, String ipv6Prefix, String ipv6Addr, Boolean fixTTL, Boolean dnsmasq, String appData) {
        // Check that rndis0 is actually available to avoid wasting time
        if (!Shell.su("ip link set dev rndis0 down").exec().isSuccess()) {
            Log.w("usbtether", "Aborting tether...");
            Shell.su("setprop sys.usb.config \"adb\"").exec();
            Shell.su("until [ \"$(getprop sys.usb.state)\" = \"adb\" ]; do sleep 1; done").exec();
            return false;
        } else {
            enable_ip_forwarding();
            set_up_nat(tetherInterface, ipv6Masquerading, ipv6SNAT, ipv6Addr);
            if (fixTTL) {
                shellCommand("iptables -t mangle -A FORWARD -i rndis0 -o " + tetherInterface + " -j TTL --ttl-set 64");
                if (ipv6Masquerading || ipv6SNAT) { // Won't work with encapsulated traffic
                    shellCommand("ip6tables -t mangle -A FORWARD -i rndis0 -o " + tetherInterface + " -j HL --hl-set 64");
                }
            }
            if (dnsmasq) {
                shellCommand("rm " + appData + "/dnsmasq.leases");
                shellCommand("rm " + appData + "/dnsmasq.pid");
                shellCommand(appData + "/dnsmasq." + Build.SUPPORTED_ABIS[0] + " --keep-in-foreground --no-resolv --no-poll --dhcp-authoritative --dhcp-range=192.168.42.10,192.168.42.99,1h --dhcp-range=" + ipv6Prefix + "10," + ipv6Prefix + "99,slaac,64,1h --dhcp-option=option:dns-server,8.8.8.8,8.8.4.4 --dhcp-option=option6:dns-server,[2001:4860:4860::8888],[2001:4860:4860::8844] --dhcp-option-force=43,ANDROID_METERED --listen-mark 0xf0063 --dhcp-leasefile=" + appData + "/dnsmasq.leases --pid-file=" + appData + "/dnsmasq.pid &");
            }
        }
        return true;
    }

    static boolean configureRoutes(String ipv6Prefix) {
        if (!Shell.su("ip link set dev rndis0 down").exec().isSuccess()) {
            Log.w("usbtether", "No tether interface...");
        } else {
            if (set_ip_addresses(ipv6Prefix)) {
                add_marked_routes(ipv6Prefix);
                return true;
            }
        }
        return false;
    }

    static void resetInterface(String tetherInterface, Boolean ipv6Masquerading, Boolean ipv6SNAT, String ipv6Prefix, String IPv6addr, Boolean fixTTL, Boolean dnsmasq) {
        if (dnsmasq) {
            shellCommand("killall dnsmasq." + Build.SUPPORTED_ABIS[0]);
        }
        if ( Shell.su("[ \"$(getprop sys.usb.state)\" = \"rndis,adb\" ]").exec().isSuccess() ) {
            Log.i("USBTether", "Restoring tether interface state");
            if (fixTTL) {
                shellCommand("iptables -t mangle -D FORWARD -i rndis0 -o " + tetherInterface + " -j TTL --ttl-set 64");
                shellCommand("ip6tables -t mangle -D FORWARD -i rndis0 -o " + tetherInterface + " -j HL --hl-set 64");
            }
            if (ipv6Masquerading || ipv6SNAT) {
                String prefix = "natctrl";
                String counter = prefix + "_tether";
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    prefix = "tetherctrl";
                    counter = prefix;
                }
                if (ipv6SNAT) {
                    shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j SNAT --to " + IPv6addr);
                } else {
                    shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j MASQUERADE");
                }
                shellCommand("ip6tables -t nat -D POSTROUTING -j " + prefix + "_nat_POSTROUTING");
                shellCommand("ip6tables -t nat -X " + prefix + "_nat_POSTROUTING");
                shellCommand("ip6tables -t mangle -D tetherctrl_mangle_FORWARD -p tcp -m tcp --tcp-flags SYN SYN -j TCPMSS --clamp-mss-to-pmtu");
                shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -j DROP");
                shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i rndis0 -o " + tetherInterface + " -g " + counter + "_counters");
                shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i rndis0 -o " + tetherInterface + " -m state --state INVALID -j DROP");
                shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i " + tetherInterface + " -o rndis0 -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
            }
            shellCommand("ndc ipfwd remove rndis0 " + tetherInterface);
            shellCommand("ndc nat disable rndis0 " + tetherInterface + " 99");
            shellCommand("ndc network interface remove 99 rndis0");
            shellCommand("ip -6 route del " + ipv6Prefix  + "/64 dev rndis0 src " + ipv6Prefix  + "1");
            shellCommand("ndc interface clearaddrs rndis0");
            shellCommand("ndc interface setcfg rndis0 down");
            shellCommand("ndc ipfwd disable tethering");
            Shell.su("setprop sys.usb.config \"adb\"").exec();
        } else {
            Log.w("USBTether", "Tether interface not configured");
        }
    }
}
