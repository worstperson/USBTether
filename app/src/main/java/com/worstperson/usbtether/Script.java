package com.worstperson.usbtether;

import com.topjohnwu.superuser.Shell;
import android.util.Log;

public class Script {

    static {
        Shell.enableVerboseLogging = BuildConfig.DEBUG;
        Shell.setDefaultBuilder(Shell.Builder.create()
                .setFlags(Shell.FLAG_REDIRECT_STDERR)
                .setTimeout(10));
    }

    static private void shellCommand(String command) {
        for ( String message : Shell.su(command).exec().getOut() ) {
            Log.w("USBTether", message);
        }

    }

    static private void set_ip_addresses() throws InterruptedException {
        Log.w("USBTether", "Setting IP addresses");
        shellCommand("ip -6 addr add fd00::1/64 dev rndis0 scope global");
        shellCommand("ndc interface setcfg rndis0 192.168.42.129 24 up");
        Log.w("USBTether", "Waiting for interface to come up");
        for (int waitTime = 1; waitTime <= 10; waitTime++) {
            if (Shell.su("[ \"$(cat /sys/class/net/rndis0/operstate)\" = \"up\" ]").exec().isSuccess()) {
                break;
            }
            Log.w("USBTether", String.valueOf(waitTime));
            Thread.sleep(1000);
        }
        Thread.sleep(3000);
        shellCommand("ip -6 route add fd00::/64 dev rndis0 src fd00::1");
    }

    static private void add_marked_routes() {
        Log.w("USBTether", "Adding marked routes");
        shellCommand("ndc network interface add 99 rndis0");
        shellCommand("ndc network route add 99 rndis0 192.168.42.0/24");
        shellCommand("ndc network route add 99 rndis0 fd00::/64");
        shellCommand("ndc network route add 99 rndis0 fe80::/64");
    }

    static private void enable_ip_forwarding() {
        Log.w("USBTether", "Enabling IP forwarding");
        shellCommand("ndc ipfwd enable tethering");
    }

    static private void set_up_nat(String tetherInterface, Boolean ipv6Masquerading) {
        Log.w("USBTether", "Setting up NAT");
        shellCommand("ndc nat enable rndis0 " + tetherInterface + " 99");
        shellCommand("ndc ipfwd add rndis0 " + tetherInterface);
        if (ipv6Masquerading) {
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
            shellCommand("ip6tables -t nat -N " + prefix + "_nat_POSTROUTING");
            shellCommand("ip6tables -t nat -A POSTROUTING -j " + prefix + "_nat_POSTROUTING");
            shellCommand("ip6tables -t nat -A " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j MASQUERADE");
        }
    }

    static void runCommands(String tetherInterface, Boolean ipv6Masquerading, Boolean fixTTL) throws InterruptedException {
        Log.w("USBTether", "Waiting for tether interface");
        for (int waitTime = 1; waitTime <= 30; waitTime++) {
            if (Shell.su("[ -d \"/sys/class/net/" + tetherInterface + "\" ]").exec().isSuccess()) {
                Thread.sleep(3000);
                if ( !Shell.su("[ \"$(getprop sys.usb.state)\" = \"rndis,adb\" ]").exec().isSuccess() ) {
                    Shell.su("setprop sys.usb.config \"rndis,adb\"").exec();
                    Shell.su("until [ \"$(getprop sys.usb.state)\" = \"rndis,adb\" ]; do sleep 1; done; sleep 2").exec();
                    set_ip_addresses();
                    add_marked_routes();
                    enable_ip_forwarding();
                    set_up_nat(tetherInterface, ipv6Masquerading);
                    if (fixTTL) {
                        // PREROUTING rules cause IPv6 packets to drop
                        shellCommand("iptables -t mangle -A POSTROUTING -o " + tetherInterface + " -j TTL --ttl-set 64");
                        //if (ipv6Masquerading) { //FIXME: breaks mobile connectivity and does not even work afaict
                        //    shellCommand("ip6tables -t mangle -A POSTROUTING -o " + tetherInterface + " -j HL --hl-set 64");
                        //}
                    }
                } else {
                    Log.w("USBTether", "Tether interface already configured?!?");
                }
                return;
            }
            Log.w("USBTether", String.valueOf(waitTime));
            Thread.sleep(1000);
        }
        Log.w("USBTether", "Tether interface never came up");
    }

    static void resetInterface(String tetherInterface, Boolean ipv6Masquerading, Boolean fixTTL) {
        if ( Shell.su("[ \"$(getprop sys.usb.state)\" = \"rndis,adb\" ]").exec().isSuccess() ) {
            Log.w("USBTether", "Restoring tether interface state");
            if (ipv6Masquerading) {
                String prefix = "natctrl";
                String counter = prefix + "_tether";
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    prefix = "tetherctrl";
                    counter = prefix;
                }
                shellCommand("ip6tables -t nat -D " + prefix + "_nat_POSTROUTING -o " + tetherInterface + " -j MASQUERADE");
                shellCommand("ip6tables -t nat -D POSTROUTING -j " + prefix + "_nat_POSTROUTING");
                shellCommand("ip6tables -t nat -X " + prefix + "_nat_POSTROUTING");
                shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -j DROP");
                shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i rndis0 -o " + tetherInterface + " -g " + counter + "_counters");
                shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i rndis0 -o " + tetherInterface + " -m state --state INVALID -j DROP");
                shellCommand("ip6tables -t filter -D " + prefix + "_FORWARD -i " + tetherInterface + " -o rndis0 -m state --state RELATED,ESTABLISHED -g " + counter + "_counters");
            }
            shellCommand("ndc ipfwd remove rndis0 " + tetherInterface);
            shellCommand("ndc nat disable rndis0 " + tetherInterface + " 99");
            shellCommand("ndc network interface remove 99 rndis0");
            shellCommand("ip -6 route del fd00::/64 dev rndis0 src fd00::1");
            shellCommand("ndc interface clearaddrs rndis0");
            shellCommand("ndc interface setcfg rndis0 down");
            shellCommand("ndc ipfwd disable tethering");
            Shell.su("setprop sys.usb.config \"adb\"").exec();
            if (fixTTL) {
                shellCommand("iptables -t mangle -D POSTROUTING -o " + tetherInterface + " -j TTL --ttl-set 64");
                //shellCommand("ip6tables -t mangle -D POSTROUTING -o " + tetherInterface + " -j HL --hl-set 64");
            }
        } else {
            Log.w("USBTether", "Tether interface not configured");
        }
    }
}
