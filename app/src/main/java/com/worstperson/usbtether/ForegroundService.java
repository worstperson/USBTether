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

import android.annotation.SuppressLint;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import android.os.SystemClock;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.core.os.HandlerCompat;
import androidx.core.app.NotificationCompat;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.HashMap;

public class ForegroundService extends Service {

    public static final String CHANNEL_ID = "ForegroundServiceChannel";
    public static String networkStatus = "Configuring network";
    public static String usbStatus = "USB disconnected";

    PowerManager powerManager;
    WakeLock wakeLock;

    public static boolean isStarted = false;
    private boolean natApplied = false;
    private boolean needsReset = false;
    private boolean watchdogActive = false;
    private int offlineCounter = 0;

    private String usbInterface;
    final private String tetherInterface = "usbt0";
    private String tetherLocalPrefix = null;

    private String cellularInterface = null;

    HashMap<String, Integer> networkMap = new HashMap<>();

    NotificationCompat.Builder notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .setSilent(true);

    final Handler handler = new Handler(Looper.getMainLooper());
    Runnable delayedRestore = new Runnable() {
        @Override
        public void run() {
            watchdogActive = false;
            if (isStarted) {
                restoreTether();
            }
        }
    };

    public boolean hasRebootOccurred() {
        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        long lastElapsedTime = sharedPref.getLong("lastRun", -1);
        long currentElapsedTime = SystemClock.elapsedRealtime();
        SharedPreferences.Editor editor = sharedPref.edit();
        editor.putLong("lastRun", currentElapsedTime);
        editor.apply();
        return lastElapsedTime == -1 || currentElapsedTime < lastElapsedTime;
    }

    private String getInterfaceName(ConnectivityManager connectivityManager, Network activeNetwork) {
        if (activeNetwork != null) {
            LinkProperties linkProperties = connectivityManager.getLinkProperties(activeNetwork);
            if (linkProperties != null) {
                return linkProperties.getInterfaceName();
            }
        }
        return null;
    }

    private String updateNetworkMap(ConnectivityManager connectivityManager, Network activeNetwork) {
        if (activeNetwork != null) {
            Integer hash;
            int hash2 = activeNetwork.hashCode();
            LinkProperties linkProperties = connectivityManager.getLinkProperties(activeNetwork);
            if (linkProperties != null) {
                String interfaceName = linkProperties.getInterfaceName();
                if (interfaceName != null) {
                    if (networkMap.containsKey(interfaceName) && (hash = networkMap.get(interfaceName)) != null) {
                        if (hash != hash2) {
                            networkMap.replace(interfaceName, hash2);
                        }
                    } else {
                        networkMap.put(interfaceName, hash2);
                    }
                    return interfaceName;
                }
            }
        }
        return null;
    }

    private String pickInterface(String upstreamInterface, String interfaceName, Network activeNetwork, int autostartVPN, ConnectivityManager connectivityManager) {
        if (upstreamInterface.equals("Auto") || autostartVPN == 1 || autostartVPN >= 3) {
            if (activeNetwork != null) {
                // VPN interfaces can be incremented so definitions exclude it
                if (interfaceName != null && (upstreamInterface.equals("Auto") || interfaceName.startsWith(upstreamInterface))) {
                    return interfaceName;
                }
            }
            return null;
        }
        return upstreamInterface;
    }

    private boolean isCellularInterface(Network network, ConnectivityManager connectivityManager) {
        if (connectivityManager != null) {
            // NOTE - is NET_CAPABILITY_NOT_VPN actually necessary?
            NetworkCapabilities networkCapabilities = connectivityManager.getNetworkCapabilities(network);
            if (networkCapabilities != null && networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                return true;
            }
        }
        return false;
    }

    private String setupSNAT(String upstreamInterface, boolean ipv6SNAT) {
        String ipv6Addr = "";
        try {
            if (ipv6SNAT) {
                NetworkInterface networkInterface = NetworkInterface.getByName(upstreamInterface);
                if (networkInterface != null) {
                    for (InetAddress inetAddress : Collections.list(networkInterface.getInetAddresses())) {
                        if (inetAddress instanceof Inet6Address && !inetAddress.isLinkLocalAddress()) {
                            ipv6Addr = inetAddress.getHostAddress();
                            break;
                        }
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return ipv6Addr;
    }

    private void startVPN(int autostartVPN, String wireguardProfile) {
        if (autostartVPN == 1 || autostartVPN == 2) {
            Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_DOWN");
            i.setPackage("com.wireguard.android");
            i.putExtra("tunnel", wireguardProfile);
            sendBroadcast(i);
            i = new Intent("com.wireguard.android.action.SET_TUNNEL_UP");
            i.setPackage("com.wireguard.android");
            i.putExtra("tunnel", wireguardProfile);
            sendBroadcast(i);
        } else if (autostartVPN == 3) {
            Script.stopCloudflare1111Warp();
            Script.startCloudflare1111Warp();
        }
    }

    private String getAddressPrefix(String ipv6Addr) {
        String result = null;
        if (ipv6Addr.contains("::")) {
            result = ipv6Addr.substring(0, ipv6Addr.indexOf("::"));
        } else {
            int count = 0;
            for (int i = 0; i < ipv6Addr.length(); i++) {
                if (ipv6Addr.charAt(i) == ':' && ++count == 4) {
                    result = ipv6Addr.substring(0, i);
                }
            }
        }
        return result;
    }

    private String getLocalPrefix(String tetherInterface) {
        try {
            NetworkInterface networkInterface = NetworkInterface.getByName(tetherInterface);
            if (networkInterface != null) {
                for (InetAddress inetAddress : Collections.list(networkInterface.getInetAddresses())) {
                    String ipv6Addr;
                    if (inetAddress instanceof Inet6Address && inetAddress.isLinkLocalAddress() && (ipv6Addr = inetAddress.getHostAddress()) != null) {
                        return getAddressPrefix(ipv6Addr);
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return null;
    }

    private String getGlobalPrefix(String ipv6Interface, String ipv6Prefix) {
        try {
            NetworkInterface networkInterface = NetworkInterface.getByName(ipv6Interface);
            if (networkInterface != null) {
                for (InetAddress inetAddress : Collections.list(networkInterface.getInetAddresses())) {
                    String ipv6Addr;
                    if (inetAddress instanceof Inet6Address && !inetAddress.isLinkLocalAddress() && (ipv6Addr = inetAddress.getHostAddress()) != null && !ipv6Addr.equals(ipv6Prefix + "1")) {
                        return getAddressPrefix(ipv6Addr);
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return null;
    }

    private String hasXlat(String currentInterface) {
        String clatInterface = "v4-" + currentInterface;
        try {
            NetworkInterface networkInterface = NetworkInterface.getByName(clatInterface);
            if (networkInterface != null) {
                return clatInterface;
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return currentInterface;
    }

    private void socks5Config(String IPv6Interface) {
        File file = new File(getFilesDir().getPath() + "/socks.yml");
        try (FileWriter writer = new FileWriter(file)) {
            writer.append("main:\n");
            writer.append("  workers: 15\n");
            writer.append("  port: 1080\n");
            writer.append("  listen-address: '::1'\n");
            writer.append("  listen-ipv6-only: true\n");
            writer.append("  bind-interface: '").append(IPv6Interface).append("'\n");
            writer.append("misc:\n");
            writer.append("  task-stack-size: 30720\n");
            writer.append("  pid-file: ").append(getFilesDir().getPath()).append("/socks.pid\n\n");
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void tproxyConfig(String ipv6Prefix) {
        File file = new File(getFilesDir().getPath() + "/tproxy.yml");
        try (FileWriter writer = new FileWriter(file)) {
            writer.append("socks5:\n");
            writer.append("  port: 1080\n");
            writer.append("  address: '::1'\n\n");
            writer.append("  udp: 'udp'\n\n");
            writer.append("tcp:\n");
            writer.append("  port: 1088\n");
            writer.append("  address: '::1'\n\n");
            writer.append("udp:\n");
            writer.append("  port: 1088\n");
            writer.append("  address: '::1'\n\n");
            writer.append("dns:\n");
            writer.append("  port: 1053\n");
            writer.append("  address: '::'\n");
            writer.append("  upstream: '").append(ipv6Prefix).append("1'\n");
            writer.append("misc:\n");
            writer.append("  task-stack-size: 30720\n");
            writer.append("  pid-file: ").append(getFilesDir().getPath()).append("/tproxy.pid\n\n");
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // FIXME - BUG - disable IPv6 when IPv6 is unavailable
    // FIXME - FEATURE - disable IPv6 when MTU is lower than spec allows
    // FIXME !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    // FIXME - Increase timer after failed cellular recovery
    // FIXME - Increase timer after failed VPN recovery
    // FIXME - Add upstream check when starting a VPN service, wait on on network availability
    // FIXME - Remove callback when waiting on network availability, use receivers instead
    // FIXME !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    private void restoreTether() {

        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String upstreamInterface = sharedPref.getString("upstreamInterface", "Auto");
        String lastIPv4Interface = sharedPref.getString("lastIPv4Interface", "");
        String lastIPv6Interface = sharedPref.getString("lastIPv6Interface", "");
        String lastIPv6 = sharedPref.getString("lastIPv6", "");
        String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
        boolean mangleTTL = sharedPref.getBoolean("mangleTTL", true);
        boolean dpiCircumvention = sharedPref.getBoolean("dpiCircumvention", false);
        boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
        String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
        String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
        int autostartVPN = sharedPref.getInt("autostartVPN", 0);
        String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
        String clientBandwidth = sharedPref.getString("clientBandwidth", "0");
        boolean cellularWatchdog = sharedPref.getBoolean("cellularWatchdog", false);

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        Network activeNetwork = null;
        if (connectivityManager != null) {
            activeNetwork = connectivityManager.getActiveNetwork();
        }
        String interfaceName = updateNetworkMap(connectivityManager, activeNetwork);

        cellularInterface = isCellularInterface(activeNetwork, connectivityManager) ? interfaceName : cellularInterface;
        String currentIPv6Interface = pickInterface(upstreamInterface, interfaceName, activeNetwork, autostartVPN, connectivityManager);
        String currentIPv4Interface = currentIPv6Interface;

        Log.i("USBTether", "Checking connection availability...");
        boolean cellularUP = true;
        String cellularIPv6 = cellularInterface;
        if (cellularIPv6 != null) {
            String cellularIPv4 = hasXlat(cellularIPv6);
            if (currentIPv6Interface == null || !currentIPv6Interface.equals(cellularIPv6)) {
                if (cellularWatchdog) {
                    // Only check that any protocol is working, it's not the tethered network so we don't care if just one goes down
                    // Keeps from having to pull APN configs, check for plat servers, and getting caught in loops during partial outages
                    cellularUP = Script.testConnection(cellularIPv4, false) || Script.testConnection(cellularIPv6, true);
                }
            } else {
                currentIPv4Interface = cellularIPv4;
            }
        // can't assume cellularInterface has been assigned so do nothing
        /*} else if (cellularWatchdog) {
            cellularUP = false;*/
        }
        if (cellularUP) {
            if (currentIPv6Interface != null && Script.testConnection(currentIPv4Interface, false) && ((!ipv6TYPE.equals("MASQUERADE") && !ipv6TYPE.equals("SNAT")) || Script.testConnection(currentIPv6Interface, true))) {
                offlineCounter = 0;
                if (!natApplied || ((upstreamInterface.equals("Auto") || autostartVPN > 0) && !currentIPv6Interface.equals(lastIPv6Interface))) {
                    // Configure Tether
                    if (!natApplied) {
                        Log.i("USBTether", "Starting tether operation...");
                    } else {
                        Log.i("USBTether", "Network changed, resetting interface...");
                        Script.unconfigureTether(tetherInterface, lastIPv4Interface, lastIPv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE, lastIPv6, mangleTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention);
                        natApplied = false;
                    }
                    String ipv6Addr = setupSNAT(currentIPv6Interface, ipv6TYPE.equals("SNAT"));
                    if (ipv6TYPE.equals("TPROXY")) {
                        socks5Config(currentIPv6Interface);
                    }
                    SharedPreferences.Editor edit = sharedPref.edit();
                    edit.putString("lastIPv4Interface", currentIPv4Interface);
                    edit.putString("lastIPv6Interface", currentIPv6Interface);
                    edit.putString("lastIPv6", ipv6Addr);
                    edit.apply();
                    if (Script.configureTether(tetherInterface, tetherLocalPrefix, currentIPv4Interface, currentIPv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE, ipv6Addr, mangleTTL, dnsmasq, getApplicationInfo().nativeLibraryDir, getFilesDir().getPath(), clientBandwidth, dpiCircumvention)) {
                        natApplied = true;
                        if (ipv6TYPE.equals("TPROXY")) {
                            // Add TPROXY exception
                            String prefix = getGlobalPrefix(currentIPv6Interface, ipv6Prefix);
                            if (prefix != null) {
                                Log.i("TetherTPROXY", prefix);
                                Script.setTPROXYRoute(prefix);
                            }
                        }
                        networkStatus = "Tether is configured";
                        notification.setContentTitle(networkStatus + ", " + usbStatus);
                        mNotificationManager.notify(1, notification.build());
                        needsReset = false; // clear this if set
                    } else {
                        Log.w("USBTether", "Failed configuring tether, resetting interface...");
                        Script.unconfigureInterface(tetherInterface);
                        Script.unconfigureRNDIS(getApplicationInfo().nativeLibraryDir);
                        usbInterface = Script.configureRNDIS(getApplicationInfo().nativeLibraryDir);
                        if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                            Log.i("USBTether", "Resetting interface, creating callback to retry tether in 5 seconds...");
                            handler.postDelayed(delayedRestore, 5000);
                            networkStatus = "Retrying after configuration failure";
                            notification.setContentTitle(networkStatus + ", " + usbStatus);
                            mNotificationManager.notify(1, notification.build());
                        }
                    }
                } else {
                    // Restore Tether
                    if (needsReset) {
                        Log.i("USBTether", "Restoring tether...");
                        // Update SNAT if needed
                        String newAddr = setupSNAT(currentIPv6Interface, ipv6TYPE.equals("SNAT"));
                        if (!newAddr.isEmpty() && !newAddr.equals(lastIPv6)) {
                            Script.refreshSNAT(currentIPv6Interface, lastIPv6, newAddr);
                            SharedPreferences.Editor edit = sharedPref.edit();
                            edit.putString("lastIPv6", newAddr);
                            edit.apply();
                        }
                        if (ipv6TYPE.equals("TPROXY")) {
                            // Add TPROXY exception
                            String prefix = getGlobalPrefix(currentIPv6Interface, ipv6Prefix);
                            if (prefix != null) {
                                Log.i("TetherTPROXY", prefix);
                                Script.setTPROXYRoute(prefix);
                            }
                        }
                        if (Script.checkRules(currentIPv4Interface, currentIPv6Interface)) {
                            // Brings tether back up on connection change
                            Script.unconfigureRules();
                            Script.configureRules(tetherInterface, currentIPv4Interface, currentIPv6Interface);
                        } else {
                            Log.i("USBTether", "ip rules still valid");
                        }
                        networkStatus = "Tether is configured";
                        notification.setContentTitle(networkStatus + ", " + usbStatus);
                        mNotificationManager.notify(1, notification.build());
                        needsReset = false;
                    } else {
                        if (dnsmasq || mangleTTL || dpiCircumvention || ipv6TYPE.equals("TPROXY")) {
                            Log.i("USBTether", "Checking processes...");
                            Script.checkProcesses(tetherInterface, ipv4Addr, ipv6Prefix, ipv6TYPE, mangleTTL, dnsmasq, dpiCircumvention, getApplicationInfo().nativeLibraryDir, getFilesDir().getPath());
                        }
                        networkStatus = "Tether is configured";
                        notification.setContentTitle(networkStatus + ", " + usbStatus);
                        mNotificationManager.notify(1, notification.build());
                    }
                }
                // Start watchdog if nothing else is scheduled
                if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                    watchdogActive = true;
                    Log.i("USBTether", "Creating callback to check tether in 120 seconds...");
                    handler.postDelayed(delayedRestore, 120000);
                }
            } else if (autostartVPN > 0) {
                // Reset VPN if tether hasn't been applied, interface is missing, or has been offline for 25 seconds
                boolean resetVPN = !natApplied || currentIPv6Interface == null || offlineCounter >= 5;
                if (resetVPN) {
                    offlineCounter = 0;
                    Log.w("USBTether", "VPN connection is DOWN, restarting...");
                    startVPN(autostartVPN, wireguardProfile);
                    if (natApplied) {
                        needsReset = true;
                    }
                    if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                        Log.i("USBTether", "Waiting for VPN, creating callback to restore tether in 10 seconds...");
                        handler.postDelayed(delayedRestore, 10000);
                        networkStatus = "Waiting for VPN network";
                        notification.setContentTitle(networkStatus + ", " + usbStatus);
                        mNotificationManager.notify(1, notification.build());
                    }
                } else {
                    offlineCounter += 1;
                    Log.i("USBTether", "VPN offline, waiting on counter");
                    if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                        Log.i("USBTether", "Waiting for VPN, creating callback to restore tether in 5 seconds...");
                        handler.postDelayed(delayedRestore, 5000);
                        networkStatus = "Waiting for VPN network";
                        notification.setContentTitle(networkStatus + ", " + usbStatus);
                        mNotificationManager.notify(1, notification.build());
                    }
                }
            } else {
                // network down, no recourse
                offlineCounter = offlineCounter + 1;
                Log.w("USBTether", "Failed, tether interface unavailable");
                if (natApplied) {
                    needsReset = true;
                }
                if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                    Log.i("USBTether", "Waiting for network, creating callback to restore tether in 5 seconds...");
                    handler.postDelayed(delayedRestore, 5000);
                    networkStatus = "Waiting for network availability";
                    notification.setContentTitle(networkStatus + ", " + usbStatus);
                    mNotificationManager.notify(1, notification.build());
                }
            }
        } else {
            // Reset cellular if tether hasn't been applied, interface is missing, or has been offline for 25 seconds
            if (!natApplied || cellularIPv6 == null || offlineCounter >= 5) {
                offlineCounter = 0;
                Log.w("USBTether", "Cellular connection is DOWN, attempting recovery");
                Script.recoverDataConnection();
                if (natApplied) {
                    needsReset = true;
                }
                if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                    Log.i("USBTether", "Recovering cellular connection, creating callback to restore tether in 25 seconds...");
                    handler.postDelayed(delayedRestore, 25000);
                    networkStatus = "Recovering cellular connection";
                    notification.setContentTitle(networkStatus + ", " + usbStatus);
                    mNotificationManager.notify(1, notification.build());
                }
            } else {
                offlineCounter += 1;
                Log.i("USBTether", "Cellular offline, waiting on counter");
                if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                    Log.i("USBTether", "Waiting for cellular network, creating callback to restore tether in 5 seconds...");
                    handler.postDelayed(delayedRestore, 5000);
                    networkStatus = "Waiting for cellular network";
                    notification.setContentTitle(networkStatus + ", " + usbStatus);
                    mNotificationManager.notify(1, notification.build());
                }
            }
        }
    }

    // Some devices go into Discharging state rather then Not Charging
    // when charge control apps are used, so we can't use BatteryManager
    // This actually works way better anyway, even though it's undocumented
    private final BroadcastReceiver USBReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            Log.i("USBTether", "Recieved USB_STATE broadcast");
            Bundle extras = intent.getExtras();
            if (extras != null) { // Work around this? Can always pull from sysfs
                if (extras.getBoolean("connected")) {
                    Log.i("USBTether", "USB Connected");
                    if (extras.getBoolean("configured")) {
                        Log.i("USBTether", "USB Configured");
                        Script.bindBridge(tetherInterface, usbInterface);
                        usbStatus = "USB connected";
                        notification.setContentTitle(networkStatus + ", " + usbStatus);
                        mNotificationManager.notify(1, notification.build());
                    } else {
                        Log.i("USBTether", "USB Not Configured");
                    }
                } else {
                    Log.i("USBTether", "USB Disconnected");
                    usbStatus = "USB disconnected";
                    notification.setContentTitle(networkStatus + ", " + usbStatus);
                    mNotificationManager.notify(1, notification.build());
                }
            }
        }
    };

    // TESTING
    // I'm making a big assumption here that a change in hash can be used to detect invalidated routes.
    // This is probably not true and will result connections loss without automated recovery.
    // The route check is relatively cheap, why am I wasting time doing this?
    private final ConnectivityManager.NetworkCallback NETReceiver = new ConnectivityManager.NetworkCallback() {
        @Override
        public void onLost(@NonNull Network network) {
            super.onLost(network);

            Log.i("USBTether", "Received a ConnectivityManager onLost event");

            if (watchdogActive) {
                ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
                SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
                String upstreamInterface = sharedPref.getString("upstreamInterface", "Auto");
                String lastIPv6Interface = sharedPref.getString("lastIPv6Interface", "");
                int autostartVPN = sharedPref.getInt("autostartVPN", 0);
                boolean cellularWatchdog = sharedPref.getBoolean("cellularWatchdog", false);

                boolean setCallback = false;
                Network activeNetwork = null;
                if (connectivityManager != null) {
                    activeNetwork = connectivityManager.getActiveNetwork();
                }
                //String interfaceName = updateNetworkMap(connectivityManager, activeNetwork);
                String interfaceName = getInterfaceName(connectivityManager, activeNetwork);
                Integer hash;
                if ((upstreamInterface.equals("Auto") || autostartVPN > 0) && !lastIPv6Interface.equals(pickInterface(upstreamInterface, interfaceName, activeNetwork, autostartVPN, connectivityManager))) {
                    Log.i("USBTether", "Active network " + lastIPv6Interface + " changed...");
                    setCallback = true;
                } else if (networkMap.containsKey(lastIPv6Interface) && (hash = networkMap.get(lastIPv6Interface)) != null && hash == network.hashCode()) {
                    Log.i("USBTether", "Tethered network " + lastIPv6Interface + " was lost...");
                    needsReset = true;
                    setCallback = true;
                } else if (cellularWatchdog && cellularInterface != null && networkMap.containsKey(cellularInterface) && (hash = networkMap.get(cellularInterface)) != null && hash == network.hashCode()) {
                    Log.i("USBTether", "Cellular network " + cellularInterface + " was lost...");
                    needsReset = true;
                    setCallback = true;
                }
                // FIXME - manually check network if it's not contained in networkMap?

                if (setCallback) {
                    if (HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                        Log.i("USBTether", "Clearing watchdog after network change");
                        handler.removeCallbacks(delayedRestore);
                        watchdogActive = false;
                    }
                    Log.i("USBTether", "Network lost, creating callback to restore tether in 5 seconds...");
                    handler.postDelayed(delayedRestore, 5000);
                    networkStatus = "Restoring after lost network";
                    notification.setContentTitle(networkStatus + ", " + usbStatus);
                    NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                    mNotificationManager.notify(1, notification.build());
                }
            }
        }

        // FIXME - hashCode() doesn't always change, verify it actually triggers on rule loss
        //  might be better to just check directly?
        @Override
        public void onLinkPropertiesChanged(@NonNull Network network, @NonNull LinkProperties linkProperties) {
            super.onLinkPropertiesChanged(network, linkProperties);

            Log.i("USBTether", "Received a ConnectivityManager onLinkPropertiesChanged event");

            ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            Network activeNetwork = null;
            if (connectivityManager != null) {
                activeNetwork = connectivityManager.getActiveNetwork();
            }
            //String interfaceName = updateNetworkMap(connectivityManager, activeNetwork);
            String interfaceName = getInterfaceName(connectivityManager, activeNetwork);

            cellularInterface = isCellularInterface(activeNetwork, connectivityManager) ? interfaceName : cellularInterface;

            SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
            String lastIPv6Interface = sharedPref.getString("lastIPv6Interface", "");

            Integer hash;
            int hash2 = network.hashCode();

            if (watchdogActive) {
                // TODO: update SNAT if onAvailable is not triggered?
                String upstreamInterface = sharedPref.getString("upstreamInterface", "Auto");
                int autostartVPN = sharedPref.getInt("autostartVPN", 0);
                boolean cellularWatchdog = sharedPref.getBoolean("cellularWatchdog", false);

                boolean setCallback = false;
                if ((upstreamInterface.equals("Auto") || autostartVPN > 0) && !lastIPv6Interface.equals(pickInterface(upstreamInterface, interfaceName, activeNetwork, autostartVPN, connectivityManager))) {
                    Log.i("USBTether", "Active network " + lastIPv6Interface + " changed...");
                    setCallback = true;
                } else if (cellularWatchdog && cellularInterface != null && networkMap.containsKey(cellularInterface) && (hash = networkMap.get(cellularInterface)) != null && hash == hash2) {
                    Log.i("USBTether", "Cellular network " + cellularInterface + " changed...");
                    needsReset = true;
                    setCallback = true;
                }
                if (interfaceName != null) {
                    if (networkMap.containsKey(interfaceName) && (hash = networkMap.get(interfaceName)) != null) {
                        if (hash != hash2) {
                            if (lastIPv6Interface.equals(interfaceName)) {
                                Log.i("USBTether", "Tethered network " + lastIPv6Interface + " changed...");
                                needsReset = true;
                                setCallback = true;
                            }
                            networkMap.replace(interfaceName, hash2);
                        }
                    } else {
                        networkMap.put(interfaceName, hash2);
                    }
                }

                if (setCallback) {
                    if (HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                        Log.i("USBTether", "Clearing watchdog after network change");
                        handler.removeCallbacks(delayedRestore);
                        watchdogActive = false;
                    }
                    Log.i("USBTether", "Network change, creating callback to restore tether in 5 seconds...");
                    handler.postDelayed(delayedRestore, 5000);
                    networkStatus = "Restoring after network change";
                    notification.setContentTitle(networkStatus + ", " + usbStatus);
                    NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                    mNotificationManager.notify(1, notification.build());
                }
            } else if (interfaceName != null) {
                if (!networkMap.containsKey(interfaceName) || (hash = networkMap.get(interfaceName)) == null || hash != hash2) {
                    Log.i("USBTether", "adding " + interfaceName + " to networkMap");
                    networkMap.put(interfaceName, hash2);
                }
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();

        //isStarted = true;
    }

    @SuppressLint("WakelockTimeout")
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        super.onStartCommand(intent, flags, startId);

        boolean hasTTL = Script.hasTTL;
        boolean hasNFQUEUE = Script.hasNFQUEUE;
        boolean hasTPROXY = Script.hasTPROXY;
        boolean hasTable = Script.hasTable;
        boolean hasSNAT = Script.hasSNAT;
        boolean hasMASQUERADE = Script.hasMASQUERADE;
        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        boolean mangleTTL = sharedPref.getBoolean("mangleTTL", true);
        String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
        String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";

        // Disable previous tether if the service was not properly stopped
        if (!hasRebootOccurred()) {
            Log.i("USBTether", "Disabling previous USBTether instance...");
            String lastIPv4Interface = sharedPref.getString("lastIPv4Interface", "");
            String lastIPv6Interface = sharedPref.getString("lastIPv6Interface", "");
            String lastIPv6 = sharedPref.getString("lastIPv6", "");
            boolean dpiCircumvention = sharedPref.getBoolean("dpiCircumvention", false);
            boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
            String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
            String clientBandwidth = sharedPref.getString("clientBandwidth", "0");
            Script.unconfigureTether(tetherInterface, lastIPv4Interface, lastIPv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE, lastIPv6, mangleTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention);
            Script.unconfigureRNDIS(getApplicationInfo().nativeLibraryDir);
            Script.destroyBridge(tetherInterface);
        }

        tproxyConfig(ipv6Prefix);

        SharedPreferences.Editor edit = sharedPref.edit();
        if (mangleTTL && !hasTTL && !hasNFQUEUE) {
            edit.putBoolean("mangleTTL", false);
        }
        if ((ipv6TYPE.equals("TPROXY") && !hasTPROXY) || (ipv6TYPE.equals("SNAT") && (!hasTable || !hasSNAT)) || (ipv6TYPE.equals("MASQUERADE") && (!hasTable || !hasMASQUERADE))) {
            edit.putString("ipv6TYPE", "None");
        }
        edit.apply();

        powerManager = (PowerManager) getSystemService(POWER_SERVICE);
        if (powerManager != null) {
            wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "USB Tether::TetherWakelockTag");
            if (wakeLock != null && !wakeLock.isHeld()) {
                wakeLock.acquire();
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel serviceChannel = new NotificationChannel(CHANNEL_ID, "Foreground Service Channel", NotificationManager.IMPORTANCE_HIGH);
            NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (notificationManager != null) {
                notificationManager.createNotificationChannel(serviceChannel);
            }
        }

        Toast.makeText(this, "Service started by user.", Toast.LENGTH_LONG).show();

        notification.setContentTitle(networkStatus + ", " + usbStatus);
        startForeground(1, notification.build());

        usbInterface = Script.configureRNDIS(getApplicationInfo().nativeLibraryDir);
        Script.createBridge(tetherInterface);
        tetherLocalPrefix = getLocalPrefix(tetherInterface);
        assert tetherLocalPrefix != null; // FIXME should never be null but...

        if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
            handler.postDelayed(delayedRestore, 5000);
        }

        registerReceiver(USBReceiver, new IntentFilter("android.hardware.usb.action.USB_STATE"));

        NetworkRequest.Builder builder = new NetworkRequest.Builder();
        builder = builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED);
        NetworkRequest networkRequest = builder.build();

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        connectivityManager.registerNetworkCallback(networkRequest, NETReceiver);

        // Some devices don't broadcast after USBReceiver is registered
        if (Script.isUSBConfigured()) {
            Script.bindBridge(tetherInterface, usbInterface);
            NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            usbStatus = "USB connected";
            notification.setContentTitle(networkStatus + ", " + usbStatus);
            mNotificationManager.notify(1, notification.build());
        }

        return Service.START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();

        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }

        try {
            unregisterReceiver(USBReceiver);
        } catch (IllegalArgumentException ignored) {}

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        connectivityManager.unregisterNetworkCallback(NETReceiver);

        if (HandlerCompat.hasCallbacks(handler, delayedRestore)) {
            handler.removeCallbacks(delayedRestore);
        }

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String lastIPv4Interface = sharedPref.getString("lastIPv4Interface", "");
        String lastIPv6Interface = sharedPref.getString("lastIPv6Interface", "");
        String lastIPv6 = sharedPref.getString("lastIPv6", "");
        String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
        boolean mangleTTL = sharedPref.getBoolean("mangleTTL", true);
        boolean dpiCircumvention = sharedPref.getBoolean("dpiCircumvention", false);
        boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
        String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
        String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
        String clientBandwidth = sharedPref.getString("clientBandwidth", "0");

        SharedPreferences.Editor editor = sharedPref.edit();
        editor.putLong("lastRun", -1);
        editor.apply();

        if (!lastIPv6Interface.isEmpty()) {
            Script.unconfigureTether(tetherInterface, lastIPv4Interface, lastIPv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE, lastIPv6, mangleTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention);
            Script.unconfigureRNDIS(getApplicationInfo().nativeLibraryDir);
            Script.destroyBridge(tetherInterface);
        }

        natApplied = false;
        isStarted = false;

        Toast.makeText(this, "Service destroyed by user.", Toast.LENGTH_LONG).show();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
