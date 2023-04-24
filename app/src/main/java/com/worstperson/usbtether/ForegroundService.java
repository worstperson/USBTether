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
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import android.util.Log;
import android.widget.Toast;
import androidx.core.os.HandlerCompat;
import androidx.core.app.NotificationCompat;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;

public class ForegroundService extends Service {

    public static final String CHANNEL_ID = "ForegroundServiceChannel";

    PowerManager powerManager;
    WakeLock wakeLock;

    static public Boolean isStarted = false;
    private boolean natApplied = false;
    private boolean needsReset = false;
    private boolean usbReconnect = false;
    private boolean watchdogActive = false;
    private int offlineCounter = 0;

    private String gadgetPath = null;
    private String configPath = null;
    private String rndisPath = null;
    private String ncmPath = null;

    private String usbInterface;

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

    private String isCellularActive() {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        Network[] networks = connectivityManager.getAllNetworks();
        for (Network network : networks) {
            NetworkCapabilities networkCapabilities = connectivityManager.getNetworkCapabilities(network);
            if (networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    networkCapabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    networkCapabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                String mobileNetwork = connectivityManager.getLinkProperties(network).getInterfaceName();
                try {
                    // Do not return clat interfaces
                    // TODO: this is probably not needed, but I can't test atm
                    NetworkInterface checkInterface = NetworkInterface.getByName(mobileNetwork);
                    if (checkInterface != null && !checkInterface.isPointToPoint()) {
                        return mobileNetwork;
                    }
                } catch (SocketException e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    private String pickInterface(String upstreamInterface) {
        if (upstreamInterface.equals("Auto")) {
            ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (connectivityManager != null) {
                Network activeNetwork = connectivityManager.getActiveNetwork();
                if (activeNetwork != null) {
                    LinkProperties linkProperties = connectivityManager.getLinkProperties(activeNetwork);
                    if (linkProperties != null) {
                        return linkProperties.getInterfaceName();
                    }
                }
            }
            return null;
        }
        return upstreamInterface;
    }

    private String setupSNAT(String upstreamInterface, Boolean ipv6SNAT) {
        String ipv6Addr = "";
        try {
            if (ipv6SNAT) {
                NetworkInterface netint = NetworkInterface.getByName(upstreamInterface);
                if (netint != null) {
                    for (InetAddress inetAddress : Collections.list(netint.getInetAddresses())) {
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

    private void startVPN(int autostartVPN, String wireguardProfile, boolean resetVPN) {
        if (autostartVPN == 1 || autostartVPN == 2) {
            if (resetVPN) {
                Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_DOWN");
                i.setPackage("com.wireguard.android");
                i.putExtra("tunnel", wireguardProfile);
                sendBroadcast(i);
            }
            Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_UP");
            i.setPackage("com.wireguard.android");
            i.putExtra("tunnel", wireguardProfile);
            sendBroadcast(i);
        } else {
            if (autostartVPN == 3) {
                if (resetVPN) {
                    Script.stopGoogleOneVPN();
                }
                Script.startGoogleOneVPN();
            } else if (autostartVPN == 4) {
                if (resetVPN) {
                    Script.stopCloudflare1111Warp();
                }
                Script.startCloudflare1111Warp();
            }
        }
    }

    /*private void stopVPN(int autostartVPN, String wireguardProfile) {
        if (autostartVPN == 1 || autostartVPN == 2) {
            Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_DOWN");
            i.setPackage("com.wireguard.android");
            i.putExtra("tunnel", wireguardProfile);
            sendBroadcast(i);
        } else {
            if (autostartVPN == 3) {
                Script.stopGoogleOneVPN();
            } else if (autostartVPN == 4) {
                Script.stopCloudflare1111Warp();
            }
        }
    }*/

    private String getPrefix(String iface, String ipv6Prefix) {
        try {
            NetworkInterface netint = NetworkInterface.getByName(iface);
            if (netint != null) {
                for (InetAddress inetAddress : Collections.list(netint.getInetAddresses())) {
                    if (inetAddress instanceof Inet6Address && !inetAddress.isLinkLocalAddress() && inetAddress.getHostAddress() != null && !inetAddress.getHostAddress().equals(ipv6Prefix + "1")) {
                        String ipv6Addr = inetAddress.getHostAddress();
                        if (ipv6Addr.contains("::")) {
                            return ipv6Addr.split("::")[0];
                        } else {
                            String[] tmp = ipv6Addr.split(":");
                            return tmp[0] + ":" + tmp[1] + ":" + tmp[2] + ":" + tmp[3];
                        }
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return null;
    }

    private boolean hasXlat(String currentInterface) {
        try { //Check for separate CLAT interface
            NetworkInterface netint = NetworkInterface.getByName("v4-" + currentInterface);
            if (netint != null) {
                for (InetAddress inetAddress : Collections.list(netint.getInetAddresses())) {
                    if (inetAddress instanceof Inet4Address) {
                        return true;
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return false;
    }


    // FIXME - BUG - disable IPv6 when IPv6 is unavailable
    // FIXME - FEATURE - disable IPv6 when MTU is lower than spec allows
    private void restoreTether() {

        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        if (isStarted && Script.isUSBConfigured()) {

            SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
            String upstreamInterface = sharedPref.getString("upstreamInterface", "Auto");
            String lastIPv4Interface = sharedPref.getString("lastIPv4Interface", "");
            String lastIPv6Interface = sharedPref.getString("lastIPv6Interface", "");
            String lastIPv6 = sharedPref.getString("lastIPv6", "");
            String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
            Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
            boolean dpiCircumvention = sharedPref.getBoolean("dpiCircumvention", false);
            boolean dmz = sharedPref.getBoolean("dmz", false);
            Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
            String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
            String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
            int autostartVPN = sharedPref.getInt("autostartVPN", 0);
            String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
            String clientBandwidth = sharedPref.getString("clientBandwidth", "0");
            boolean cellularWatchdog = sharedPref.getBoolean("cellularWatchdog", false);
            int usbMode = sharedPref.getInt("usbMode", 0);
            boolean preferNCM = sharedPref.getBoolean("preferNCM", false);

            String currentIPv6Interface = pickInterface(upstreamInterface);
            if (currentIPv6Interface != null && !currentIPv6Interface.equals("") && !currentIPv6Interface.equals("Auto")) {
                Log.i("USBTether", "Checking connection availability...");
                String cellularIface = isCellularActive();
                if (!cellularWatchdog || (cellularIface != null && (Script.testConnection(cellularIface) || Script.testConnection6(cellularIface)))) {
                    NetworkInterface checkInterface;
                    boolean isUp = false;
                    boolean ipv4UP = false;
                    boolean ipv6UP = false;
                    String currentIPv4Interface = currentIPv6Interface;
                    try {
                        checkInterface = NetworkInterface.getByName(currentIPv6Interface);
                        if (checkInterface != null) { // Exception passed try block; Stop being lazy
                            isUp = checkInterface.isUp();
                            if (isUp) {
                                if (!natApplied && currentIPv6Interface.startsWith("rmnet")) {
                                    if (hasXlat(currentIPv6Interface)) {
                                        currentIPv4Interface = "v4-" + currentIPv4Interface;
                                    }
                                }
                                ipv4UP = Script.testConnection(currentIPv4Interface);
                                ipv6UP = (ipv6TYPE.equals("MASQUERADE") || ipv6TYPE.equals("SNAT")) ? Script.testConnection6(currentIPv6Interface) : true;
                            }
                        }
                    } catch (SocketException e) {
                        e.printStackTrace();
                    }
                    if (isUp && ipv4UP && ipv6UP) {
                        offlineCounter = 0;
                        if (!natApplied || (upstreamInterface.equals("Auto") && !currentIPv6Interface.equals(lastIPv6Interface))) {
                            // Configure Tether
                            if (!natApplied) {
                                Log.i("USBTether", "Starting tether operation...");
                            } else {
                                Log.i("USBTether", "Network changed, resetting interface...");
                                Script.unconfigureTether(usbInterface, lastIPv4Interface, lastIPv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE, lastIPv6, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz);
                                natApplied = false;
                            }
                            String ipv6Addr = setupSNAT(currentIPv6Interface, ipv6TYPE.equals("SNAT"));
                            SharedPreferences.Editor edit = sharedPref.edit();
                            edit.putString("lastIPv4Interface", currentIPv4Interface);
                            edit.putString("lastIPv6Interface", currentIPv6Interface);
                            edit.putString("lastIPv6", ipv6Addr);
                            edit.apply();
                            if (Script.configureTether(usbInterface, currentIPv4Interface, currentIPv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE, ipv6Addr, fixTTL, dnsmasq, getApplicationInfo().nativeLibraryDir, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz, usbMode)) {
                                natApplied = true;
                                // Start bound services
                                if (dpiCircumvention) {
                                    Script.startTPWS(ipv4Addr, ipv6Prefix, getApplicationInfo().nativeLibraryDir, getFilesDir().getPath());
                                }
                                if (ipv6TYPE.equals("TPROXY")) {
                                    // Add TPROXY exception
                                    String tmp = getPrefix(currentIPv6Interface, ipv6Prefix);
                                    if (tmp != null) {
                                        Log.i("TetherTPROXY", tmp);
                                        Script.setTPROXYRoute(tmp);
                                    }
                                }
                                notification.setContentTitle("Service is running, Connected");
                                mNotificationManager.notify(1, notification.build());
                            } else {
                                Log.w("USBTether", "Failed configuring tether, resetting interface...");
                                Script.unconfigureInterface(usbInterface);
                                Script.unconfigureRNDIS(usbMode, gadgetPath, configPath, rndisPath, ncmPath);
                                usbInterface = Script.configureRNDIS(usbMode, preferNCM, gadgetPath, configPath, rndisPath, ncmPath);
                                if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                                    Log.i("USBTether", "Resetting interface, creating callback to retry tether in 5 seconds...");
                                    handler.postDelayed(delayedRestore, 5000);
                                    notification.setContentTitle("Service is running, resetting interface after failure");
                                    mNotificationManager.notify(1, notification.build());
                                }
                            }
                        } else {
                            // Restore Tether
                            if (needsReset) {
                                Log.i("USBTether", "Restoring tether...");
                                // Update SNAT if needed
                                String newAddr = setupSNAT(currentIPv6Interface, ipv6TYPE.equals("SNAT"));
                                if (!newAddr.equals("") && !newAddr.equals(lastIPv6)) {
                                    Script.refreshSNAT(currentIPv6Interface, lastIPv6, newAddr);
                                    SharedPreferences.Editor edit = sharedPref.edit();
                                    edit.putString("lastIPv6", newAddr);
                                    edit.apply();
                                }
                                if (ipv6TYPE.equals("TPROXY")) {
                                    // Add TPROXY exception
                                    String tmp = getPrefix(currentIPv6Interface, ipv6Prefix);
                                    if (tmp != null) {
                                        Log.i("TetherTPROXY", tmp);
                                        Script.setTPROXYRoute(tmp);
                                    }
                                }
                                if (usbReconnect) {
                                    Script.unconfigureInterface(usbInterface);
                                    if (Script.configureInterface(usbInterface, currentIPv4Interface, currentIPv6Interface, ipv4Addr, ipv6Prefix, usbMode)) {
                                        // Start bound services
                                        if (dpiCircumvention) {
                                            Script.startTPWS(ipv4Addr, ipv6Prefix, getApplicationInfo().nativeLibraryDir, getFilesDir().getPath());
                                        }
                                        notification.setContentTitle("Service is running, Connected");
                                        mNotificationManager.notify(1, notification.build());
                                    } else {
                                        Log.w("USBTether", "Failed to restore after USB reset, resetting interface...");
                                        Script.unconfigureTether(usbInterface, currentIPv4Interface, currentIPv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE, lastIPv6, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz);
                                        Script.unconfigureRNDIS(usbMode, gadgetPath, configPath, rndisPath, ncmPath);
                                        usbInterface = Script.configureRNDIS(usbMode, preferNCM, gadgetPath, configPath, rndisPath, ncmPath);
                                        natApplied = false;
                                        if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                                            Log.i("USBTether", "Resetting interface, creating callback to retry tether in 5 seconds...");
                                            handler.postDelayed(delayedRestore, 5000);
                                            notification.setContentTitle("Service is running, resetting interface after failure");
                                            mNotificationManager.notify(1, notification.build());
                                        }
                                    }
                                } else {
                                    // Brings tether back up on connection change
                                    Script.unconfigureRules();
                                    Script.configureRules(usbInterface, currentIPv4Interface, currentIPv6Interface);
                                    notification.setContentTitle("Service is running, Connected");
                                    mNotificationManager.notify(1, notification.build());
                                }
                                usbReconnect = false;
                                needsReset = false;
                            } else {
                                if (dnsmasq || dpiCircumvention || ipv6TYPE.equals("TPROXY")) {
                                    Log.i("USBTether", "Checking processes...");
                                    Script.checkProcesses(ipv4Addr, ipv6Prefix, ipv6TYPE, dnsmasq, getApplicationInfo().nativeLibraryDir, getFilesDir().getPath(), dpiCircumvention);
                                }
                                notification.setContentTitle("Service is running, Connected");
                                mNotificationManager.notify(1, notification.build());
                            }
                        }
                        // Start watchdog if nothing else is scheduled
                        if (autostartVPN > 0 || cellularWatchdog || dnsmasq || dpiCircumvention || ipv6TYPE.equals("TPROXY")) {
                            if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                                watchdogActive = true;
                                Log.i("USBTether", "Creating callback to check tether in 60 seconds...");
                                handler.postDelayed(delayedRestore, 60000);
                            }
                        }
                    } else if (autostartVPN > 0) {
                        boolean resetVPN = !natApplied || offlineCounter >= 5;
                        if (resetVPN) {
                            offlineCounter = 0;
                            Log.w("USBTether", "VPN connection is DOWN, restarting...");
                            //stopVPN(autostartVPN, wireguardProfile);
                            startVPN(autostartVPN, wireguardProfile, true);
                            if (natApplied) {
                                needsReset = true;
                            }
                        } else {
                            offlineCounter += 1;
                            Log.i("USBTether", "VPN offline, waiting on counter");
                            notification.setContentTitle("Service is running, VPN offline");
                            mNotificationManager.notify(1, notification.build());
                        }
                        if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                            Log.i("USBTether", "Waiting for VPN, creating callback to restore tether in 5 seconds...");
                            handler.postDelayed(delayedRestore, 5000);
                            notification.setContentTitle("Service is running, waiting for VPN network");
                            mNotificationManager.notify(1, notification.build());
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
                            notification.setContentTitle("Service is running, waiting for network availability");
                            mNotificationManager.notify(1, notification.build());
                        }
                    }
                } else {
                    Log.w("USBTether", "Cellular connection is DOWN, attempting recovery");
                    Script.recoverDataConnection();
                    if (natApplied) {
                        needsReset = true;
                    }
                    if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                        Log.i("USBTether", "Recovering cellular connection, creating callback to restore tether in 5 seconds...");
                        handler.postDelayed(delayedRestore, 5000);
                        notification.setContentTitle("Service is running, recovering cellular connection...");
                        mNotificationManager.notify(1, notification.build());
                    }
                }
            } else {
                Log.w("USBTether", "Tether failed, invalid interface");
                if (natApplied) {
                    needsReset = true;
                }
                notification.setContentTitle("Service is running, no upstream interface");
                mNotificationManager.notify(1, notification.build());
            }
        } /*else {
            // USB NOT CONNECTED
        }*/
    }

    // Some devices go into Discharging state rather then Not Charging
    // when charge control apps are used, so we can't use BatteryManager
    // This actually works way better anyway, even though it's undocumented
    private final BroadcastReceiver USBReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {

            NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

            Log.i("USBTether", "Recieved USB_STATE broadcast");
            if (intent.getExtras().getBoolean("connected")) {
                Log.i("USBTether", "USB Connected");
                if (intent.getExtras().getBoolean("configured")) {
                    Log.i("USBTether", "USB Configured");
                    if (natApplied) {
                        // Fix for Google One VPN
                        needsReset = true;
                    }
                    boolean hasCallback = HandlerCompat.hasCallbacks(handler, delayedRestore);
                    if (watchdogActive && hasCallback) {
                        Log.i("USBTether", "Clearing watchdog after network change");
                        handler.removeCallbacks(delayedRestore);
                        watchdogActive = false;
                        hasCallback = false;
                    }
                    if (!hasCallback) {
                        if (natApplied && !usbReconnect) {
                            // Restore right away if there was no disconnect event
                            restoreTether();
                        } else {
                            Log.i("USBTether", "Configuring interface, creating callback to restore tether in 5 seconds...");
                            handler.postDelayed(delayedRestore, 5000);
                            notification.setContentTitle("Service is running, configuring interface");
                            mNotificationManager.notify(1, notification.build());
                        }
                    } else {
                        Log.i("USBTether", "Tether restore callback already scheduled");
                    }
                } else {
                    Log.i("USBTether", "USB Not Configured");
                }
            } else {
                Log.i("USBTether", "USB Disconnected");
                if (natApplied) {
                    needsReset = true;
                    usbReconnect = true;
                }
                // Stop bound services
                Script.stopTPWS(getFilesDir().getPath());
                if (HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                    Log.i("USBTether", "USB Disconnected, removing tether restore callback");
                    handler.removeCallbacks(delayedRestore);
                }
                notification.setContentTitle("Service is running, USB disconnected");
                mNotificationManager.notify(1, notification.build());
            }
        }
    };

    @Override
    public void onCreate() {
        super.onCreate();

        isStarted = true;
    }

    @SuppressLint("WakelockTimeout")
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        boolean hasTTL = Script.hasTTL;
        boolean hasTPROXY = Script.hasTPROXY;
        boolean hasTable = Script.hasTable;
        boolean hasSNAT = Script.hasSNAT;
        boolean hasMASQUERADE = Script.hasMASQUERADE;
        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
        int usbMode = sharedPref.getInt("usbMode", 0);
        boolean preferNCM = sharedPref.getBoolean("preferNCM", false);
        SharedPreferences.Editor edit = sharedPref.edit();
        if (fixTTL && !hasTTL) {
            edit.putBoolean("fixTTL", false);
        }
        if ((ipv6TYPE.equals("TPROXY") && !hasTPROXY) || (ipv6TYPE.equals("SNAT") && (!hasTable || !hasSNAT)) || (ipv6TYPE.equals("MASQUERADE") && (!hasTable || !hasMASQUERADE))) {
            edit.putString("ipv6TYPE", "None");
        }
        edit.apply();

        String[] vars = Script.gadgetVars();

        gadgetPath = vars[0];
        configPath = vars[1];
        rndisPath = vars[2];
        ncmPath = vars[3];

        Log.i("usbtether", "gadgetPath: " + gadgetPath);
        Log.i("usbtether", "configPath: " + configPath);
        Log.i("usbtether", "rndisPath: " + rndisPath);
        Log.i("usbtether", "ncmPath: " + ncmPath);

        powerManager = (PowerManager) getSystemService(POWER_SERVICE);
        if (powerManager != null) {
            wakeLock = powerManager.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "USB Tether::TetherWakelockTag");
        }
        if (wakeLock != null && !wakeLock.isHeld()) {
            wakeLock.acquire();
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel serviceChannel = new NotificationChannel(CHANNEL_ID, "Foreground Service Channel", NotificationManager.IMPORTANCE_HIGH);
            NotificationManager notificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            if (notificationManager != null) {
                notificationManager.createNotificationChannel(serviceChannel);
            }
        }

        Toast.makeText(this, "Service started by user.", Toast.LENGTH_LONG).show();

        notification.setContentTitle("Service is running, USB disconnected");
        startForeground(1, notification.build());

        usbInterface = Script.configureRNDIS(usbMode, preferNCM, gadgetPath, configPath, rndisPath, ncmPath);

        registerReceiver(USBReceiver, new IntentFilter("android.hardware.usb.action.USB_STATE"));

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkRequest.Builder builder = new NetworkRequest.Builder();
        builder = builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED);

        NetworkRequest networkRequest = builder.build();

        connectivityManager.registerNetworkCallback(networkRequest, new ConnectivityManager.NetworkCallback() {
            @Override
            public void onLinkPropertiesChanged(Network network, LinkProperties linkProperties) {
                super.onLinkPropertiesChanged(network, linkProperties);
                SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
                String upstreamInterface = sharedPref.getString("upstreamInterface", "Auto");
                String lastIPv6Interface = sharedPref.getString("lastIPv6Interface", "");
                if ((upstreamInterface.equals("Auto") && !lastIPv6Interface.equals(pickInterface(upstreamInterface)))
                        || linkProperties.getInterfaceName().equals(lastIPv6Interface)) {
                    Log.i("USBTether", "Tethered network " + lastIPv6Interface + " changed...");
                    needsReset = true;

                    boolean hasCallback = HandlerCompat.hasCallbacks(handler, delayedRestore);
                    if (watchdogActive && hasCallback) {
                        Log.i("USBTether", "Clearing watchdog after network change");
                        handler.removeCallbacks(delayedRestore);
                        watchdogActive = false;
                        hasCallback = false;
                    }
                    if (!hasCallback) {
                        Log.i("USBTether", "Network change, creating callback to restore tether in 5 seconds...");
                        handler.postDelayed(delayedRestore, 5000);
                        notification.setContentTitle("Service is running, restoring after network change");
                        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                        mNotificationManager.notify(1, notification.build());
                    }
                }
            }
        });


        if (Script.isUSBConfigured()) {
            NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            Log.i("USBTether", "Configuring interface, creating callback to restore tether in 5 seconds...");
            handler.postDelayed(delayedRestore, 5000);
            notification.setContentTitle("Service is running, configuring interface");
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

        if (HandlerCompat.hasCallbacks(handler, delayedRestore)) {
            handler.removeCallbacks(delayedRestore);
        }

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String lastIPv4Interface = sharedPref.getString("lastIPv4Interface", "");
        String lastIPv6Interface = sharedPref.getString("lastIPv6Interface", "");
        String lastIPv6 = sharedPref.getString("lastIPv6", "");
        String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
        Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        boolean dpiCircumvention = sharedPref.getBoolean("dpiCircumvention", false);
        boolean dmz = sharedPref.getBoolean("dmz", false);
        Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
        String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
        String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
        String clientBandwidth = sharedPref.getString("clientBandwidth", "0");
        int usbMode = sharedPref.getInt("usbMode", 0);

        if (!lastIPv6Interface.equals("")) {
            // Stop bound services
            Script.unconfigureTether(usbInterface, lastIPv4Interface, lastIPv6Interface, ipv4Addr, ipv6Prefix, ipv6TYPE, lastIPv6, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz);
            Script.unconfigureRNDIS(usbMode, gadgetPath, configPath, rndisPath, ncmPath);
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
