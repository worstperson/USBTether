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

import android.annotation.SuppressLint;
import android.app.Notification;
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
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import android.widget.Toast;
import androidx.core.app.NotificationCompat;

import android.os.PowerManager;
import android.os.PowerManager.WakeLock;

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
    private boolean usbState = false;

    private String pickInterface(String tetherInterface) {
        if (tetherInterface.equals("Auto")) {
            ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (connectivityManager != null) {
                Network activeNetwork = connectivityManager.getActiveNetwork();
                if (activeNetwork != null) {
                    LinkProperties linkProperties = connectivityManager.getLinkProperties(activeNetwork);
                    if (linkProperties != null) {
                        tetherInterface = linkProperties.getInterfaceName();
                    }
                }
            }
        }
        return tetherInterface;
    }

    private boolean waitInterface(String tetherInterface) {
        //We need to wait for the interface to become configured
        Log.i("usbtether", "Waiting for " + tetherInterface + "...");
        int count = 1;
        while (count < 10) {
            try {
                // fixme - this ping test does not belong here
                if (NetworkInterface.getByName(tetherInterface) != null && Script.testConnection(tetherInterface)) {
                    return true;
                }
            } catch (SocketException e) {
                e.printStackTrace();
            }
            Log.i("usbtether", "Waiting for " + tetherInterface + "..." + count);
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            count = count + 1;
        }
        return false;
    }

    private String setupSNAT(String tetherInterface, Boolean ipv6SNAT) {
        String ipv6Addr = "";
        try {
            if (ipv6SNAT) {
                NetworkInterface netint = NetworkInterface.getByName(tetherInterface);
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

    private void startVPN(int autostartVPN, String wireguardProfile, String currentInterface) {
        if (autostartVPN == 1 || autostartVPN == 2) {
            Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_UP");
            i.setPackage("com.wireguard.android");
            i.putExtra("tunnel", wireguardProfile);
            sendBroadcast(i);
        } else {
            if (autostartVPN == 3) {
                Script.startGoogleOneVPN();
            } else if (autostartVPN == 4) {
                Script.startCloudflare1111Warp();
            }
        }
        waitInterface(currentInterface);
    }

    // FIXME - BUG - disable IPv6 when IPv6 is unavailable
    // FIXME - FEATURE - disable IPv6 when MTU is lower than spec allows
    //  (AT&T Cricket has broken IPv6, MTU is set to the minimum for IPv4, don't use it)
    private void restoreTether(boolean isConnected) {
        if (isConnected) {
            SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
            String tetherInterface = sharedPref.getString("tetherInterface", "Auto");
            String lastNetwork = sharedPref.getString("lastNetwork", "");
            String lastIPv6 = sharedPref.getString("lastIPv6", "");
            Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
            Boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
            Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
            Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
            String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
            String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
            boolean isXLAT = sharedPref.getBoolean("isXLAT", false);
            int autostartVPN = sharedPref.getInt("autostartVPN", 0);
            String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
            String clientBandwidth = sharedPref.getString("clientBandwidth", "0");
            String ipv4Prefix = "";
            if (isXLAT) {
                ipv4Prefix = "v4-";
            }

            String currentInterface = pickInterface(tetherInterface);
            NetworkInterface checkInterface = null;
            boolean isUp = false;
            try {
                checkInterface = NetworkInterface.getByName(currentInterface);
                if (checkInterface != null) { // Exception passed try block; Stop being lazy
                    isUp = checkInterface.isUp();
                }
            } catch (SocketException e) {
                e.printStackTrace();
            }

            // Restart VPN if needed
            if (autostartVPN > 0 && !isUp) {
                Log.w("usbtether", "VPN down, restarting...");
                startVPN(autostartVPN, wireguardProfile, currentInterface);
                if (natApplied) {
                    needsReset = true;
                }
                try {
                    checkInterface = NetworkInterface.getByName(currentInterface);
                    if (checkInterface != null) { // Exception passed try block; Stop being lazy
                        isUp = checkInterface.isUp();
                    }
                } catch (SocketException e) {
                    e.printStackTrace();
                }
            }

            if (currentInterface != null && !currentInterface.equals("") && !currentInterface.equals("Auto")) {
                if (!natApplied || (natApplied && tetherInterface.equals("Auto") && !currentInterface.equals(lastNetwork))) { // Configure Tether
                    if (!natApplied) {
                        Log.w("usbtether", "Starting tether operation...");
                    } else {
                        Log.w("usbtether", "Network changed, resetting interface...");
                        Script.resetInterface(true, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, clientBandwidth);
                        natApplied = false;
                    }
                    if (waitInterface(currentInterface)) {
                        String ipv6Addr = setupSNAT(currentInterface, ipv6SNAT);
                        SharedPreferences.Editor edit = sharedPref.edit();
                        edit.putString("lastNetwork", currentInterface);
                        edit.putString("lastIPv6", ipv6Addr);
                        edit.putBoolean("isXLAT", false); // hmm...
                        ipv4Prefix = "";
                        try { //Check for separate CLAT interface
                            NetworkInterface netint = NetworkInterface.getByName("v4-" + currentInterface);
                            if (netint != null) {
                                for (InetAddress inetAddress : Collections.list(netint.getInetAddresses())) {
                                    if (inetAddress instanceof Inet4Address) {
                                        ipv4Prefix = "v4-";
                                        edit.putBoolean("isXLAT", true);
                                    }
                                }
                            }
                        } catch (SocketException e) {
                            e.printStackTrace();
                        }
                        edit.apply();
                        natApplied = Script.configureNAT(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Masquerading, ipv6SNAT, ipv6Prefix, ipv6Addr, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth);
                        if (!Script.configureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT)) {
                            Log.w("usbtether", "Failed configuring tether, resetting interface...");
                            Script.resetInterface(false, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, clientBandwidth);
                            natApplied = false;
                            Script.configureRNDIS();
                        }
                    } else {
                        Log.w("usbtether", "Failed, tether interface unavailable");
                    }
                } else { // Restore Tether
                    if (isUp) {
                        if (needsReset) {
                            Log.w("usbtether", "Restoring tether...");
                            // Update SNAT if needed
                            String newAddr = setupSNAT(currentInterface, ipv6SNAT);
                            if (!newAddr.equals("") && !newAddr.equals(lastIPv6)) {
                                Script.refreshSNAT(currentInterface, lastIPv6, newAddr);
                                SharedPreferences.Editor edit = sharedPref.edit();
                                edit.putString("lastIPv6", newAddr);
                                edit.apply();
                            }
                            if (usbReconnect && !Script.configureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT)) {
                                Log.w("usbtether", "Failed to restore after USB reset, resetting interface...");
                                Script.resetInterface(false, ipv4Prefix + currentInterface, currentInterface, ipv6Masquerading, ipv6SNAT, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, clientBandwidth);
                                natApplied = false;
                                Script.configureRNDIS();
                            } else {
                                // Brings tether back up on connection change
                                Script.forwardInterface(ipv4Prefix + currentInterface, currentInterface);
                            }
                            usbReconnect = false;
                            needsReset = false;
                        } else {
                            Log.i("usbtether", "No action required");
                        }
                    } else {
                        Log.w("usbtether", "Interface down, setting reset flag...");
                        needsReset = true;
                    }
                }
            } else {
                Log.w("usbtether", "Tether failed, invalid interface");
            }
        } else {
            Log.i("usbtether", "USB not connected");
        }
    }

    // Some devices go into Discharging state rather then Not Charging
    // when charge control apps are used, so we can't use BatteryManager
    // This actually works way better anyway, even though it's undocumented
    private final BroadcastReceiver USBReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i("usbtether", "Recieved USB_STATE broadcast");
            if (intent.getExtras().getBoolean("connected")) {
                Log.i("usbtether", "USB Connected");
                if (intent.getExtras().getBoolean("configured")) {
                    Log.i("usbtether", "USB Configured");
                    if (natApplied) {
                        // Fix for Google One VPN
                        needsReset = true;
                    }
                    usbState = true;
                    restoreTether(true);
                } else {
                    Log.i("usbtether", "USB Not Configured");
                }
            } else {
                Log.i("usbtether", "USB Disconnected");
                if (natApplied) {
                    needsReset = true;
                    usbReconnect = true;
                }
                usbState = false;
            }
        }
    };

    // This does not broadcast on mobile changes (ex. 3g->lte)
    // This does not broadcast on WireGuard's kernel module interface
    // This does broadcast on mobile data availability
    private final BroadcastReceiver ConnectionReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i("usbtether", "Recieved CONNECTIVITY_CHANGE broadcast");
            restoreTether(usbState);
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

        Notification notification = new NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("Service is running")
                .setSmallIcon(R.mipmap.ic_launcher)
                .setOngoing(true)
                .build();

        Toast.makeText(this, "Service started by user.", Toast.LENGTH_LONG).show();

        startForeground(1, notification);

        registerReceiver(USBReceiver, new IntentFilter("android.hardware.usb.action.USB_STATE"));
        registerReceiver(ConnectionReceiver, new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"));
        Script.configureRNDIS();

        return Service.START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
        unregisterReceiver(USBReceiver);
        unregisterReceiver(ConnectionReceiver);

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String lastNetwork = sharedPref.getString("lastNetwork", "");
        String lastIPv6 = sharedPref.getString("lastIPv6", "");
        Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
        Boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
        Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
        String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
        String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
        Boolean isXLAT = sharedPref.getBoolean("isXLAT", false);
        String clientBandwidth = sharedPref.getString("clientBandwidth", "0");
        String ipv4Prefix = "";
        if (isXLAT) {
            ipv4Prefix = "v4-";
        }

        if (!lastNetwork.equals("")) {
            Script.resetInterface(false, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, clientBandwidth);
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
