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
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
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
    private int offlineCounter = 0;

    private String gadgetPath = null;
    private String configPath = null;
    private String functionPath = null;

    NotificationCompat.Builder notification = new NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .setSilent(true);

    final Handler handler = new Handler(Looper.getMainLooper());
    Runnable delayedRestore = new Runnable() {
        @Override
        public void run() {
            restoreTether();
        }
    };

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

    // FIXME - BUG - disable IPv6 when IPv6 is unavailable
    // FIXME - FEATURE - disable IPv6 when MTU is lower than spec allows
    private void restoreTether() {

        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        if (Script.isUSBConfigured()) {
            SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
            String tetherInterface = sharedPref.getString("tetherInterface", "Auto");
            String lastNetwork = sharedPref.getString("lastNetwork", "");
            String lastIPv6 = sharedPref.getString("lastIPv6", "");
            Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
            Boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
            Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
            boolean dpiCircumvention = sharedPref.getBoolean("dpiCircumvention", false);
            boolean dmz = sharedPref.getBoolean("dmz", false);
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

            // Restart VPN if interface is down or has no connectivity for over 30 seconds
            boolean resetVPN = offlineCounter >= 5;
            if (resetVPN) {
                offlineCounter = 0;
            }
            if (autostartVPN > 0 && (!isUp || resetVPN)) {
                Log.i("usbtether", "VPN down, restarting...");
                startVPN(autostartVPN, wireguardProfile, resetVPN);
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

            // fixme - make this a selectable gui option to allow/disallow offline connections
            // fixme - we only know the primary interface at this point
            if (isUp && (tetherInterface.equals("Auto") || (Script.testConnection(currentInterface) && ((!ipv6Masquerading && !ipv6SNAT) || Script.testConnection6(currentInterface))))) {
                offlineCounter = 0;
                if (currentInterface != null && !currentInterface.equals("") && !currentInterface.equals("Auto")) {
                    if (!natApplied || (natApplied && tetherInterface.equals("Auto") && !currentInterface.equals(lastNetwork))) {
                        // Configure Tether
                        if (!natApplied) {
                            Log.i("usbtether", "Starting tether operation...");
                        } else {
                            Log.i("usbtether", "Network changed, resetting interface...");
                            Script.unconfigureTether(ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, clientBandwidth, dpiCircumvention, dmz);
                            natApplied = false;
                        }
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
                        natApplied = Script.configureTether(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Masquerading, ipv6SNAT, ipv6Prefix, ipv6Addr, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz, configPath, functionPath);
                        if (!natApplied || !Script.configureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT)) {
                            if (natApplied) {
                                Log.w("usbtether", "Failed configuring tether, resetting interface...");
                                Script.unconfigureTether(ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, clientBandwidth, dpiCircumvention, dmz);
                                Script.unconfigureRNDIS(configPath);
                                natApplied = false;
                            }
                            if (!handler.hasCallbacks(delayedRestore)) {
                                Log.i("usbtether", "Creating callback to retry tether in 5 seconds...");
                                handler.postDelayed(delayedRestore, 5000);
                                notification.setContentTitle("Service is running, waiting 5 seconds...");
                                mNotificationManager.notify(1, notification.build());
                            }
                        } else {
                            if (dpiCircumvention) {
                                Script.startTPWS(ipv4Addr, ipv6Prefix, getFilesDir().getPath());
                            }
                            notification.setContentTitle("Service is running, Connected");
                            mNotificationManager.notify(1, notification.build());
                        }
                    } else {
                        // Restore Tether
                        if (needsReset) {
                            Log.i("usbtether", "Restoring tether...");
                            // Update SNAT if needed
                            String newAddr = setupSNAT(currentInterface, ipv6SNAT);
                            if (!newAddr.equals("") && !newAddr.equals(lastIPv6)) {
                                Script.refreshSNAT(currentInterface, lastIPv6, newAddr);
                                SharedPreferences.Editor edit = sharedPref.edit();
                                edit.putString("lastIPv6", newAddr);
                                edit.apply();
                            }
                            if (usbReconnect) {
                                Script.unconfigureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix);
                                if (!Script.configureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT)) {
                                    Log.w("usbtether", "Failed to restore after USB reset, resetting interface...");
                                    Script.unconfigureTether(ipv4Prefix + currentInterface, currentInterface, ipv6Masquerading, ipv6SNAT, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, clientBandwidth, dpiCircumvention, dmz);
                                    Script.unconfigureRNDIS(configPath);
                                    natApplied = false;
                                    if (!handler.hasCallbacks(delayedRestore)) {
                                        Log.i("usbtether", "Creating callback to retry tether in 5 seconds...");
                                        handler.postDelayed(delayedRestore, 5000);
                                        notification.setContentTitle("Service is running, waiting 5 seconds...");
                                        mNotificationManager.notify(1, notification.build());
                                    }
                                } else {
                                    if (dpiCircumvention) {
                                        Script.startTPWS(ipv4Addr, ipv6Prefix, getFilesDir().getPath());
                                    }
                                    notification.setContentTitle("Service is running, Connected");
                                    mNotificationManager.notify(1, notification.build());
                                }
                            } else {
                                // Brings tether back up on connection change
                                Script.unforwardInterface(ipv4Prefix + currentInterface, currentInterface);
                                Script.forwardInterface(ipv4Prefix + currentInterface, currentInterface);
                            }
                            usbReconnect = false;
                            needsReset = false;
                        } else {
                            Log.i("usbtether", "No action required");
                            notification.setContentTitle("Service is running, Connected");
                            mNotificationManager.notify(1, notification.build());
                        }
                    }
                } else {
                    Log.w("usbtether", "Tether failed, invalid interface");
                    needsReset = true;
                }
            } else {
                offlineCounter = offlineCounter + 1;
                Log.w("usbtether", "Failed, tether interface unavailable");
                if (!handler.hasCallbacks(delayedRestore)) {
                    Log.i("usbtether", "Creating callback to restore tether in 5 seconds...");
                    handler.postDelayed(delayedRestore, 5000);
                    notification.setContentTitle("Service is running, waiting 5 seconds...");
                    mNotificationManager.notify(1, notification.build());
                }
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

            NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

            Log.i("usbtether", "Recieved USB_STATE broadcast");
            if (intent.getExtras().getBoolean("connected")) {
                Log.i("usbtether", "USB Connected");
                if (intent.getExtras().getBoolean("configured")) {
                    Log.i("usbtether", "USB Configured");
                    if (!handler.hasCallbacks(delayedRestore)) {
                        if (natApplied) {
                            // Fix for Google One VPN
                            needsReset = true;
                        }
                        if (natApplied && !usbReconnect) {
                            // Restore right away if there was no disconnect event
                            restoreTether();
                        } else {
                            Log.i("usbtether", "Creating callback to restore tether in 5 seconds...");
                            handler.postDelayed(delayedRestore, 5000);
                            notification.setContentTitle("Service is running, waiting 5 seconds...");
                            mNotificationManager.notify(1, notification.build());
                        }
                    } else {
                        Log.i("usbtether", "Tether restore callback already scheduled");
                    }
                } else {
                    Log.i("usbtether", "USB Not Configured");
                }
            } else {
                Log.i("usbtether", "USB Disconnected");
                if (natApplied) {
                    needsReset = true;
                    usbReconnect = true;
                }
                if (handler.hasCallbacks(delayedRestore)) {
                    Log.i("usbtether", "USB Disconnected, removing tether restore callback");
                    handler.removeCallbacks(delayedRestore);
                }
                notification.setContentTitle("Service is running, USB disconnected");
                mNotificationManager.notify(1, notification.build());
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
            if (!handler.hasCallbacks(delayedRestore)) {
                restoreTether();
            } else {
                Log.i("usbtether", "Skipping event due to pending callback");
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

        boolean hasTTL = Script.hasTTL();
        boolean hasTable = Script.hasTable();
        boolean hasSNAT = Script.hasSNAT();
        boolean hasMASQUERADE = Script.hasMASQUERADE();
        if (!hasTTL || !hasTable || !hasSNAT || !hasMASQUERADE) {
            SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
            SharedPreferences.Editor edit = sharedPref.edit();
            if (!hasTTL) {
                edit.putBoolean("fixTTL", false);
            }
            if (!hasTable || !hasSNAT) {
                edit.putBoolean("ipv6SNAT", false);
            }
            if (!hasTable || !hasMASQUERADE) {
                edit.putBoolean("ipv6Masquerading", false);
            }
            edit.apply();
        }

        String[] vars = Script.gadgetVars();

        gadgetPath = vars[0];
        configPath = vars[1];
        functionPath = vars[2];

        Log.i("usbtether", "gadgetPath: " + gadgetPath);
        Log.i("usbtether", "configPath: " + configPath);
        Log.i("usbtether", "functionPath: " + functionPath);

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

        Script.configureRNDIS(gadgetPath, configPath, functionPath);

        registerReceiver(USBReceiver, new IntentFilter("android.hardware.usb.action.USB_STATE"));
        registerReceiver(ConnectionReceiver, new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"));

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
        try {
            unregisterReceiver(ConnectionReceiver);
        } catch (IllegalArgumentException ignored) {}

        if (handler.hasCallbacks(delayedRestore)) {
            handler.removeCallbacks(delayedRestore);
        }

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String lastNetwork = sharedPref.getString("lastNetwork", "");
        String lastIPv6 = sharedPref.getString("lastIPv6", "");
        Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
        Boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
        Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        boolean dpiCircumvention = sharedPref.getBoolean("dpiCircumvention", false);
        boolean dmz = sharedPref.getBoolean("dmz", false);
        Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
        String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
        String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
        boolean isXLAT = sharedPref.getBoolean("isXLAT", false);
        String clientBandwidth = sharedPref.getString("clientBandwidth", "0");
        String ipv4Prefix = "";
        if (isXLAT) {
            ipv4Prefix = "v4-";
        }

        if (!lastNetwork.equals("")) {
            Script.unconfigureTether(ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, clientBandwidth, dpiCircumvention, dmz);
            Script.unconfigureRNDIS(configPath);
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
