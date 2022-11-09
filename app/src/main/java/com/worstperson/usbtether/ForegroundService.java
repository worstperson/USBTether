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
import android.net.NetworkCapabilities;
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
            if (isStarted) {
                restoreTether();
            }
        }
    };

    final Handler handler2 = new Handler(Looper.getMainLooper());
    Runnable watchdog = new Runnable() {
        @Override
        public void run() {
            SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
            String lastNetwork = sharedPref.getString("lastNetwork", "");
            String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
            boolean dpiCircumvention = sharedPref.getBoolean("dpiCircumvention", false);
            Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
            String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
            String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
            int autostartVPN = sharedPref.getInt("autostartVPN", 0);
            String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
            boolean cellularWatchdog = sharedPref.getBoolean("cellularWatchdog", false);

            if (isStarted && Script.isUSBConfigured()) {
                Log.i("usbtether", "Checking connection availability...");
                String iface;
                if (cellularWatchdog && (iface = isCellularActive()) != null && !(Script.testConnection(iface) || Script.testConnection6(iface))) {
                    Log.w("usbtether", "Cellular connection is DOWN, attempting recovery");
                    Script.recoverDataConnection();
                    needsReset = true;
                } else if (autostartVPN > 0 && !Script.testConnection(lastNetwork)) {
                    Log.w("usbtether", "VPN connection is DOWN, attempting recovery");
                    startVPN(autostartVPN, wireguardProfile, true);
                    needsReset = true;
                }
                if (needsReset) {
                    Log.w("usbtether", "Scheduling tether restore");
                    if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                        Log.i("usbtether", "Creating callback to restore tether in 5 seconds...");
                        handler.postDelayed(delayedRestore, 5000);
                        notification.setContentTitle("Service is running, waiting 5 seconds...");
                        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                        mNotificationManager.notify(1, notification.build());
                    }
                }
                Log.i("usbtether", "Checking processes...");
                Script.checkProcesses(ipv4Addr, ipv6TYPE, ipv6Prefix, dnsmasq, getFilesDir().getPath(), dpiCircumvention);
                if (!HandlerCompat.hasCallbacks(handler2, watchdog)) {
                    Log.i("usbtether", "Running watchdog in 60 seconds...");
                    handler2.postDelayed(watchdog, 60000);
                }
            }
        }
    };

    private String isCellularActive() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        Network[] networks = cm.getAllNetworks();
        String mobileNetwork = null;
        for (Network network : networks) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_DUN)) {
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    mobileNetwork = cm.getLinkProperties(network).getInterfaceName();
                } else if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) {
                    return null;
                }
            }
        }
        return mobileNetwork;
    }

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

    // FIXME - BUG - disable IPv6 when IPv6 is unavailable
    // FIXME - FEATURE - disable IPv6 when MTU is lower than spec allows
    private void restoreTether() {

        NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        if (Script.isUSBConfigured()) {

            SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
            String tetherInterface = sharedPref.getString("tetherInterface", "Auto");
            //if (tetherInterface.equals("TPROXY")) { //TODO - ADD SUPPORT FOR THIS
            //    tetherInterface = "Auto";
            //}
            String lastNetwork = sharedPref.getString("lastNetwork", "");
            String lastIPv6 = sharedPref.getString("lastIPv6", "");
            String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
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
            boolean cellularWatchdog = sharedPref.getBoolean("cellularWatchdog", false);
            String ipv4Prefix = "";
            if (isXLAT) {
                ipv4Prefix = "v4-";
            }

            if (autostartVPN > 0 || cellularWatchdog || dnsmasq || dpiCircumvention || ipv6TYPE.equals("TPROXY")) {
                if (!HandlerCompat.hasCallbacks(handler2, watchdog)) {
                    Log.i("usbtether", "Running watchdog in 60 seconds...");
                    handler2.postDelayed(watchdog, 60000);
                }
            }

            String currentInterface = pickInterface(tetherInterface);
            NetworkInterface checkInterface;
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
            // TPROXY skips IPv6 test since we are not controlling the interface it uses
            if (isUp && (tetherInterface.equals("Auto") || (Script.testConnection(currentInterface) && ((!ipv6TYPE.equals("MASQUERADE") && !ipv6TYPE.equals("SNAT")) || Script.testConnection6(currentInterface))))) {
                offlineCounter = 0;
                if (currentInterface != null && !currentInterface.equals("") && !currentInterface.equals("Auto")) {
                    if (!natApplied || (tetherInterface.equals("Auto") && !currentInterface.equals(lastNetwork))) {
                        // Configure Tether
                        if (!natApplied) {
                            Log.i("usbtether", "Starting tether operation...");
                        } else {
                            Log.i("usbtether", "Network changed, resetting interface...");
                            Script.unconfigureTether(ipv4Prefix + lastNetwork, lastNetwork, ipv6TYPE, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz);
                            natApplied = false;
                        }
                        String ipv6Addr = setupSNAT(currentInterface, ipv6TYPE.equals("SNAT"));
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
                        if (!(natApplied = Script.configureTether(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6TYPE, ipv6Prefix, ipv6Addr, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz, configPath, functionPath))
                                || !Script.configureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix, ipv6TYPE)) {
                            if (natApplied) {
                                Log.w("usbtether", "Failed configuring tether, resetting interface...");
                                Script.unconfigureTether(ipv4Prefix + lastNetwork, lastNetwork, ipv6TYPE, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz);
                                natApplied = false;
                            }
                            Script.unconfigureRNDIS(gadgetPath, configPath, getFilesDir().getPath());
                            Script.configureRNDIS(gadgetPath, configPath, functionPath, getFilesDir().getPath());
                            if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                                Log.i("usbtether", "Creating callback to retry tether in 5 seconds...");
                                handler.postDelayed(delayedRestore, 5000);
                                notification.setContentTitle("Service is running, waiting 5 seconds...");
                                mNotificationManager.notify(1, notification.build());
                            }
                        } else {
                            // Start bound services
                            if (dpiCircumvention) {
                                Script.startTPWS(ipv4Addr, ipv6Prefix, getFilesDir().getPath());
                            }
                            if (ipv6TYPE.equals("TPROXY")) {
                                // Add TPROXY exception
                                String tmp = getPrefix(currentInterface, ipv6Prefix);
                                if (tmp != null) {
                                    Log.i("TetherTPROXY", tmp);
                                    Script.setTPROXYRoute(tmp);
                                }
                            }
                            notification.setContentTitle("Service is running, Connected");
                            mNotificationManager.notify(1, notification.build());
                        }
                    } else {
                        // Restore Tether
                        if (needsReset) {
                            Log.i("usbtether", "Restoring tether...");
                            // Update SNAT if needed
                            String newAddr = setupSNAT(currentInterface, ipv6TYPE.equals("SNAT"));
                            if (!newAddr.equals("") && !newAddr.equals(lastIPv6)) {
                                Script.refreshSNAT(currentInterface, lastIPv6, newAddr);
                                SharedPreferences.Editor edit = sharedPref.edit();
                                edit.putString("lastIPv6", newAddr);
                                edit.apply();
                            }
                            if (ipv6TYPE.equals("TPROXY")) {
                                // Add TPROXY exception
                                String tmp = getPrefix(currentInterface, ipv6Prefix);
                                if (tmp != null) {
                                    Log.i("TetherTPROXY", tmp);
                                    Script.setTPROXYRoute(tmp);
                                }
                            }
                            if (usbReconnect) {
                                Script.unconfigureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix);
                                if (!Script.configureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix, ipv6TYPE)) {
                                    Log.w("usbtether", "Failed to restore after USB reset, resetting interface...");
                                    Script.unconfigureTether(ipv4Prefix + currentInterface, currentInterface, ipv6TYPE, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz);
                                    Script.unconfigureRNDIS(gadgetPath, configPath, getFilesDir().getPath());
                                    Script.configureRNDIS(gadgetPath, configPath, functionPath, getFilesDir().getPath());
                                    natApplied = false;
                                    if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
                                        Log.i("usbtether", "Creating callback to retry tether in 5 seconds...");
                                        handler.postDelayed(delayedRestore, 5000);
                                        notification.setContentTitle("Service is running, waiting 5 seconds...");
                                        mNotificationManager.notify(1, notification.build());
                                    }
                                } else {
                                    // Start bound services
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
                                notification.setContentTitle("Service is running, Connected");
                                mNotificationManager.notify(1, notification.build());
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
                    notification.setContentTitle("Service is running, invalid tether interface");
                    mNotificationManager.notify(1, notification.build());
                }
            } else {
                offlineCounter = offlineCounter + 1;
                Log.w("usbtether", "Failed, tether interface unavailable");
                needsReset = true;
                if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
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
                    if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
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
                // Stop bound services
                Script.stopTPWS(getFilesDir().getPath());
                if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
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
            if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
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
        boolean hasTPROXY = Script.hasTPROXY();
        boolean hasTable = Script.hasTable();
        boolean hasSNAT = Script.hasSNAT();
        boolean hasMASQUERADE = Script.hasMASQUERADE();
        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
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

        Script.configureRNDIS(gadgetPath, configPath, functionPath, getFilesDir().getPath());

        registerReceiver(USBReceiver, new IntentFilter("android.hardware.usb.action.USB_STATE"));
        registerReceiver(ConnectionReceiver, new IntentFilter("android.net.conn.CONNECTIVITY_CHANGE"));

        if (Script.isUSBConfigured()) {
            NotificationManager mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
            Log.i("usbtether", "Creating callback to restore tether in 5 seconds...");
            handler.postDelayed(delayedRestore, 5000);
            notification.setContentTitle("Service is running, waiting 5 seconds...");
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
        try {
            unregisterReceiver(ConnectionReceiver);
        } catch (IllegalArgumentException ignored) {}

        if (!HandlerCompat.hasCallbacks(handler, delayedRestore)) {
            handler.removeCallbacks(delayedRestore);
        }
        if (!HandlerCompat.hasCallbacks(handler2, watchdog)) {
            handler2.removeCallbacks(watchdog);
        }


        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String lastNetwork = sharedPref.getString("lastNetwork", "");
        String lastIPv6 = sharedPref.getString("lastIPv6", "");
        String ipv6TYPE = sharedPref.getString("ipv6TYPE", "None");
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
            // Stop bound services
            Script.unconfigureTether(ipv4Prefix + lastNetwork, lastNetwork, ipv6TYPE, ipv4Addr, ipv6Prefix, lastIPv6, fixTTL, dnsmasq, getFilesDir().getPath(), clientBandwidth, dpiCircumvention, dmz);
            Script.unconfigureRNDIS(gadgetPath, configPath, getFilesDir().getPath());
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
