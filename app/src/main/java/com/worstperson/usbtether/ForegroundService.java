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
import android.os.BatteryManager;
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
    private Boolean tetherActive = false;
    private boolean natApplied = false;
    private boolean needsReset = false;
    private boolean usbReconnect = false;

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
        int count = 1;
        while (count < 10) {
            Log.i("usbtether", "Waiting for " + tetherInterface + "..." + count);
            try {
                // fixme - this ping test does not belong here
                if (NetworkInterface.getByName(tetherInterface) != null && Script.testConnection(tetherInterface)) {
                    return true;
                }
            } catch (SocketException e) {
                e.printStackTrace();
            }
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

    private void startVPN(int autostartVPN, String wireguardProfile) {
        if (autostartVPN == 1 || autostartVPN == 2) {
            Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_UP");
            i.setPackage("com.wireguard.android");
            i.putExtra("tunnel", wireguardProfile);
            sendBroadcast(i);
            if (autostartVPN == 1) {
                waitInterface("tun0");
            } else {
                // This might not get triggered, idk
                waitInterface(wireguardProfile);
            }
        } else {
            NetworkInterface checkInterface = null;
            try {
                checkInterface = NetworkInterface.getByName("tun0");
            } catch (SocketException e) {
                e.printStackTrace();
            }
            if (checkInterface == null) {
                if (autostartVPN == 3) {
                    Script.startGoogleOneVPN();
                } else if (autostartVPN == 4) {
                    Script.startCloudflare1111Warp();
                }
                waitInterface("tun0");
            }
        }
    }

    private boolean checkUSB(Context context) {
        Intent batteryStatus = context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (batteryStatus != null && batteryStatus.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) == BatteryManager.BATTERY_PLUGGED_USB) {
            Log.w("USBTether", "Connected to tetherable device");
            return true;
        } else {
            Log.w("USBTether", "Not connected to tetherable device");
            return false;
        }
    }

    // FIXME - BUG - disable IPv6 when IPv6 is unavailable
    // FIXME - FEATURE - disable IPv6 when MTU is lower than spec allows
    //  (AT&T Cricket has broken IPv6, MTU is set to the minimum for IPv4, don't use it)
    private void restoreTether(boolean isConnected) {
        if (!isConnected) {
            isConnected = checkUSB(this);
        }
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
            String ipv4Prefix = "";
            if (isXLAT) {
                ipv4Prefix = "v4-";
            }

            // Check Connection events and recover the tether operation
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
            if (tetherActive && natApplied) {
                Log.w("usbtether", "Tether is active...");
                if (currentInterface != null && !currentInterface.equals("") && !currentInterface.equals("Auto")) {
                    if (tetherInterface.equals("Auto") && !currentInterface.equals(lastNetwork)) {
                        Log.w("usbtether", "Network changed, reconnecting...");
                        // Works for changing interfaces for now
                        // Need to clean this up FIXME
                        Log.w("usbtether", "Resetting interface...");
                        Script.resetInterface(true, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                        natApplied = false;
                        tetherActive = true;
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
                            natApplied = Script.configureNAT(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Masquerading, ipv6SNAT, ipv6Prefix, ipv6Addr, fixTTL, dnsmasq, getFilesDir().getPath());
                            if (!Script.configureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT)) {
                                Log.w("usbtether", "Resetting interface...");
                                Script.resetInterface(false, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                                natApplied = false;
                                tetherActive = true;
                                Script.configureRNDIS();
                            }
                        }
                    } else {
                        // Restart VPN if needed
                        if (autostartVPN > 0 && !isUp) {
                            Log.w("usbtether", "VPN down, restarting...");
                            startVPN(autostartVPN, wireguardProfile);
                            needsReset = true;
                        }
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

                                if (usbReconnect && !Script.configureRoutes(ipv4Prefix + tetherInterface, tetherInterface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT)) {
                                    Log.w("usbtether", "Resetting interface...");
                                    Script.resetInterface(false, ipv4Prefix + currentInterface, currentInterface, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                                    natApplied = false;
                                    tetherActive = true;
                                    Script.configureRNDIS();
                                } else {
                                    // Brings tether back up on connection change
                                    Script.forwardInterface(ipv4Prefix + currentInterface, currentInterface);
                                }
                                usbReconnect = false;
                                needsReset = false;
                            }
                        } else {
                            Log.w("usbtether", "Interface down, setting reset flag...");
                            needsReset = true;
                        }
                    }
                }
            } else if (!tetherActive) {
                Log.i("usbtether", "Checking if tethering should be started...");
                // Tethering not configured, start configuring
                if (isUp) {
                    Log.i("usbtether", "Starting tether...");
                    natApplied = false;
                    tetherActive = true;

                    String ipv6Addr = setupSNAT(currentInterface, ipv6SNAT);
                    SharedPreferences.Editor edit = sharedPref.edit();
                    edit.putString("lastNetwork", currentInterface);
                    edit.putString("lastIPv6", ipv6Addr);
                    edit.putBoolean("isXLAT", false); // idk, seems lazy
                    ipv4Prefix = "";

                    if (tetherInterface.equals("Auto")) {
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
                    }

                    edit.apply();
                    tetherInterface = currentInterface;
                    natApplied = Script.configureNAT(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Masquerading, ipv6SNAT, ipv6Prefix, ipv6Addr, fixTTL, dnsmasq, getFilesDir().getPath());
                    if (natApplied && !Script.configureRoutes(ipv4Prefix + tetherInterface, tetherInterface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT)) {
                        Log.w("usbtether", "Resetting interface...");
                        Script.resetInterface(false, ipv4Prefix + currentInterface, currentInterface, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                        natApplied = false;
                        tetherActive = true;
                        Script.configureRNDIS();
                    }

                } else {
                    Log.i("usbtether", tetherInterface + " not available");
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
            Log.i("usbtether", "Recieved USB_STATE broadcast");
            if (intent.getExtras().getBoolean("connected")) {
                Log.i("usbtether", "USB Connected");
                if (intent.getExtras().getBoolean("configured")) {
                    Log.i("usbtether", "USB Configured");
                    if (tetherActive && natApplied) {
                        // Fix for Google One VPN
                        needsReset = true;
                    }
                    restoreTether(true);
                } else {
                    Log.i("usbtether", "USB Not Configured");
                }
            } else {
                Log.i("usbtether", "USB Disconnected");
                if (tetherActive && natApplied) {
                    needsReset = true;
                    usbReconnect = true;
                }
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
            restoreTether(false);
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
        String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
        Boolean isXLAT = sharedPref.getBoolean("isXLAT", false);
        String ipv4Prefix = "";
        if (isXLAT) {
            ipv4Prefix = "v4-";
        }

        if (!lastNetwork.equals("")) {
            Script.resetInterface(false, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
        }

        natApplied = false;
        tetherActive = false;
        isStarted = false;

        Toast.makeText(this, "Service destroyed by user.", Toast.LENGTH_LONG).show();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
