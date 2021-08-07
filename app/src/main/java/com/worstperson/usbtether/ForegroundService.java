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

import java.io.IOException;
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
    private boolean blockReciever = false;
    private boolean needsReset = false;

    private String pickInterface(String tetherInterface) {
        if (tetherInterface.equals("Auto")) {
            ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (connectivityManager != null) {
                Network activeNetwork = connectivityManager.getActiveNetwork();
                if (activeNetwork != null) {
                    LinkProperties linkProperties = connectivityManager.getLinkProperties(activeNetwork);
                    if (linkProperties != null) {
                        tetherInterface = linkProperties.getInterfaceName();
                        if (tetherInterface != null) {
                            try { //Check for separate CLAT interface
                                NetworkInterface netint = NetworkInterface.getByName("v4-" + tetherInterface);
                                if (netint != null) {
                                    for (InetAddress inetAddress : Collections.list(netint.getInetAddresses())) {
                                        if (inetAddress instanceof Inet4Address) {
                                            tetherInterface = netint.getName();
                                        }
                                    }
                                }
                            } catch (SocketException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                }
            }
        }
        return tetherInterface;
    }

    private boolean waitInterface(String tetherInterface) {
        //We need to wait for the interface to become configured
        int count = 1;
        while (count < 10) { // this is too long, but sometimes required
            Log.i("usbtether", "Waiting for " + tetherInterface + "..." + count);
            try {
                if (NetworkInterface.getByName(tetherInterface) != null) {
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
        // FIXME wait for address?
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
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

    private final BroadcastReceiver USBReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i("usbtether", "Recieved USB_STATE broadcast");
            SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
            String tetherInterface = sharedPref.getString("tetherInterface", "Auto");
            String lastNetwork = sharedPref.getString("lastNetwork", "");
            String lastIPv6 = sharedPref.getString("lastIPv6", "");
            Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
            Boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
            Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
            Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", false);
            String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";

            // Some devices go into Discharging state rather then Not Charging
            // when charge control apps are used, so we can't use BatteryManager
            // This actually works way better anyway, even though it's undocumented
            if (intent.getExtras().getBoolean("connected")) {
                Log.i("usbtether", "USB Connected");
                if (intent.getExtras().getBoolean("configured")) {
                    if (!tetherActive) {
                        blockReciever = true;
                        Log.i("usbtether", "Configuring interface...");
                        int autostartVPN = sharedPref.getInt("autostartVPN", 0);
                        if (autostartVPN > 0) {
                            if (autostartVPN == 1 || autostartVPN == 2) {
                                String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
                                Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_UP");
                                i.setPackage("com.wireguard.android");
                                i.putExtra("tunnel", wireguardProfile);
                                sendBroadcast(i);
                                if (autostartVPN == 1) {
                                    waitInterface("tun0");
                                } else {
                                    waitInterface(wireguardProfile);
                                }
                            } else if (autostartVPN == 3) {
                                Script.startGoogleOneVPN();
                                waitInterface("tun0");
                            } else if (autostartVPN == 4) {
                                Script.startCloudflare1111Warp();
                                waitInterface("tun0");
                            }
                        }
                        tetherInterface = pickInterface(tetherInterface);
                        NetworkInterface currentInterface = null;
                        try {
                            currentInterface = NetworkInterface.getByName(tetherInterface);
                        } catch (SocketException e) {
                            e.printStackTrace();
                        }
                        if (currentInterface != null) {
                            tetherActive = true;
                            Script.configureRNDIS();
                        } else {
                            blockReciever = false;
                        }
                    } else {
                        if (!natApplied) {
                            tetherInterface = pickInterface(tetherInterface);
                            if (tetherInterface != null && !tetherInterface.equals("") && !tetherInterface.equals("Auto") && waitInterface(tetherInterface)) {
                                String ipv6Addr = setupSNAT(tetherInterface, ipv6SNAT);
                                lastNetwork = tetherInterface;
                                lastIPv6 = ipv6Addr;
                                SharedPreferences.Editor edit = sharedPref.edit();
                                edit.putString("lastNetwork", tetherInterface);
                                edit.putString("lastIPv6", ipv6Addr);
                                edit.apply();
                                natApplied = Script.configureNAT(tetherInterface, ipv6Masquerading, ipv6SNAT, ipv6Prefix, ipv6Addr, fixTTL, dnsmasq, getFilesDir().getPath());
                            }
                        }
                        if (natApplied) {
                            // Google One VPN is trash and reconnects all the time, just restore it for now
                            // todo: find the minimal operation to bring the connection back up
                            boolean result = false;
                            result = Script.configureRoutes(tetherInterface, ipv6Prefix);
                            if (!result) {
                                Log.w("usbtether", "Resetting interface...");
                                Script.resetInterface(false, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                                natApplied = false;
                                tetherActive = false;
                            }
                            blockReciever = false;
                        }
                    }
                } else {
                    Log.i("usbtether", "Interface not yet ready");
                }
            } else {
                Log.i("usbtether", "USB Disconnected");
                Script.resetInterface(false, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                natApplied = false;
                tetherActive = false;

                int autostartVPN = sharedPref.getInt("autostartVPN", 0);
                if (autostartVPN == 1 || autostartVPN == 2) {
                    String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
                    Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_DOWN");
                    i.setPackage("com.wireguard.android");
                    i.putExtra("tunnel", wireguardProfile);
                    sendBroadcast(i);
                } else if (autostartVPN == 3) {
                    Script.stopGoogleOneVPN();
                } else if (autostartVPN == 4) {
                    Script.stopCloudflare1111Warp();
                }
            }
        }
    };

    private boolean isOnline() {
        Runtime runtime = Runtime.getRuntime();
        try {
            Process ipProcess = runtime.exec("ping -c 1 8.8.8.8");
            if (ipProcess.waitFor() == 0) {
                Log.i("usbtether", "NETWORK ONLINE");
                return true;
            }
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        Log.w("usbtether", "NETWORK OFFLINE");
        return false;
    }

    // Try to detect VPN disconnects and restart it if possible
    private final BroadcastReceiver ConnectionReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.i("usbtether", "Recieved CONNECTIVITY_CHANGE broadcast");
            SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
            String tetherInterface = sharedPref.getString("tetherInterface", "Auto");
            String lastNetwork = sharedPref.getString("lastNetwork", "");
            String lastIPv6 = sharedPref.getString("lastIPv6", "");
            Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
            Boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
            Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
            Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", false);
            String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
            int autostartVPN = sharedPref.getInt("autostartVPN", 0);
            NetworkInterface currentInterface = null;

            // Check Connection events and recover the tether operation
            if (!blockReciever) {
                // TODO: this can return false switching from VPN -> WiFi

                if (isOnline()) {
                    if (tetherActive && natApplied) {
                        if (!Script.testConnection(lastNetwork)) {
                            Log.w("usbtether", "Tethered interface offline");
                            needsReset = true;
                        }
                        if (ipv6SNAT && !setupSNAT(lastNetwork, ipv6SNAT).equals(lastIPv6)) {
                            Log.w("usbtether", "IPv6 address changed");
                            needsReset = true;
                        }
                        if (tetherInterface.equals("Auto") && !pickInterface(tetherInterface).equals(lastNetwork)) {
                            Log.w("usbtether", "Tether interface changed");
                            needsReset = true;
                        }
                        if (needsReset) {
                            needsReset = false;
                            // Restart VPN if needed
                            if (autostartVPN > 0) {
                                blockReciever = true;
                                if (autostartVPN == 1 || autostartVPN == 2) {
                                    String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
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
                                    try {
                                        currentInterface = NetworkInterface.getByName("tun0");
                                    } catch (SocketException e) {
                                        e.printStackTrace();
                                    }
                                    if (currentInterface == null) {
                                        if (autostartVPN == 3) {
                                            Script.startGoogleOneVPN();
                                        } else if (autostartVPN == 4) {
                                            Script.startCloudflare1111Warp();
                                        }
                                        waitInterface("tun0");
                                    }
                                }
                            }
                            // Check if the network changed and restore
                            tetherInterface = pickInterface(tetherInterface);
                            if (tetherInterface != null && !tetherInterface.equals("") && !tetherInterface.equals("Auto") && tetherInterface.equals(lastNetwork)) {
                                try {
                                    currentInterface = NetworkInterface.getByName(tetherInterface);
                                } catch (SocketException e) {
                                    e.printStackTrace();
                                }
                                if (currentInterface != null) {
                                    // Update SNAT if needed
                                    String newAddr = setupSNAT(tetherInterface, ipv6SNAT);
                                    if (!newAddr.equals("") && !newAddr.equals(lastIPv6)) {
                                        Script.refreshSNAT(tetherInterface, lastIPv6, newAddr);
                                        SharedPreferences.Editor edit = sharedPref.edit();
                                        edit.putString("lastIPv6", newAddr);
                                        edit.apply();
                                    }
                                    // Brings tether back up on connection change
                                    Script.forwardInterface(tetherInterface);
                                    blockReciever = false;
                                } else {
                                    Log.w("usbtether", "Interface missing, waiting...");
                                    needsReset = true;
                                    blockReciever = false;
                                }
                            } else {
                                // Works for changing interfaces for now
                                Log.w("usbtether", "Resetting interface...");
                                Script.resetInterface(true, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                                natApplied = false;
                                tetherActive = true;
                                tetherInterface = pickInterface(tetherInterface);
                                if (tetherInterface != null && !tetherInterface.equals("") && !tetherInterface.equals("Auto") && waitInterface(tetherInterface)) {
                                    String ipv6Addr = setupSNAT(tetherInterface, ipv6SNAT);
                                    SharedPreferences.Editor edit = sharedPref.edit();
                                    edit.putString("lastNetwork", tetherInterface);
                                    edit.putString("lastIPv6", ipv6Addr);
                                    edit.apply();
                                    natApplied = Script.configureNAT(tetherInterface, ipv6Masquerading, ipv6SNAT, ipv6Prefix, ipv6Addr, fixTTL, dnsmasq, getFilesDir().getPath());
                                    boolean result = false;
                                    result = Script.configureRoutes(tetherInterface, ipv6Prefix);
                                    if (!result) {
                                        Log.w("usbtether", "Resetting interface...");
                                        Script.resetInterface(false, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                                        natApplied = false;
                                        tetherActive = false;
                                    }
                                }
                            }
                        }
                    } else if (!tetherActive) {
                        Log.i("usbtether", "Checking if tethering should be started...");
                        // Tethering not configured, start configuring
                        tetherInterface = pickInterface(tetherInterface);
                        try {
                            currentInterface = NetworkInterface.getByName(tetherInterface);
                        } catch (SocketException e) {
                            e.printStackTrace();
                        }
                        if (currentInterface != null) {
                            Log.i("usbtether", "Starting tether...");
                            blockReciever = true;
                            natApplied = false;
                            tetherActive = true;
                            Script.configureRNDIS();
                        } else {
                            Log.i("usbtether", tetherInterface + " not available");
                        }
                    }
                } else {
                    Log.w("usbtether", "Device is offline");
                    needsReset = true;
                }
            } else {
                Log.w("usbtether", "Broadcast blocked...");
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
        Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", false);
        String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";

        if (!lastNetwork.equals("")) {
            Script.resetInterface(false, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
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
