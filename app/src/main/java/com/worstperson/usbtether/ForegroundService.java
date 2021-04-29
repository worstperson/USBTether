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
    public Boolean tetherActive = false;

    private void runScript() {
        unregisterReceiver(USBReceiver); //Required for < android.os.Build.VERSION_CODES.P

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String tetherInterface = sharedPref.getString("tetherInterface", "");
        Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
        Boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
        Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", false);

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

        if (tetherInterface != null && !tetherInterface.equals("") && !tetherInterface.equals("Auto")) {
            SharedPreferences.Editor edit = sharedPref.edit();
            edit.putString("lastNetwork", tetherInterface);
            edit.apply();

            String ipv6Addr = "";
            try {
                NetworkInterface netint = NetworkInterface.getByName(tetherInterface);
                if (netint != null) {
                    for (InetAddress inetAddress : Collections.list(netint.getInetAddresses())) {
                        if (inetAddress instanceof Inet6Address) {
                            ipv6Addr = inetAddress.getHostAddress();
                        }
                    }
                }
                edit.putString("lastIPv6", ipv6Addr);
                edit.apply();
            } catch (SocketException e) {
                e.printStackTrace();
            }

            try {
                Script.runCommands(tetherInterface, ipv6Masquerading, ipv6SNAT, fixTTL, ipv6Addr, dnsmasq, getFilesDir().getPath());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        IntentFilter filter = new IntentFilter();
        filter.addAction("android.hardware.usb.action.USB_STATE");
        registerReceiver(USBReceiver, filter);
    }

    private final BroadcastReceiver USBReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            // Some devices go into Discharging state rather then Not Charging
            // when charge control apps are used, so we can't use BatteryManager
            if (intent.getExtras().getBoolean("connected")) {
                Log.i("usbtether", "USB Connected");
                if (intent.getExtras().getBoolean("configured")) {
                    if (!tetherActive) {
                        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
                        boolean startWireGuard = sharedPref.getBoolean("startWireGuard", false);
                        String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
                        if (startWireGuard) {
                            Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_UP");
                            i.setPackage("com.wireguard.android");
                            i.putExtra("tunnel", wireguardProfile);
                            sendBroadcast(i);
                        }
                        runScript();
                        tetherActive = true;
                    } else {
                        Log.i("usbtether", "Tethering already active");
                    }
                } else {
                    Log.i("usbtether", "Interface not yet configured");
                }
            } else {
                Log.i("usbtether", "USB Disconnected");
                SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
                String lastNetwork = sharedPref.getString("lastNetwork", "");
                String lastIPv6 = sharedPref.getString("lastIPv6", "");
                Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
                Boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
                Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
                Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", false);

                if (!lastNetwork.equals("")) {
                    Script.resetInterface(lastNetwork, ipv6Masquerading, ipv6SNAT, fixTTL, lastIPv6, dnsmasq);
                }
                tetherActive = false;

                boolean startWireGuard = sharedPref.getBoolean("startWireGuard", false);
                String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
                if (startWireGuard) {
                    Intent i = new Intent("com.wireguard.android.action.SET_TUNNEL_DOWN");
                    i.setPackage("com.wireguard.android");
                    i.putExtra("tunnel", wireguardProfile);
                    sendBroadcast(i);
                }
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

        IntentFilter filter = new IntentFilter();
        filter.addAction("android.hardware.usb.action.USB_STATE");
        registerReceiver(USBReceiver, filter);

        return Service.START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
        unregisterReceiver(USBReceiver);

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String lastNetwork = sharedPref.getString("lastNetwork", "");
        String lastIPv6 = sharedPref.getString("lastIPv6", "");
        Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
        Boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
        Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", false);

        if (!lastNetwork.equals("")) {
            Script.resetInterface(lastNetwork, ipv6Masquerading, ipv6SNAT, fixTTL, lastIPv6, dnsmasq);
        }
        tetherActive = false;
        isStarted = false;

        Toast.makeText(this, "Service destroyed by user.", Toast.LENGTH_LONG).show();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
