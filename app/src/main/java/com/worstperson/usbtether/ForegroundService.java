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
import android.util.Pair;
import android.widget.Toast;
import androidx.core.app.NotificationCompat;

import android.os.PowerManager;
import android.os.PowerManager.WakeLock;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

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

    // todo: try not resetting, don't disable unless the service is
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
            Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
            String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
            String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
            Boolean isXLAT = sharedPref.getBoolean("isXLAT", false);
            String ipv4Prefix = "";
            if (isXLAT) {
                ipv4Prefix = "v4-";
            }

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
                            String currentInterface = pickInterface(tetherInterface);
                            if (currentInterface != null && !currentInterface.equals("") && !currentInterface.equals("Auto") && waitInterface(currentInterface)) {
                                String ipv6Addr = setupSNAT(currentInterface, ipv6SNAT);
                                lastNetwork = currentInterface;
                                lastIPv6 = ipv6Addr;
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
                            }
                        }
                        if (natApplied) {
                            // Google One VPN is trash and reconnects all the time, just restore it for now
                            // todo: find the minimal operation to bring the connection back up
                            boolean result = false;
                            result = Script.configureRoutes(ipv4Prefix + tetherInterface, tetherInterface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT);
                            if (!result) {
                                Log.w("usbtether", "Resetting interface...");
                                Script.resetInterface(false, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                                blockReciever = true;
                                natApplied = false;
                                tetherActive = true;
                                Script.configureRNDIS();
                            } else {
                                blockReciever = false;
                            }
                        }
                    }
                } else {
                    Log.i("usbtether", "Interface not yet ready");
                }
            } else {
                Log.i("usbtether", "USB Disconnected");
                Script.resetInterface(false, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                natApplied = false;
                tetherActive = false;

                // This code doesn't belong here. Don't drop the tunnel unless it actually died.
                /*int autostartVPN = sharedPref.getInt("autostartVPN", 0);
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
                }*/
            }
        }
    };

    // This does not broadcast on mobile changes (ex. 3g->lte)
    // This does not broadcast on WireGuard's kernel module interface
    // TODO track the state of interfaces to figure out why we were invoked
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
            Boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
            String ipv6Prefix = sharedPref.getBoolean("ipv6Default", false) ? "2001:db8::" : "fd00::";
            int autostartVPN = sharedPref.getInt("autostartVPN", 0);
            String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
            Boolean isXLAT = sharedPref.getBoolean("isXLAT", false);
            String ipv4Prefix = "";
            if (isXLAT) {
                ipv4Prefix = "v4-";
            }
            NetworkInterface checkInterface = null;

            // Build interface list
            /*Enumeration<NetworkInterface> nets;
            try {
                ArrayList<Pair<String, Boolean>> netList = new ArrayList<>();
                nets = NetworkInterface.getNetworkInterfaces();
                for (NetworkInterface netint : Collections.list(nets)) {
                    netList.add(new Pair<>(netint.getName(), netint.isUp()));
                }

                for (Pair pair : netList) {
                    //Boolean.parseBoolean();
                    Log.i("usbtether", pair.first.toString());
                    Log.i("usbtether", pair.second.toString());
                }

            } catch (SocketException e) {
                e.printStackTrace();
            }*/

            // Check Connection events and recover the tether operation
            if (!blockReciever) {
                if (tetherActive && natApplied) {
                    if (!Script.testConnection(ipv4Prefix + lastNetwork)) {
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
                        // Check if the network changed and restore
                        String currentInterface = pickInterface(tetherInterface);
                        if (currentInterface != null && !currentInterface.equals("") && !currentInterface.equals("Auto") && currentInterface.equals(lastNetwork)) {
                            try {
                                checkInterface = NetworkInterface.getByName(currentInterface);
                            } catch (SocketException e) {
                                e.printStackTrace();
                            }
                            if (checkInterface != null) {
                                // Update SNAT if needed
                                String newAddr = setupSNAT(currentInterface, ipv6SNAT);
                                if (!newAddr.equals("") && !newAddr.equals(lastIPv6)) {
                                    Script.refreshSNAT(currentInterface, lastIPv6, newAddr);
                                    SharedPreferences.Editor edit = sharedPref.edit();
                                    edit.putString("lastIPv6", newAddr);
                                    edit.apply();
                                }
                                // Brings tether back up on connection change
                                Script.forwardInterface(ipv4Prefix + currentInterface, currentInterface);
                                blockReciever = false;
                            } else {
                                Log.w("usbtether", "Interface missing, waiting...");
                                needsReset = true;
                                blockReciever = false;
                            }
                        } else {
                            // Works for changing interfaces for now
                            // Need to clean this up FIXME
                            Log.w("usbtether", "Resetting interface...");
                            Script.resetInterface(true, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                            natApplied = false;
                            tetherActive = true;
                            if (currentInterface != null && !currentInterface.equals("") && !currentInterface.equals("Auto") && waitInterface(currentInterface)) {
                                String ipv6Addr = setupSNAT(currentInterface, ipv6SNAT);
                                SharedPreferences.Editor edit = sharedPref.edit();
                                edit.putString("lastNetwork", currentInterface);
                                edit.putString("lastIPv6", ipv6Addr);
                                edit.putBoolean("isXLAT", false); // hmm...
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
                                natApplied = Script.configureNAT(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Masquerading, ipv6SNAT, ipv6Prefix, ipv6Addr, fixTTL, dnsmasq, getFilesDir().getPath());
                                boolean result = false;
                                result = Script.configureRoutes(ipv4Prefix + currentInterface, currentInterface, ipv4Addr, ipv6Prefix, ipv6Masquerading, ipv6SNAT);
                                if (!result) {
                                    Log.w("usbtether", "Resetting interface...");
                                    Script.resetInterface(false, ipv4Prefix + lastNetwork, lastNetwork, ipv6Masquerading, ipv6SNAT, ipv6Prefix, lastIPv6, fixTTL, dnsmasq);
                                    blockReciever = true;
                                    natApplied = false;
                                    tetherActive = true;
                                    Script.configureRNDIS();
                                }
                            }
                        }
                    }
                } else if (!tetherActive) {
                    Log.i("usbtether", "Checking if tethering should be started...");
                    // Tethering not configured, start configuring
                    tetherInterface = pickInterface(tetherInterface);
                    try {
                        checkInterface = NetworkInterface.getByName(tetherInterface);
                    } catch (SocketException e) {
                        e.printStackTrace();
                    }
                    if (checkInterface != null) {
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
