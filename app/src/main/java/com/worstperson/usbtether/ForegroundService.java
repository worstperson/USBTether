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
import android.os.BatteryManager;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import android.widget.Toast;
import androidx.core.app.NotificationCompat;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;

public class ForegroundService extends Service {

    public static final String CHANNEL_ID = "ForegroundServiceChannel";

    PowerManager powerManager;
    WakeLock wakeLock;

    static public Boolean isStarted = false;

    private void runScript() {
        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String tetherInterface = sharedPref.getString("tetherInterface", "");
        Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
        Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        if (tetherInterface != null && !tetherInterface.equals("")) {

            unregisterReceiver(PowerReceiver); //Required for < android.os.Build.VERSION_CODES.P

            try {
                Script.runCommands(tetherInterface, ipv6Masquerading, fixTTL);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            IntentFilter filter = new IntentFilter();
            filter.addAction(Intent.ACTION_POWER_CONNECTED);
            filter.addAction(Intent.ACTION_POWER_DISCONNECTED);
            registerReceiver(PowerReceiver, filter);
        }
    }

    private void checkHost(Context context) {
        Intent batteryStatus = context.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
        if (batteryStatus != null && batteryStatus.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) == BatteryManager.BATTERY_PLUGGED_USB) {
            Log.w("USBTether", "Connected to tetherable device");

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
        } else {
            Log.w("USBTether", "Not connected to tetherable device");
        }
    }

    private final BroadcastReceiver PowerReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            if (action != null && action.equals(Intent.ACTION_POWER_CONNECTED)) {
                checkHost(context);
            } else {
                SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
                String tetherInterface = sharedPref.getString("tetherInterface", "");
                Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
                Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);

                Script.resetInterface(tetherInterface, ipv6Masquerading, fixTTL);

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
        filter.addAction(Intent.ACTION_POWER_CONNECTED);
        filter.addAction(Intent.ACTION_POWER_DISCONNECTED);
        registerReceiver(PowerReceiver, filter);

        checkHost(this);

        return Service.START_STICKY;
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (wakeLock != null && wakeLock.isHeld()) {
            wakeLock.release();
        }
        unregisterReceiver(PowerReceiver);

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String tetherInterface = sharedPref.getString("tetherInterface", "");
        Boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
        Boolean fixTTL = sharedPref.getBoolean("fixTTL", false);

        Script.resetInterface(tetherInterface, ipv6Masquerading, fixTTL);

        Toast.makeText(this, "Service destroyed by user.", Toast.LENGTH_LONG).show();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
