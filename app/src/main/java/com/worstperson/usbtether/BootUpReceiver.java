package com.worstperson.usbtether;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

public class BootUpReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent.getAction().equals(Intent.ACTION_BOOT_COMPLETED)) {
            SharedPreferences sharedPref = context.getSharedPreferences("Settings", Context.MODE_PRIVATE);
            boolean serviceEnabled = sharedPref.getBoolean("serviceEnabled", false);
            if (serviceEnabled && !ForegroundService.isStarted) {
                Intent it = new Intent(context.getApplicationContext(), ForegroundService.class);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(it);
                } else {
                    context.startService(it);
                }
            }
        }
    }
}
