package com.worstperson.usbtether;

import androidx.appcompat.app.AppCompatActivity;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import com.google.android.material.snackbar.Snackbar;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity {

    PowerManager powerManager;

    @SuppressLint({"NewApi", "UseSwitchCompatOrMaterialCode", "BatteryLife"})
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        View view = findViewById(android.R.id.content);

        if (checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED ||
                checkSelfPermission("com.wireguard.android.permission.CONTROL_TUNNELS") != PackageManager.PERMISSION_GRANTED) {
            String[] PERMISSIONS = {
                    Manifest.permission.READ_EXTERNAL_STORAGE,
                    "com.wireguard.android.permission.CONTROL_TUNNELS"
            };
            requestPermissions(PERMISSIONS, 1);
        }

        powerManager = (PowerManager) getSystemService(POWER_SERVICE);

        if (powerManager != null && !powerManager.isIgnoringBatteryOptimizations(getPackageName())) {
            Snackbar.make(view, "IGNORE_BATTERY_OPTIMIZATIONS", Snackbar.LENGTH_INDEFINITE).setAction(
                    "Grant", view1 -> startActivity(new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                            Uri.parse("package:" + getPackageName())))).show();
        }

        TextView textview1 = findViewById(R.id.textview1);
        Switch switch1 = findViewById(R.id.switch1);
        Switch switch2 = findViewById(R.id.switch2);
        Switch switch3 = findViewById(R.id.switch3);
        Switch switch4 = findViewById(R.id.switch4);
        Spinner spinner1 = findViewById(R.id.spinner1);
        EditText edittext1 = findViewById(R.id.edittext1);

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (connectivityManager != null) {
            Network activeNetwork = connectivityManager.getActiveNetwork();
            if (activeNetwork != null) {
                LinkProperties linkProperties = connectivityManager.getLinkProperties(activeNetwork);
                if (linkProperties != null) {
                    String name = linkProperties.getInterfaceName();
                    textview1.setText(name);
                }
            }
        }

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        boolean serviceEnabled = sharedPref.getBoolean("serviceEnabled", false);
        boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
        boolean startWireGuard = sharedPref.getBoolean("startWireGuard", false);
        String tetherInterface = sharedPref.getString("tetherInterface", "");
        String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");

        switch1.setChecked(serviceEnabled);
        switch2.setChecked(fixTTL);
        switch3.setChecked(ipv6Masquerading);
        switch4.setChecked(startWireGuard);

        edittext1.setText(wireguardProfile);

        ArrayList<String> arraySpinner = new ArrayList<>();
        arraySpinner.add(tetherInterface);
        Enumeration<NetworkInterface> nets;
        try {
            nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets)){
                if (netint.isUp() && !netint.isLoopback() && !netint.isVirtual() && !netint.getName().equals("rndis0")) {
                    for (InetAddress inetAddress : Collections.list(netint.getInetAddresses())){
                        if (inetAddress instanceof Inet4Address && !arraySpinner.contains(netint.getName())) {
                            arraySpinner.add(netint.getName());
                        }
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, arraySpinner);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner1.setAdapter(adapter);

        if (serviceEnabled) {
            switch2.setEnabled(false);
            switch3.setEnabled(false);
            switch4.setEnabled(false);
            edittext1.setEnabled(false);
            spinner1.setEnabled(false);
        }

        switch1.setOnCheckedChangeListener((buttonView, isChecked) -> {
            switch2.setEnabled(!isChecked);
            switch3.setEnabled(!isChecked);
            switch4.setEnabled(!isChecked);
            edittext1.setEnabled(!isChecked);
            spinner1.setEnabled(!isChecked);
            SharedPreferences.Editor edit = sharedPref.edit();
            edit.putBoolean("serviceEnabled", isChecked);
            edit.apply();
            Intent it = new Intent(MainActivity.this, ForegroundService.class);
            if (isChecked) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(it);
                } else {
                    startService(it);
                }
            } else {
                stopService(it);
            }
        });

        switch2.setOnCheckedChangeListener((buttonView, isChecked) -> {
            SharedPreferences.Editor edit = sharedPref.edit();
            edit.putBoolean("fixTTL", isChecked);
            edit.apply();
        });

        switch3.setOnCheckedChangeListener((buttonView, isChecked) -> {
            SharedPreferences.Editor edit = sharedPref.edit();
            edit.putBoolean("ipv6Masquerading", isChecked);
            edit.apply();
        });

        switch4.setOnCheckedChangeListener((buttonView, isChecked) -> {
            SharedPreferences.Editor edit = sharedPref.edit();
            edit.putBoolean("startWireGuard", isChecked);
            edit.apply();
        });

        spinner1.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
                Object item = adapterView.getItemAtPosition(position);
                SharedPreferences.Editor edit = sharedPref.edit();
                edit.putString("tetherInterface", item.toString());
                edit.apply();
            }
            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });

        edittext1.setOnEditorActionListener((v, actionId, event) -> {
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                SharedPreferences.Editor edit = sharedPref.edit();
                edit.putString("wireguardProfile", String.valueOf(edittext1.getText()));
                edit.apply();
                return true;
            }
            return false;
        });

        if (serviceEnabled && !ForegroundService.isStarted) {
            Intent it = new Intent(MainActivity.this, ForegroundService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(it);
            } else {
                startService(it);
            }
        }
    }

    @Override
    public void onResume(){
        super.onResume();

        Spinner spinner1 = findViewById(R.id.spinner1);

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String tetherInterface = sharedPref.getString("tetherInterface", "");

        ArrayList<String> arraySpinner = new ArrayList<>();
        arraySpinner.add(tetherInterface);
        Enumeration<NetworkInterface> nets;
        try {
            nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets)){
                if (netint.isUp() && !netint.isLoopback() && !netint.isVirtual() && !netint.getName().equals("rndis0")) {
                    for (InetAddress inetAddress : Collections.list(netint.getInetAddresses())){
                        if (inetAddress instanceof Inet4Address && !arraySpinner.contains(netint.getName())) {
                            arraySpinner.add(netint.getName());
                        }
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, arraySpinner);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner1.setAdapter(adapter);
    }
}