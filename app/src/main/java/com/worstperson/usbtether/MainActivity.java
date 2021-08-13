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
import android.view.KeyEvent;
import android.view.View;
import android.view.inputmethod.EditorInfo;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.Switch;
import android.widget.TextView;
import com.google.android.material.snackbar.Snackbar;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.regex.Pattern;

public class MainActivity extends AppCompatActivity {

    PowerManager powerManager;

    void setInterfaceSpinner(String tetherInterface, Spinner interface_spinner) {
        ArrayList<String> arraySpinner = new ArrayList<>();
        arraySpinner.add(tetherInterface);
        if (!tetherInterface.equals("Auto")) {
            arraySpinner.add("Auto");
        }
        Enumeration<NetworkInterface> nets;
        try {
            nets = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface netint : Collections.list(nets)){
                if (netint.isUp() && !netint.isLoopback() && !netint.isVirtual() && !netint.getName().equals("rndis0") && !netint.getName().startsWith("v4-")) {
                    for (InetAddress inetAddress : Collections.list(netint.getInetAddresses())){
                        if (!arraySpinner.contains(netint.getName())) {
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
        interface_spinner.setAdapter(adapter);
    }

    @SuppressLint({"UseSwitchCompatOrMaterialCode", "BatteryLife", "WrongConstant"})
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

        File file = new File(getFilesDir().getPath() + "/dnsmasq.armeabi-v7a");
        if (!file.exists()) {
            try (InputStream in = getResources().openRawResource(R.raw.dnsmasq_arm)) {
                try (FileOutputStream out = new FileOutputStream(file)) {
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        file.setExecutable(true);

        file = new File(getFilesDir().getPath() + "/dnsmasq.arm64-v8a");
        if (!file.exists()) {
            try (InputStream in = getResources().openRawResource(R.raw.dnsmasq_arm64)) {
                try (FileOutputStream out = new FileOutputStream(file)) {
                    byte[] buf = new byte[1024];
                    int len;
                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        file.setExecutable(true);

        TextView net_textview = findViewById(R.id.net_textview);
        Switch service_switch = findViewById(R.id.service_switch);
        Switch dnsmasq_switch = findViewById(R.id.dnsmasq_switch);
        Switch ttl_switch = findViewById(R.id.ttl_switch);
        Spinner vpn_spinner = findViewById(R.id.vpn_spinner);
        Spinner interface_spinner = findViewById(R.id.interface_spinner);
        Spinner nat_spinner = findViewById(R.id.nat_spinner);
        Spinner prefix_spinner = findViewById(R.id.prefix_spinner);
        EditText ipv4_text = findViewById(R.id.ipv4_text);
        EditText wg_text = findViewById(R.id.wg_text);
        LinearLayout wgp_layout = findViewById(R.id.wgp_layout);

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (connectivityManager != null) {
            Network activeNetwork = connectivityManager.getActiveNetwork();
            if (activeNetwork != null) {
                LinkProperties linkProperties = connectivityManager.getLinkProperties(activeNetwork);
                if (linkProperties != null) {
                    String name = linkProperties.getInterfaceName();
                    net_textview.setText(name);
                }
            }
        }

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        boolean serviceEnabled = sharedPref.getBoolean("serviceEnabled", false);
        boolean dnsmasq = sharedPref.getBoolean("dnsmasq", true);
        boolean fixTTL = sharedPref.getBoolean("fixTTL", false);
        boolean ipv6Masquerading = sharedPref.getBoolean("ipv6Masquerading", false);
        boolean ipv6SNAT = sharedPref.getBoolean("ipv6SNAT", false);
        boolean ipv6Default = sharedPref.getBoolean("ipv6Default", false);
        int autostartVPN = sharedPref.getInt("autostartVPN", 0);
        String tetherInterface = sharedPref.getString("tetherInterface", "Auto");
        String ipv4Addr = sharedPref.getString("ipv4Addr", "192.168.42.129");
        String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");

        service_switch.setChecked(serviceEnabled);
        dnsmasq_switch.setChecked(dnsmasq);
        ttl_switch.setChecked(fixTTL);

        ipv4_text.setText(ipv4Addr);
        wg_text.setText(wireguardProfile);

        setInterfaceSpinner(tetherInterface, interface_spinner);

        ArrayList<String> arraySpinner2 = new ArrayList<>();
        arraySpinner2.add("None");
        arraySpinner2.add("Masquerading");
        arraySpinner2.add("SNAT");
        ArrayAdapter<String> adapter2 = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, arraySpinner2);
        adapter2.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        nat_spinner.setAdapter(adapter2);
        int position = 0;
        if (ipv6Masquerading) {
            position = 1;
        } else if (ipv6SNAT) {
            position = 2;
        }
        nat_spinner.setSelection(position);

        ArrayList<String> arraySpinner3 = new ArrayList<>();
        arraySpinner3.add("ULA (fd00::)");     // Prefer IPv4
        arraySpinner3.add("GUA (2001:db8::)"); // Prefer IPv6
        ArrayAdapter<String> adapter3 = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, arraySpinner3);
        adapter3.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        prefix_spinner.setAdapter(adapter3);
        prefix_spinner.setSelection(ipv6Default ? 1 : 0);

        ArrayList<String> arraySpinner4 = new ArrayList<>();
        arraySpinner4.add("disabled");
        arraySpinner4.add("WireGuard");
        arraySpinner4.add("WireGuard Kernel Mode");
        arraySpinner4.add("Google One VPN");
        arraySpinner4.add("Cloudflare 1.1.1.1 Warp");
        ArrayAdapter<String> adapter4 = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, arraySpinner4);
        adapter4.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        vpn_spinner.setAdapter(adapter4);
        vpn_spinner.setSelection(autostartVPN);

        if (serviceEnabled) {
            dnsmasq_switch.setEnabled(false);
            ttl_switch.setEnabled(false);
            ipv4_text.setEnabled(false);
            wg_text.setEnabled(false);
            interface_spinner.setEnabled(false);
            nat_spinner.setEnabled(false);
            prefix_spinner.setEnabled(false);
            vpn_spinner.setEnabled(false);
        }

        if (autostartVPN != 1 && autostartVPN != 2) {
            wgp_layout.setVisibility(View.GONE);
        }

        service_switch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            dnsmasq_switch.setEnabled(!isChecked);
            ttl_switch.setEnabled(!isChecked);
            ipv4_text.setEnabled(!isChecked);
            wg_text.setEnabled(!isChecked);
            interface_spinner.setEnabled(!isChecked);
            nat_spinner.setEnabled(!isChecked);
            prefix_spinner.setEnabled(!isChecked);
            vpn_spinner.setEnabled(!isChecked);
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

        dnsmasq_switch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            SharedPreferences.Editor edit = sharedPref.edit();
            edit.putBoolean("dnsmasq", isChecked);
            edit.apply();
        });

        ttl_switch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            SharedPreferences.Editor edit = sharedPref.edit();
            edit.putBoolean("fixTTL", isChecked);
            edit.apply();
        });

        interface_spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
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

        nat_spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
                Object item = adapterView.getItemAtPosition(position);
                SharedPreferences.Editor edit = sharedPref.edit();
                if (item.equals("Masquerading")) {
                    edit.putBoolean("ipv6Masquerading", true);
                    edit.putBoolean("ipv6SNAT", false);
                } else if (item.equals("SNAT")) {
                    edit.putBoolean("ipv6Masquerading", false);
                    edit.putBoolean("ipv6SNAT", true);
                } else {
                    edit.putBoolean("ipv6Masquerading", false);
                    edit.putBoolean("ipv6SNAT", false);
                }
                edit.apply();
            }
            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });

        prefix_spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
                SharedPreferences.Editor edit = sharedPref.edit();
                edit.putBoolean("ipv6Default", position == 1);
                edit.apply();
            }
            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });

        vpn_spinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
                String tetherInterface = "";
                SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
                String wireguardProfile = sharedPref.getString("wireguardProfile", "wgcf-profile");
                SharedPreferences.Editor edit = sharedPref.edit();
                edit.putInt("autostartVPN", position);
                switch (position) {
                    case 0:
                        wgp_layout.setVisibility(View.GONE);
                        break;
                    case 1: case 2:
                        wgp_layout.setVisibility(View.VISIBLE);
                        if (position == 1) {
                            tetherInterface = "tun0";
                        } else {
                            tetherInterface = wireguardProfile;
                        }
                        break;
                    default:
                        wgp_layout.setVisibility(View.GONE);
                        tetherInterface = "tun0";
                }
                if (position > 0) {
                    setInterfaceSpinner(tetherInterface, interface_spinner);
                    edit.putString("tetherInterface", tetherInterface);
                }
                edit.apply();
            }
            @Override
            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });

        ipv4_text.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                if (actionId == EditorInfo.IME_ACTION_DONE) {
                    Pattern sPattern = Pattern.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
                    if (sPattern.matcher(String.valueOf(ipv4_text.getText())).matches()) {
                        SharedPreferences.Editor edit = sharedPref.edit();
                        edit.putString("ipv4Addr", String.valueOf(ipv4_text.getText()));
                        edit.apply();
                        return false;
                    }
                }
                return true;
            }
        });

        wg_text.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
                int autostartVPN = sharedPref.getInt("autostartVPN", 0);
                if (actionId == EditorInfo.IME_ACTION_DONE) {
                    SharedPreferences.Editor edit = sharedPref.edit();
                    edit.putString("wireguardProfile", String.valueOf(wg_text.getText()));
                    if (autostartVPN == 2) {
                        String tetherInterface = String.valueOf(wg_text.getText());
                        MainActivity.this.setInterfaceSpinner(tetherInterface, interface_spinner);
                        edit.putString("tetherInterface", tetherInterface);
                    }
                    edit.apply();
                    return false;
                }

                return true;
            }
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

        TextView net_textview = findViewById(R.id.net_textview);
        Spinner interface_spinner = findViewById(R.id.interface_spinner);

        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (connectivityManager != null) {
            Network activeNetwork = connectivityManager.getActiveNetwork();
            if (activeNetwork != null) {
                LinkProperties linkProperties = connectivityManager.getLinkProperties(activeNetwork);
                if (linkProperties != null) {
                    String name = linkProperties.getInterfaceName();
                    net_textview.setText(name);
                }
            }
        }

        SharedPreferences sharedPref = getSharedPreferences("Settings", Context.MODE_PRIVATE);
        String tetherInterface = sharedPref.getString("tetherInterface", "Auto");

        setInterfaceSpinner(tetherInterface, interface_spinner);
    }
}