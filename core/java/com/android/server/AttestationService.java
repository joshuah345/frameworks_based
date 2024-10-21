/*
* Copyright (C) 2024 The LeafOS Project
*
* SPDX-License-Identifier: Apache-2.0
*
*/

package com.android.server;

import android.content.Context;
import android.content.ContentResolver;
import android.content.om.*;
import android.net.Uri;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Environment;
import android.os.SystemProperties;
import android.util.Log;
import android.os.UserHandle;

import com.android.internal.util.crdroid.KeyProviderManager;

import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;


public class AttestationService {
    private static final String TAG = AttestationService.class.getSimpleName();
   // private static final String KEYBOX_API = "https://play.leafos.org/keybox";
    
    private static final String KEYBOX_DATA_FILENAME = "user_keybox.xml";
    
    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);
    private static final boolean SPOOF_KEYBOX = SystemProperties.getBoolean("persist.sys.spoof.gms", true);
    private static final boolean KEYBOX_USE_XML = SystemProperties.getBoolean("persist.sys.pihooks.key_attestation_use_xml", false);
    private static final String OVERLAY_PKG = "com.hiro.keyattestation";
    private static Context mContext;
    
    private static File mKeyboxDataFile = new File(Environment.getDataSystemDirectory(), KEYBOX_DATA_FILENAME);

      public AttestationService(Context context) {
        super(context);
        mContext = context;
    }
    
    public class AttestationServiceUtils {

    public static void reloadKeybox() throws Exception {
        if (isPackageInstalled(OVERLAY_PKG) && !KEYBOX_USE_XML) {
            try {
                enableOverlay(mContext, OVERLAY_PKG);
                KeyProviderManager.loadKeyboxRRO();
            } catch (Exception err) {
                Log.e(TAG, "Loading RRO keybox failed.");
                err.printStackTrace();
                throw new Exception();
            }
        } else if (KEYBOX_USE_XML) {
            try {
                KeyProviderManager.loadKeyboxXML(mKeyboxDataFile);
            } catch (Exception err) {
                Log.w(TAG,"Falling back to RRO.");
                try {
                    enableOverlay(mContext, OVERLAY_PKG);
                    KeyProviderManager.loadKeyboxRRO();  
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new Exception();
                }
            }
        }
    }

    private void writeToFile(File file, String data) {
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(data);
            // Set -rw-r--r-- (644) permission to make it readable by others.
            file.setReadable(true, false);
        } catch (IOException e) {
            Log.e(TAG, "Error writing to file", e);
        }
    }

     public static boolean enableOverlay(Context context, String overlayPackageName) {
        try {
            OverlayManager overlayManager = (OverlayManager) context.getSystemService(Context.OVERLAY_SERVICE);

            if (overlayManager != null) {
                UserHandle userHandle = UserHandle.of(UserHandle.myUserId());
                OverlayInfo overlayInfo = overlayManager.getOverlayInfo(overlayPackageName, userHandle);

                if (overlayInfo.isEnabled()) {
                    Log.d(TAG, "Overlay " + overlayPackageName + " is already enabled.");
                    return true;
                }
                // Enable the overlay (method is void, so use try-catch to handle errors)
                overlayManager.setEnabled(overlayPackageName, true, userHandle);
                Log.d(TAG, "Overlay " + overlayPackageName + " enabled successfully.");

                // Confirm if the overlay is enabled after the change
                overlayInfo = overlayManager.getOverlayInfo(overlayPackageName, userHandle);
                return overlayInfo != null && overlayInfo.isEnabled();
            } else {
                Log.e(TAG, "OverlayManager service not available.");
            }
        } catch (Exception e) {
            Log.e(TAG, "Error enabling overlay: " + e.getMessage(), e);
        }
        return false;
    }

    public static void writeFileFromUri(Uri fileUri, File destinationFile, ContentResolver resolver) throws Exception {
       try {
        // Get input stream from the Uri
        InputStream inputStream = resolver.openInputStream(fileUri);

            if (inputStream != null) {
                OutputStream outputStream = new FileOutputStream(destinationFile, false); // Overwrite if exists

            // Buffer for transferring data
                byte[] buffer = new byte[1024];
                int length;

            // Write the file
                while ((length = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, length);
            }

            // Close streams
                inputStream.close();
                outputStream.close();

            // Set -rw-r--r-- (644) permission to make it readable by others.
                destinationFile.setReadable(true, false);

                Log.d("FileWrite", "File written successfully to " + destinationFile.getAbsolutePath());
            }
        } catch (Exception e) {
            Log.e("FileWrite", "Error writing to " + e.getMessage(), e);
        }
    }

    private static boolean isPackageInstalled(String packageName) {
        PackageManager pm = mContext.getPackageManager();
        try {
            pm.getPackageInfo(packageName, PackageManager.GET_ACTIVITIES);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            Log.i(TAG, packageName + " is not installed");
            return false;
        }
    }
}
    
    private String readFromFile(File file) {
        StringBuilder content = new StringBuilder();
        
        if (file.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;
                
                while ((line = reader.readLine()) != null) {
                    content.append(line);
                }
            } catch (IOException e) {
                Log.e(TAG, "Error reading from file", e);
            }
        }
        return content.toString();
    }
    

    
    private boolean isInternetConnected() {
        ConnectivityManager cm =
        (ConnectivityManager) mContext.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network nw = cm.getActiveNetwork();
        if (nw == null) return false;
        NetworkCapabilities actNw = cm.getNetworkCapabilities(nw);
        return actNw != null
        && (actNw.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
        || actNw.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        || actNw.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        || actNw.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH));
    }
    
    
    private void dlog(String message) {
        if (DEBUG) Log.d(TAG, message);
    }
    
}