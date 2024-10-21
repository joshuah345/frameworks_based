package com.android.internal.util.crdroid;

import android.app.ActivityThread;
import android.content.Context;
import android.content.om.*;
import android.content.ContentResolver;
import android.content.pm.PackageManager;
import android.os.UserHandle;
import android.os.ServiceManager;
import android.os.RemoteException;
import android.util.Log;

import android.os.Environment;
import android.os.SystemProperties;

import android.net.Uri;

import com.android.internal.R;

import androidx.annotation.Nullable;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
/**
 * Manager class for handling keybox providers.
 * @hide
 */
public final class KeyProviderManager {
    private static final String TAG = "KeyProviderManager";
    private static final boolean KEYBOX_USE_XML = SystemProperties.getBoolean("persist.sys.pihooks.key_attestation_use_xml", false);
    private static Map<String, String> keyboxData = new HashMap<>();
    private static final String KEYBOX_DATA_FILENAME = "user_keybox.xml";
    private static final File KEYBOX_DATA_FILE = new File(Environment.getDataSystemDirectory(), KEYBOX_DATA_FILENAME);
    private static final String OVERLAY_PKG = "com.hiro.keyattestation";

    private static Context getApplicationContext() {
        try {
            return ActivityThread.currentApplication().getApplicationContext();
        } catch (Exception e) {
            Log.e(TAG, "Error getting application context", e);
            return null;
        }
    }

    private static final IKeyboxProvider PROVIDER = new DefaultKeyboxProvider();

    public static IKeyboxProvider getProvider() {
        return PROVIDER;
    }

    public static boolean isKeyboxAvailable() {
        return PROVIDER.hasKeybox();
    }

    public static boolean isPackageInstalled(String packageName, Context context) {
        PackageManager packageManager = context.getPackageManager();
        try {
        packageManager.getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    public static void loadKeyboxRRO() throws Exception {
        keyboxData.clear();
            Log.d(TAG, "Using RRO for keyboxData...");
            String[] keybox = getApplicationContext().getResources().getStringArray(R.array.config_certifiedKeybox);
            Arrays.stream(keybox)
                .map(entry -> entry.split(":", 2))
                    .filter(parts -> parts.length == 2)
                        .forEach(parts -> keyboxData.put(parts[0], parts[1]));
            KeyboxUtils.KeyConverter.convertKeys(KeyboxUtils.sanitizeMap(keyboxData));
            if (!isKeyboxAvailable()) {
                throw new Exception();
        }
    }

    public static void loadKeyboxXML(File xmlFile) throws Exception {
            keyboxData.clear();
            Log.d(TAG, "Using user provided xml for keyboxData...");
            if (xmlFile.exists()) {
                try  {
                    keyboxData = KeyboxUtils.KeyConverter.convertKeys(KeyboxUtils.getMapFromXML(xmlFile));
                } catch (KeyboxUtils.InvalidKeyboxException e) {
                    Log.e(TAG, "Invalid Keybox: " + e.getMessage());
                } catch (Exception e) {
                    e.printStackTrace();
                }
                if (!isKeyboxAvailable()) {
                    throw new Exception("Loading XML keybox failed.");
                }
            } else {
                throw new Exception("Keybox XML not found.");
            }    
        }

    private static class DefaultKeyboxProvider implements IKeyboxProvider {

        Context context = getApplicationContext();

        private DefaultKeyboxProvider() {
            
            if (context == null) {
                Log.e(TAG, "Failed to get application context");
                return;
            }
        
            if (!hasKeybox()) {
                Log.w(TAG, "Incomplete keybox data loaded");    
            }
        }

        @Override
        public boolean hasKeybox() {
            return Arrays.asList("EC.PRIV", "EC.CERT_1", "EC.CERT_2", "EC.CERT_3",
                    "RSA.PRIV", "RSA.CERT_1", "RSA.CERT_2", "RSA.CERT_3")
                    .stream()
                    .allMatch(keyboxData::containsKey);
        }

        @Override
        public String getEcPrivateKey() {
            return keyboxData.get("EC.PRIV");
        }

        @Override
        public String getRsaPrivateKey() {
            return keyboxData.get("RSA.PRIV");
        }

        @Override
        public String[] getEcCertificateChain() {
            return getCertificateChain("EC");
        }

        @Override
        public String[] getRsaCertificateChain() {
            return getCertificateChain("RSA");
        }

        private String[] getCertificateChain(String prefix) {
            return new String[]{
                    keyboxData.get(prefix + ".CERT_1"),
                    keyboxData.get(prefix + ".CERT_2"),
                    keyboxData.get(prefix + ".CERT_3")
            };
        }
    }
}