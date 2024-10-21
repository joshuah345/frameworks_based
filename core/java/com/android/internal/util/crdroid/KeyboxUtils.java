package com.android.internal.util.crdroid;

import java.io.File;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.xml.parsers.*;
import org.w3c.dom.*;

import android.util.Log;

// TODO: add methods to get serial numbers and banned list as well as some additional metadata such as expiration

public class KeyboxUtils {

    private static final Pattern SANITIZE_PATTERN = Pattern.compile("\\s|-----BEGIN [^-]+-----|-----END [^-]+-----");
    private static final String TAG = "KeyboxUtils";
    
    public static String sanitizePEM(String pem) {
        if (pem == null) {
            return null;
        }

        return SANITIZE_PATTERN.matcher(pem).replaceAll("");
    }

    public static Map<String, String> sanitizeMap(Map<String, String> map) {
        Log.d(TAG, "Preparing keybox for use...");
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String sanitizedValue = sanitizePEM(entry.getValue());
            entry.setValue(sanitizedValue);
        }
        return map;
    }

     public static class InvalidKeyboxException extends Exception {
        public InvalidKeyboxException(String message) {
            super(message);
        }
    }

    public static class ParsedKey {
        public String algorithm;
        public String privateKey;
        public List<String> certificateChain = new ArrayList<>();
    }

    public static List<ParsedKey> parseKeybox(File xmlFile) throws Exception {
        // Parse the XML document
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(xmlFile);

        // Check if the root element is <AndroidAttestation>
        Element root = document.getDocumentElement();
        if (!"AndroidAttestation".equals(root.getTagName())) {
            throw new InvalidKeyboxException("Missing <AndroidAttestation> root element.");
        }

        List<ParsedKey> parsedKeys = new ArrayList<>();

        // Get all <Keybox> elements
        NodeList keyboxes = root.getElementsByTagName("Keybox");
        for (int i = 0; i < keyboxes.getLength(); i++) {
            Element keybox = (Element) keyboxes.item(i);

            // For each <Key> element inside the <Keybox>
            NodeList keys = keybox.getElementsByTagName("Key");
            for (int j = 0; j < keys.getLength(); j++) {
                Element keyElement = (Element) keys.item(j);

                // Parse the key information (algorithm and private key)
                String algorithm = keyElement.getAttribute("algorithm");
                String privateKey = getTagContent(keyElement, "PrivateKey");

                ParsedKey parsedKey = new ParsedKey();
                parsedKey.algorithm = algorithm;
                parsedKey.privateKey = privateKey;

                // Parse the certificate chain
                Element certChainElement =
                        (Element) keyElement.getElementsByTagName("CertificateChain").item(0);
                int numberOfCertificates =
                        Integer.parseInt(getTagContent(certChainElement, "NumberOfCertificates"));
                NodeList certificates = certChainElement.getElementsByTagName("Certificate");

                // Verify that the number of <Certificate> elements matches the
                // <NumberOfCertificates> value
                if (certificates.getLength() != numberOfCertificates) {
                    throw new InvalidKeyboxException(
                            "Number of certificates doesn't match the actual count.");
                }

                // Add each certificate to the ParsedKey object
                for (int k = 0; k < certificates.getLength(); k++) {
                    String certificate = certificates.item(k).getTextContent().trim();
                    parsedKey.certificateChain.add(certificate);
                }

                parsedKeys.add(parsedKey);
            }
        }

        return parsedKeys;
    }

    public static Map<String, String> writeCertsAndKeysToMap(List<ParsedKey> parsedKeys) {
        Map<String, String> certKeyMap = new HashMap<>();

        for (ParsedKey key : parsedKeys) {
    
            String keyAlgo = ("ecdsa".equals(key.algorithm)) ? "EC" : "RSA";
            // Sanitize the private key and add it to the map
            String sanitizedPrivateKey = sanitizePEM(key.privateKey);
            certKeyMap.put(keyAlgo + ".PRIV", sanitizedPrivateKey);

            // Sanitize each certificate and add it to the map with a unique key
            for (int i = 0; i < key.certificateChain.size(); i++) {
                String certAlgo = ("ecdsa".equals(key.algorithm)) ? "EC" : "RSA";
                String sanitizedCert = sanitizePEM(key.certificateChain.get(i));
                certKeyMap.put(certAlgo + ".CERT" + "_" + (i + 1), sanitizedCert);
            }
        }

        return certKeyMap;
    }

    // Helper method to get the content of a specific tag
    private static String getTagContent(Element parent, String tagName)
            throws InvalidKeyboxException {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() == 0) {
            throw new InvalidKeyboxException("Missing <" + tagName + "> element.");
        }
        return nodes.item(0).getTextContent().trim();
    }

    public static Map<String, String> getMapFromXML(File xmlFile) throws InvalidKeyboxException {
        if (xmlFile == null | !xmlFile.exists()) {
            throw new IllegalArgumentException("No XML file was specified or XML file could not be found.");
        }

        Map<String, String> keyboxMap = new HashMap<>();

        try {
            Log.d(TAG, "Attempting to create map from XML keybox...");
            List<ParsedKey> parsedKeys = parseKeybox(xmlFile);
            keyboxMap = writeCertsAndKeysToMap(parsedKeys);

        } catch (InvalidKeyboxException e) {
            Log.e(TAG, "Invalid Keybox: " + e.getMessage());
        } catch (Exception e) {
        e.printStackTrace();
    }

        return keyboxMap;
    }

    public class KeyConverter {

    private static final String TAG = "KeyConverter";

    public static Map<String, String> convertKeys(Map<String, String> map) {
        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            String convertedValue = convertToPKCS8(entry.getValue());
            result.put(entry.getKey(), convertedValue);
        }
        return result;
    }

    private static String convertToPKCS8(String input) {
        if (input == null || input.isEmpty()) {
            Log.w(TAG, "No input to convert to PKCS8");
            return input;
        }
        Log.d(TAG, "Attempting to convert keys to PKCS#8...");
        try {
            byte[] decodedKey = Base64.getDecoder().decode(input);
            
            // Check if it's already in PKCS8 format
            if (isPKCS8(decodedKey)) {
                Log.d(TAG, "Key is already PKCS8, skipping...");
                return input;
            }

            byte[] pkcs8Bytes;
            if (isRSAKey(decodedKey)) {
                Log.d(TAG, "Converting RSA Key...");
                pkcs8Bytes = convertRSAToPKCS8(decodedKey);
            } else if (isECKey(decodedKey)) {
                Log.d(TAG, "Converting EC Key...");
                pkcs8Bytes = convertECToPKCS8(decodedKey);
            } else {
                // Not a recognized private key format, return as is
                return input;
            }

            return Base64.getEncoder().encodeToString(pkcs8Bytes);
        } catch (Exception e) {
            // If any exception occurs, return the original input
            return input;
        }
    }

    private static boolean isPKCS8(byte[] key) {
        // PKCS8 starts with 30 82 (sequence) followed by 2 bytes of length
        return key.length > 4 && key[0] == 0x30 && key[1] == (byte)0x82;
    }

    private static boolean isRSAKey(byte[] key) {
        // RSA PKCS1 starts with 30 82 (sequence) followed by 2 bytes of length,
        // then 02 01 00 (version) and 02 (integer)
        return key.length > 7 && key[0] == 0x30 && key[1] == (byte)0x82 
               && key[5] == 0x02 && key[6] == 0x01 && key[7] == 0x00;
    }

    private static boolean isECKey(byte[] key) {
        // EC PKCS1 starts with 30 77 (sequence) for prime256v1 or 30 81 (sequence) for secp384r1
        return key.length > 2 && key[0] == 0x30 && (key[1] == 0x77 || key[1] == (byte)0x81);
    }

    private static byte[] convertRSAToPKCS8(byte[] pkcs1Bytes) throws Exception {
        RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs1Bytes));

        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(
                privateKey.getModulus(),
                privateKey.getPublicExponent(),
                privateKey.getPrivateExponent(),
                privateKey.getPrimeP(),
                privateKey.getPrimeQ(),
                privateKey.getPrimeExponentP(),
                privateKey.getPrimeExponentQ(),
                privateKey.getCrtCoefficient()
        );

        return KeyFactory.getInstance("RSA").generatePrivate(keySpec).getEncoded();
    }

    private static byte[] convertECToPKCS8(byte[] pkcs1Bytes) throws Exception {
        ECPrivateKey privateKey = (ECPrivateKey) KeyFactory.getInstance("EC")
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs1Bytes));

        return privateKey.getEncoded();
    }

}
}
