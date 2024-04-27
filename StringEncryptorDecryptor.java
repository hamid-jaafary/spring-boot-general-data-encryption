package com.example.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;

@Component
public class StringEncryptorDecryptor {

  @Value("${encrypt-data.key-store.location}")
  private String keyStoreLocation;
  @Value("${encrypt-data.key-store.password}")
  private String keyStorePassword;
  @Value("${encrypt-data.key-store.alias}")
  private String keyStoreAESAlias;
  @Value("${encrypt-data.key-store.secret}")
  private String keyStoreAESAliasSecret;

  // Running following main method for encryption/decryption purposes without running entire application,
  //  needs four string value for following fields, (@Value() only works in running application context):
  //  1. keyStoreLocation, 2. keyStorePassword, 3. keyStoreAESAlias, 4. keyStoreAESAliasSecret
  public static void main(String[] args) throws Exception {

    StringEncryptorDecryptor encryptorDecryptor = new StringEncryptorDecryptor();

    // Encrypt and decrypt strings
    String plainText = "text to encrypt; If it's less than 245 char, both RSA/AES keys can be used for encryption, otherwise only choice is AES key";

    System.out.println("original text : " + plainText);

//    Encrypt and decrypt using RSA
//    if (plainText.length() < 245) {
//      String base64EncodedFromEncryptedBytesUsingRSA = encryptorDecryptor.encryptRSA(plainText);
//      System.out.println("RSA Encrypted (Base64): " + base64EncodedFromEncryptedBytesUsingRSA);
//      System.out.println("Decrypted: " + encryptorDecryptor.decryptRSA(base64EncodedFromEncryptedBytesUsingRSA));
//    }

    // Encrypt and decrypt using AES
    String base64EncodedFromEncryptedBytesUsingAES = encryptorDecryptor.encryptAES(plainText);
    System.out.println("AES Encrypted (Base64): " + base64EncodedFromEncryptedBytesUsingAES);
    System.out.println("Decrypted: " + encryptorDecryptor.decryptAES(base64EncodedFromEncryptedBytesUsingAES));
  }

  public void generateAESKey() throws Exception {
    // Load the keystore
    String keystoreFile = keyStoreLocation;
    char[] keystorePassword = keyStorePassword.toCharArray();
    KeyStore keyStore = KeyStore.getInstance("JCEKS");
    FileInputStream fis = new FileInputStream(keystoreFile);
    keyStore.load(fis, keystorePassword);
    fis.close();

    // Generate AES key
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(256); // Choose a key size (128, 192, or 256)
    SecretKey aesKey = keyGen.generateKey();

    // Store the AES key in the keystore
    KeyStore.SecretKeyEntry aesKeyEntry = new KeyStore.SecretKeyEntry(aesKey);
    keyStore.setEntry(keyStoreAESAlias, aesKeyEntry, new KeyStore.PasswordProtection(keyStoreAESAliasSecret.toCharArray()));

    // Save the keystore
    FileOutputStream fos = new FileOutputStream(keystoreFile);
    keyStore.store(fos, keystorePassword);
    fos.close();

    // entries of keystore can be verified after creation using: keytool -v -list -keystore keystore.jks -storetype JCEKS
    System.out.println("AES key generated and stored successfully.");
  }

//  public String encryptRSA(String input) throws Exception {
//    // Load keystore
//    KeyStore keyStore = getKeyStore();
//
//    // Access RSA public key
//    PublicKey rsaPub = keyStore.getCertificate(keyStoreRSAAlias).getPublicKey();
//    RSAPublicKey publicKey = (RSAPublicKey) rsaPub;
//
//    // encrypt data
//    Cipher cipher = Cipher.getInstance("RSA");
//    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//    byte[] bytes = cipher.doFinal(input.getBytes());
//
//    // encode to base64 (so it can be saved in DB)
//    return Base64.getEncoder().encodeToString(bytes);
//  }
//
//  public String decryptRSA(String base64String) throws Exception {
//    // Load keystore
//    KeyStore keyStore = getKeyStore();
//
//    // Access RSA private key
//    Key rsaPriv = keyStore.getKey(keyStoreRSAAlias, keyStoreRSAAliasSecret.toCharArray());
//    RSAPrivateKey privateKey = (RSAPrivateKey) rsaPriv;
//
//    // decode from base64 (saved text in DB is base64)
//    byte[] encryptedBytes = Base64.getDecoder().decode(base64String);
//
//    // decrypt data
//    return decryptRSA(encryptedBytes, privateKey);
//  }
//
//  public String decryptRSA(byte[] input, RSAPrivateKey privateKey) throws Exception {
//    Cipher cipher = Cipher.getInstance("RSA");
//    cipher.init(Cipher.DECRYPT_MODE, privateKey);
//    byte[] decryptedBytes = cipher.doFinal(input);
//    return new String(decryptedBytes);
//  }

  public String encryptAES(String input) throws Exception {
    // Load keystore
    KeyStore keyStore = getKeyStore();

    // Access encryption key
    Key aesKey = keyStore.getKey(keyStoreAESAlias, keyStoreAESAliasSecret.toCharArray());

    // encrypt data
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, aesKey);
    byte[] bytes = cipher.doFinal(input.getBytes());

    // encode to base64 (so it can be saved in DB)
    return Base64.getEncoder().encodeToString(bytes);
  }

  public String decryptAES(String base64String) throws Exception {
    // Load keystore
    KeyStore keyStore = getKeyStore();

    // Access encryption key
    Key aesKey = keyStore.getKey(keyStoreAESAlias, keyStoreAESAliasSecret.toCharArray());

    // decode from base64 (saved text in DB is base64)
    byte[] encryptedBytes = Base64.getDecoder().decode(base64String);

    // decrypt data
    return decryptAES(encryptedBytes, aesKey);
  }

  public String decryptAES(byte[] input, Key key) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.DECRYPT_MODE, key);
    byte[] decryptedBytes = cipher.doFinal(input);
    return new String(decryptedBytes);
  }

  private KeyStore getKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
    String keystoreFile = keyStoreLocation;
    char[] keystorePassword = keyStorePassword.toCharArray();
    KeyStore keyStore = KeyStore.getInstance("JCEKS");
    FileInputStream fis = new FileInputStream(keystoreFile);
    keyStore.load(fis, keystorePassword);
    fis.close();
    return keyStore;
  }
}
