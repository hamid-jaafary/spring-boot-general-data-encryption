# Enabling General Data Encryption/Decryption in Spring Boot v2.7.*

This repo contains configuration and sample classes for encrypting/decrypting general data using AES/RSA algorithm.

> [!NOTE]
> Setup Used:
>   * JDK 8 | 17
>   * Spring Boot v 2.7.*
>   * keytool utility provided by installed jdk. (keytool is a key and certificate management utility that is part of the Java Development Kit)

## Steps:
**1. Store Creation:**

create store using the Java KeyStore keytool (commands for different sizes has been written for simplicity):
```shell
keytool -genseckey -alias 128bitkey -keyalg aes -keysize 128 -keypass changeme -keystore datakeystore.jks -storetype jceks -storepass letmein
keytool -genseckey -alias 192bitkey -keyalg aes -keysize 192 -keypass changeme -keystore datakeystore.jks -storetype jceks -storepass letmein
keytool -genseckey -alias 256bitkey -keyalg aes -keysize 256 -keypass changeme -keystore datakeystore.jks -storetype jceks -storepass letmein
```

* **New store creation | adding to existing one;**
> If a store is already available, generated key (named under aliases: `128bitkey` | `192bitkey` | `256bitkey`) will be added to already created store, otherwise a new store will be created which contains aes key.

* **Separate config-keystore from general-data-keystore[^1];**
> If you're using keystore for cloud properties encryption/decryption, preferably separate data keystore from config keystore; Otherwise project couldn't start locally.

* **Can RSA keys be used instead of AES key?**
> RSA-pair assymetric key of length 2048, could only be used for encryption/decryption purposes in text with max length of 245char, but it's possible to encrypt/decrypt texts with any length using AES symmetric key.
AES key was used in all use cases in this document; It's possible to use RSA-pair keys to encrypt/decrypt data, keeping in mind limitation above-mentioned. code for RSA encryption/decryption is also added to StringEncryptorDecryptor class, but is commented out.

* **Verifying created entry**
> entries of keystore can be verified after creation using: 
```shell
keytool -v -list -keystore datakeystore.jks -storetype JCEKS
```

* **Generate AES key using java code**
> AES key can be generated with provided method `StringEncryptorDecryptor.generateAESKey()`.

copy created store in a path which can be addressed in your spring boot application, example:

**windows**:
>C:\base\path\datakeystore.jks

**Linux**:
>/base/path/datakeystore.jks

**2. Environment Variables Creation:**

in **windows** add following environment variables:

```properties
DATA_KEYSTORE_PATH=C:\base\path
DATA_KEYSTORE_PASSWORD=letmein
DATA_KEY_SECRET=changeme
```

in **linux** add following commands to ~/.bashrc file:

```shell script
  export DATA_KEYSTORE_PATH=/base/path
  export DATA_KEYSTORE_PASSWORD=letmein
  export DATA_KEY_SECRET=changeme
```

in **docker** implementation for spring boot application, add following to corresponding .env file:
 ```properties
DATA_KEYSTORE_PATH=/base/path
DATA_KEYSTORE_PASSWORD=letmein
DATA_KEY_SECRET=changeme
 ```  

**3. Needed Properties:**

add following properties to bootstrap.yml file for spring boot application:
```yaml
encrypt-data:
  key-store:
    location: ${DATA_KEYSTORE_PATH}/datakeystore.jks
    password: ${DATA_KEYSTORE_PASSWORD}
    alias: 128bitkey
    secret: ${DATA_KEY_SECRET}
```
> [!IMPORTANT]
> As it can be seen in above snippet, environment variables has been used, so sensitive data is not compromised in a shared git repository.

> [!IMPORTANT]
> `file:` string is not needed at first of location; That would cause file not to be found.

**4. Encrypt | Decrypt Text:**

* to test functionality of **encrypt | decrypt** use main method in StringEncryptorDecryptor class:

```java
public static void main(String[] args) throws Exception {
    String plainText = "text to encrypt; If it's less than 245 char, both RSA/AES keys can be used for encryption, otherwise only choice is AES key";
    //...
}
```

* to encrypt a `plainText`, encrypt its value with method `StringEncryptorDecryptor.encryptAES()` of StringEncryptorDecryptor class:

```java
public SomeClass {

    @AutoWired
    private final StringEncryptorDecryptor stringEncryptorDecryptor;

    public void someMethod() {
        //...
        String encryptedText = stringEncryptorDecryptor.encryptAES("plainText");
        //...
    }

}
```

* to decrypt an `encryptedText`, decrypt its value with method `StringEncryptorDecryptor.decryptAES()` of StringEncryptorDecryptor class:

```java
public SomeClass {

    @AutoWired
    private final StringEncryptorDecryptor stringEncryptorDecryptor;

    public void someMethod(){
        //...
        String plainText = stringEncryptorDecryptor.decryptAES("encryptedText");
        //...
    }

}
```

<hr/>

You can safely save encrypted text in DB, and the secret data remains protected. I hope you find it useful for your data encryption and decryption purposes.

Good luck!

[^1]: https://github.com/hamid-jaafary/spring-cloud-config-encryption
