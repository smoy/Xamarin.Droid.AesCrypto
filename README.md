# Xamarin.Droid.AesCrypto
Binding Library to java-aes-crypto

Inspired from https://github.com/tozny/java-aes-crypto, I want Xamarin
Developers to have sane default to use in Android encryption. Rather
than re-implement this in Xamarin Android, I think a binding library
is more appropriate.

#Examples

##Encrypt

```c#
      var mySecretText = "This is my secret";
      const string alias = "com.stevenmoy.droid.secret";
      var encryptedBundle = EncryptionUtil.Encrypt (context, alias, mySecretText);
      // you can now store the EncryptedText, EncryptedConfidentialKey, EncryptedIntegrityKey somewhere
```

##Decrypt

```c#
  //Use the constructor to re-create the EncryptedBundle class from the string:
  const string alias = "com.stevenmoy.droid.secret";
  var encryptedBundle = new EncryptedBundle (EncryptedText, EncryptedConfidentialKey, EncryptedIntegrityKey);
  var decryptedText = EncryptionUtil.Decrypt (context, alias, encryptedBundle);
```  