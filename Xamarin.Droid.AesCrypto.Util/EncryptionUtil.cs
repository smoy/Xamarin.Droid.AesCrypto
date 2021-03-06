﻿using System;
using System.Text;
using Android.Content;
using Com.Tozny.Crypto.Android;

namespace Xamarin.Droid.AesCrypto.Util
{
  /// <summary>
  /// EncryptionUtil exists because AndroidKeyStore does not play well with symmetric key (SecretKeyEntry)
  /// until API 23. So we are doing a around about well to have a asymmetric key pair to wrap our
  /// symmetric key; then we can store the encrypted symmetric key in SharedPreference (or whereever). Only
  /// when you need to use the symmetric key, you use AndroidKeyStore to unwrap our enerypted symmetric key.
  /// </summary>
  public class EncryptionUtil
  {
    public EncryptionUtil ()
    {
    }

    /// <summary>
    /// Encrypt the specified clearText.
    /// </summary>
    /// <param name="context">Your Android Context, likely your Activity or Service</param>
    /// <param name="alias">Alias is the name you are using for the key, use sensible name</param>
    /// <param name="clearText">The content you want to encrypt</param>
    public static EncryptedTuple Encrypt (Context context, string alias, string clearText)
    {
      var secretKeys = AesCbcWithIntegrity.GenerateKey ();
      var confidentialKeyWrapper = new SecretKeyWrapper (context, alias);
      var encryptedSymmetricKey = confidentialKeyWrapper.EncryptedThenMac (secretKeys);

      var encryptedBundle = AesCbcWithIntegrity.Encrypt (Encoding.UTF8.GetBytes (clearText), secretKeys);
      return new EncryptedTuple (encryptedBundle.ToString (), encryptedSymmetricKey);
    }

    /// <summary>
    /// Decrypt the encryptedTuple.
    /// </summary>
    /// <param name="context">Your Android Context, likely your Activity or Service</param>
    /// <param name="alias">Alias is the name you are using for the key, use sensible name</param>
    /// <param name="encryptedTuple">Encrypted tuple.</param>
    public static string Decrypt (Context context, string alias, EncryptedTuple encryptedTuple)
    {
      var confidentialKeyWrapper = new SecretKeyWrapper (context, alias);
      var secretKeys = confidentialKeyWrapper.CheckMacAndDecrypt(encryptedTuple.EncryptedSymmetricKey);

      return AesCbcWithIntegrity.DecryptString (new AesCbcWithIntegrity.CipherTextIvMac(encryptedTuple.EncryptedText), secretKeys);
    }
  }
}

