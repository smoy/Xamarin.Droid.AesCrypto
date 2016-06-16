using System;
using Android.Content;
using Android.Security;
using Java.Math;
using Java.Security;
using Java.Util;
using Java.Util.Concurrent.Atomic;
using Javax.Crypto;
using Javax.Security.Auth.X500;

using Com.Tozny.Crypto.Android;

namespace Xamarin.Droid.AesCrypto.Util
{
  /// <summary>
  /// Secret key wrapper.
  /// 
  /// Inspired from https://android.googlesource.com/platform/development/+/master/samples/Vault/src/com/example/android/vault/SecretKeyWrapper.java
  /// 
  /// Only tested with API 19
  /// 
  /// 
  /// </summary>
  public class SecretKeyWrapper
  {
    private readonly Cipher cipher;
    private readonly KeyPair pair;

    static readonly AtomicBoolean prngFixed = new AtomicBoolean (false);
    static readonly object prngLock = new object ();

    public SecretKeyWrapper (Context context, String alias)
    {
      FixPrng ();

      cipher = Cipher.GetInstance("RSA/ECB/PKCS1Padding");
      var keyStore = KeyStore.GetInstance ("AndroidKeyStore");
      keyStore.Load (null);
      if (!keyStore.ContainsAlias (alias)) {
        GenerateKeyPair (context, alias);
      }
      // Even if we just generated the key, always read it back to ensure we
      // can read it successfully.
      var entry = (KeyStore.PrivateKeyEntry)keyStore.GetEntry (alias, null);
      pair = new KeyPair (entry.Certificate.PublicKey, entry.PrivateKey);
    }

    private static void FixPrng ()
    {
      if (!prngFixed.Get ()) {
        lock (prngLock) {
                if (!prngFixed.Get()) {
                    AesCbcWithIntegrity.PrngFixes.Apply();
                    prngFixed.Set(true);
                }
        }
      }
    }

    private static void GenerateKeyPair (Context context, String alias)
    {
      Calendar start = new GregorianCalendar ();
      Calendar end = new GregorianCalendar ();
      end.Add(CalendarField.Year, 100);
      KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .SetAlias (alias)
                .SetSubject (new X500Principal ("CN=" + alias))
                .SetSerialNumber (BigInteger.One)
                .SetStartDate (start.Time)
                .SetEndDate (end.Time)
                .Build ();
      KeyPairGenerator gen = KeyPairGenerator.GetInstance("RSA", "AndroidKeyStore");
      gen.Initialize(spec);
      gen.GenerateKeyPair();
    }

    public byte [] Wrap (ISecretKey key) {
      cipher.Init(CipherMode.WrapMode, pair.Public);
      return cipher.Wrap(key);
    }

    public ISecretKey Unwrap (byte [] blob) {
      cipher.Init(CipherMode.UnwrapMode, pair.Private);
      return (ISecretKey) cipher.Unwrap(blob, "AES", KeyType.SecretKey);
    }
  }
}

