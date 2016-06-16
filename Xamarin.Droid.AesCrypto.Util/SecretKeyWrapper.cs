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
using System.Text;
using Javax.Crypto.Spec;
using Java.Security.Cert;

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
    public const string DefaultHmacAlgorithm = "SHA256withRSA";

    private readonly Cipher cipher;
    private readonly KeyPair pair;
    private readonly Certificate cert;
    private readonly string HmacAlgorithm;

    static readonly AtomicBoolean prngFixed = new AtomicBoolean (false);
    static readonly object prngLock = new object ();

    public SecretKeyWrapper (Context context, String alias)
    {
      FixPrng ();

      this.HmacAlgorithm = DefaultHmacAlgorithm;
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
      cert = entry.Certificate;
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

    public string EncryptedThenMac (AesCbcWithIntegrity.SecretKeys keys) {
      cipher.Init(CipherMode.EncryptMode, pair.Public);
      var cipherText = cipher.DoFinal (Encoding.UTF8.GetBytes(AesCbcWithIntegrity.KeyString (keys)));

      Signature s = Signature.GetInstance (HmacAlgorithm);
      s.InitSign (pair.Private);
      s.Update (cipherText);
      byte [] signature = s.Sign ();


      return string.Format ("{0}:{1}", Convert.ToBase64String (signature), Convert.ToBase64String (cipherText));
    }

    public AesCbcWithIntegrity.SecretKeys CheckMacAndDecrypt (string encryptedForm) {

      string [] separators = { ":"};
      var stuffs = encryptedForm.Split(separators, StringSplitOptions.None);
      var signature = Convert.FromBase64String(stuffs [0]);
      var blob = Convert.FromBase64String (stuffs[1]);

      // prevent padding oracle attack
      Signature s = Signature.GetInstance (HmacAlgorithm);
      s.InitVerify (cert.PublicKey);
      s.Update (blob);
      if (!s.Verify (signature)) {
        throw new GeneralSecurityException ("bad mac");
      }

      cipher.Init(CipherMode.DecryptMode, pair.Private);

      var decrypted = cipher.DoFinal(blob);
      return AesCbcWithIntegrity.Keys (Encoding.UTF8.GetString (decrypted));
    }
  }
}

