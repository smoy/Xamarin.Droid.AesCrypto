using System;
namespace Xamarin.Droid.AesCrypto.Util
{
  public class EncryptedTuple
  {

    public EncryptedTuple (string encryptedText, string encryptedSymmetricKey, string encryptedIntegrityKey)
    {
      EncryptedText = encryptedText;
      EncryptedSymmetricKey = encryptedSymmetricKey;
      EncryptedIntegrityKey = encryptedIntegrityKey;
    }

    public string EncryptedText {
      get;
      private set;
    }

    public string EncryptedSymmetricKey {
      get;
      private set;
    }

    public string EncryptedIntegrityKey {
      get;
      private set;
    }
  }
}

