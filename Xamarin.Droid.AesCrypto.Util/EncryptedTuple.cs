using System;
namespace Xamarin.Droid.AesCrypto.Util
{
  public class EncryptedTuple
  {

    public EncryptedTuple (string encryptedText, string encryptedSymmetricKey)
    {
      EncryptedText = encryptedText;
      EncryptedSymmetricKey = encryptedSymmetricKey;
    }

    public string EncryptedText {
      get;
      private set;
    }

    public string EncryptedSymmetricKey {
      get;
      private set;
    }
  }
}

