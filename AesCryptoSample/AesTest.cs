using System;
using Xunit;

using Com.Tozny.Crypto.Android;
using System.Text;

namespace AesCryptoSample
{
  public class AesTest
  {
    public AesTest ()
    {
    }

    [Fact]
    public void TestRoundTrip ()
    {
      var privateKey = AesCbcWithIntegrity.GenerateKey ();
      var mySecretText = "This is my secret";
      var mySecretBytes = Encoding.UTF8.GetBytes (mySecretText);
      var cipherText = AesCbcWithIntegrity.Encrypt (mySecretBytes, privateKey);
      var decryptedBytes = AesCbcWithIntegrity.Decrypt (cipherText, privateKey);
      var decryptedText = Encoding.UTF8.GetString (decryptedBytes);

      System.Diagnostics.Contracts.Contract.Assert (mySecretText == decryptedText, 
                                                    string.Format("Expect {0} but got {1}", mySecretText, decryptedText));
    }
  }
}

