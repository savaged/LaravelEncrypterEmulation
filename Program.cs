using System;

namespace CryptoEmulator
{
    partial class Program
    {
        static void Main(string[] args)
        {
            // The sample text to encrypt and decrypt.
            const string Text = "121212";

            var aes256CbcEncryptionService = new Aes256CbcEncryptionService(Key);
            // Encrypt and decrypt the sample text via the Aes256CbcEncrypter class.
            var encrypted = aes256CbcEncryptionService.Encrypt(Text);
            //var Decrypted = aes256CbcEncryptionService.Decrypt(Encrypted);
            var decrypted = aes256CbcEncryptionService.Decrypt(DB_FIELD);

            Console.WriteLine("Encrypted: {0}", encrypted);
            Console.WriteLine("Decrypted: {0}", decrypted);
            Console.WriteLine("DB field:  {0}", DB_FIELD);

            Console.ReadLine();
        }
    }
}

