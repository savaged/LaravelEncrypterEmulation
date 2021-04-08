using System;

namespace CryptoEmulator
{
    partial class Program
    {
        static void Main(string[] args)
        {
            var aes256CbcEncryptionService = new LaravelEncryptionEmulator(
                KEY);

            var decrypted = aes256CbcEncryptionService.Decrypt(DB_FIELD);

            Console.WriteLine("Decrypted: {0}", decrypted);


            //var encrypted = aes256CbcEncryptionService.Encrypt("121212");
            //decrypted = aes256CbcEncryptionService.Decrypt(encrypted);

            //Console.WriteLine("Decrypted: {0}", decrypted);

            Console.ReadLine();
        }
    }
}

