using System;

namespace CryptoEmulator
{
    partial class Program
    {
        static void Main(string[] args)
        {
            var encrypter = new IlluminateEncrypterEmulator(KEY);

            var decrypted = encrypter.Decrypt(DB_FIELD);

            Console.WriteLine("Decrypted: {0}", decrypted);


            var encrypted = encrypter.Encrypt("s:7:\"TP00202\";");
            decrypted = encrypter.Decrypt(encrypted);

            Console.WriteLine("Decrypted: {0}", decrypted);

            Console.ReadLine();
        }
    }
}

