using IlluminateEncrypterEmulation;
using System;

namespace ExampleClient
{
    partial class Program
    {
        static void Main(string[] args)
        {
            var encrypter = new Encrypter(KEY);

            var decrypted = encrypter.Decrypt(DB_FIELD);

            Console.WriteLine("Decrypted: {0}", decrypted);


            var encrypted = encrypter.Encrypt("s:6:\"121212\";");
            decrypted = encrypter.Decrypt(encrypted);

            Console.WriteLine("Decrypted: {0}", decrypted);

            Console.ReadLine();
        }
    }
}

