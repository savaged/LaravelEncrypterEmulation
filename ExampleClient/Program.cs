/*
 * Add a partial named `Program.partial.cs` with the following contents
namespace ExampleClient
{
    partial class Program
    {
        public const string KEY = "your key here";

        public const string DB_FIELD = "eyJpdiI6ImZVRm1ObFwvd29BUXBBbnVicnNTajB3PT0iLCJ2YWx1ZSI6Ik0wYU9qeU44aUM1YXRQZUZwSGlhVWc9PSIsIm1hYyI6IjQ4ODUwYjAzMzk4OTlkYTllM2U3MGExYjU3OTM5M2UzMzViYTZkMDFjYWE1ZjA0YzRiMGYxNjMxMjEwMzE1ODgifQ==";
    }
}
 */
using IlluminateEncrypterEmulation;
using System;

namespace ExampleClient
{
    partial class Program
    {
        static void Main(string[] args)
        {
            var encrypter = new Encrypter(KEY);

            Console.WriteLine("Encrypt then decrypt same data (TODO: figure out what the value wrapping is about)");
            var encrypted = encrypter.Encrypt("s:6:\"121212\";");
            Console.WriteLine("Encrypted: {0}", encrypted);
            var decrypted = encrypter.Decrypt(encrypted);
            Console.WriteLine("Decrypted: {0}", decrypted);

            Console.WriteLine("Decrypt an earlier instance of this encrypter's output");
            decrypted = encrypter.Decrypt("eyJpdiI6InlWb3k3bHFVU2d2eTBFRWFGQWRmVVE9PSIsInZhbHVlIjoieThYZnFpakFobEg1cnU2NDZmcmVPdz09IiwibWFjIjoiOGUyMjRhNzM2ZmVmYjFmYjVjY2ZlMjU4ZDk3ZWJiNTIwMTcwNzM4NmUyOTFkYTJiNGNiNjNhZTgwMjFlZTY2MiJ9");
            Console.WriteLine("Decrypted: {0}", decrypted);

            Console.WriteLine("Decrypt an instance of the Laravel encrypter's output");
            try
            {
                decrypted = encrypter.Decrypt(DB_FIELD);
            }
            catch (InvalidOperationException)
            {
                Console.WriteLine("An original will not convert because the MAC cannot match.");
            }

            Console.ReadLine();
        }
    }
}

