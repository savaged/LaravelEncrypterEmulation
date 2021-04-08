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

            var decrypted = encrypter.Decrypt(DB_FIELD);

            Console.WriteLine("Decrypted: {0}", decrypted);


            var encrypted = encrypter.Encrypt("s:6:\"121212\";");
            decrypted = encrypter.Decrypt(encrypted);

            Console.WriteLine("Decrypted: {0}", decrypted);

            Console.ReadLine();
        }
    }
}

