using System.Security.Cryptography;
using System.Text;
using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.IO;

namespace IlluminateEncrypterEmulation
{
    public class Encrypter
    {
        private readonly AesManaged _aes;

        public Encrypter(string key)
        {
            _aes = new AesManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                Key = Convert.FromBase64String(key)
            };
        }

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException(nameof(plainText));
            }
            _aes.GenerateIV();

            // First encrypt the value
            var value = EncryptStringToBytes_Aes(plainText);

            // Calculate a MAC for the encrypted value so that this value
            // can be verified later as not having been changed by the users.
            var mac = GetHashedMac(value);

            var json = JsonEncode(Compact(_aes.IV, value, mac));

            return Base64Encode(json);
        }

        public string Decrypt(string encrypted)
        {
            if (string.IsNullOrEmpty(encrypted))
            {
                throw new ArgumentNullException(nameof(encrypted));
            }
            var arr = Convert.FromBase64String(encrypted);
            var json = Encoding.UTF8.GetString(arr);
            var package = 
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    json);

            var iv = package["iv"];
            var value = package["value"];

            _aes.IV = Convert.FromBase64String(iv);
            var data = Convert.FromBase64String(value);

            return DecryptStringFromBytes_Aes(data);
        }
        

        private IDictionary<string, string> Compact(
            byte[] iv, byte[] value, string mac)
        {
            var package = new Dictionary<string, string>
            {
                { "iv", Convert.ToBase64String(iv) },
                { "value", Convert.ToBase64String(value) },
                { "mac", mac },
            };
            return package;
        }

        private string JsonEncode(IDictionary<string, string> dict)
        {
            return JsonConvert.SerializeObject(dict);
        }

        private string Base64Encode(string s)
        {
            var arr = Encoding.UTF8.GetBytes(s);
            return Convert.ToBase64String(arr);
        }


        private string GetHashedMac(byte[] value)
        {
            byte[] hmacSha256;
            using (var hmac = new HMACSHA256(_aes.Key))
            {
                hmacSha256 = hmac.ComputeHash(value);
            }
            var raw = BitConverter.ToString(hmacSha256);
            var tidied = raw.Replace("-", "").ToLower();
            return tidied;
        }


        private byte[] EncryptStringToBytes_Aes(string plainText)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            byte[] encrypted;

            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = _aes.Key;
                aesAlg.IV = _aes.IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = 
                    aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(
                        msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(
                            csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

        private string DecryptStringFromBytes_Aes(byte[] cipherText)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }
            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = _aes.Key;
                aesAlg.IV = _aes.IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(
                    aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(
                    cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(
                        msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(
                            csDecrypt))
                        {
                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }

    }
}
