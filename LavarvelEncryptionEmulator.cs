﻿using System.Security.Cryptography;
using System.Text;
using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.IO;

namespace CryptoEmulator
{
    public class LaravelEncryptionEmulator
    {
        private readonly AesManaged _aes;

        public LaravelEncryptionEmulator(string key)
        {
            _aes = new AesManaged
            {
                KeySize = 256,
                BlockSize = 128,
                Padding = PaddingMode.PKCS7,
                Mode = CipherMode.CBC,
                Key = Convert.FromBase64String(key)
            };
            _aes.GenerateIV();
        }

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException(nameof(plainText));
            }
            var data = EncryptStringToBytes_Aes(plainText);
            var encryptedText = Convert.ToString(data);

            var mac = GetHashedMac(data);
            var keyValues = new Dictionary<string, object>
            {
                { "iv", Convert.ToBase64String(_aes.IV) },
                { "value", encryptedText },
                { "mac", mac },
            };

            var withMeta = Encoding.UTF8.GetBytes(
                JsonConvert.SerializeObject(keyValues));

            var value = Convert.ToBase64String(withMeta);
            return value;
        }

        public string Decrypt(string cipherText)
        {
            // Base 64 decode
            var base64Decoded = Convert.FromBase64String(cipherText);
            var base64DecodedStr = Encoding.UTF8.GetString(base64Decoded);
            // JSON decode
            var payload = 
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    base64DecodedStr);

            _aes.IV = Convert.FromBase64String(payload["iv"]);
            var data = Convert.FromBase64String(payload["value"]);

            var value = DecryptStringFromBytes_Aes(data);
            return value;
        }


        private string GetHashedMac(byte[] data)
        {
            byte[] hmacSha256;
            using (var hmac = new HMACSHA256(_aes.Key))
            {
                hmacSha256 = hmac.ComputeHash(data);
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
