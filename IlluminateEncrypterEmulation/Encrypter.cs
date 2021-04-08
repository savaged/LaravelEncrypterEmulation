using System.Security.Cryptography;
using System.Text;
using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using System.IO;
using System.Linq;

namespace IlluminateEncrypterEmulation
{
    public class Encrypter
    {
        // TODO try changing this to be the key and cipher
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
            _aes.GenerateIV();
        }

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                throw new ArgumentNullException(nameof(plainText));
            }
            // First encrypt the value
            var value = EncryptStringToBytes_Aes(plainText, _aes.Key, _aes.IV);

            // Calculate a MAC for the encrypted value so that this value
            // can be verified later as not having been changed by the users.
            var mac = Hash(_aes.IV, value);

            var iv = Base64Encode(_aes.IV);

            var json = JsonEncode(Compact(iv, value, mac));

            // TODO serialize option
            return Base64Encode(json);
        }

        public string Decrypt(string encryptedPayload)
        {
            if (string.IsNullOrEmpty(encryptedPayload))
            {
                throw new ArgumentNullException(nameof(encryptedPayload));
            }
            var payload = GetJsonPayload(encryptedPayload);

            var iv = Base64Decode(payload["iv"]); 
            var value = Base64Decode(payload["value"]);

            // TODO serialize option
            return DecryptStringFromBytes_Aes(value, _aes.Key, iv);
        }


        private IDictionary<string, object> GetJsonPayload(string payload)
        {
            var json = Base64DecodeToString(payload);
            var dict = JsonDecode(json);

            if (!ValidPayload(dict))
            {
                throw new InvalidOperationException("The payload is invalid.");
            }
            if (!ValidMac(dict))
            {
                throw new InvalidOperationException("The MAC is invalid.");
            }
            return dict;
        }


        private bool ValidPayload(IDictionary<string, object> dict)
        {
            var fieldsPresent = dict != null &&
                dict.ContainsKey("iv") &&
                dict.ContainsKey("value") &&
                dict.ContainsKey("mac");

            var incomingIvLength = Base64Decode(dict["iv"]).Length;
            var ivLength = _aes.IV.Length;
            var ivMatches = incomingIvLength == ivLength;

            return fieldsPresent && ivMatches;
        }

        private bool ValidMac(IDictionary<string, object> dict)
        {
            var mac = dict["mac"]?.ToString();

            var iv = Base64Decode(dict["iv"]); 
            var value = Base64Decode(dict["value"]);

            var hash = Hash(iv, value);

            return mac == hash;
        }
        

        private IDictionary<string, object> Compact(
            string iv, byte[] value, string mac)
        {
            var package = new Dictionary<string, object>
            {
                { "iv", iv },
                { "value", Convert.ToBase64String(value) },
                { "mac", mac },
            };
            return package;
        }

        private IDictionary<string, object> JsonDecode(string json)
        {
            return JsonConvert
                .DeserializeObject<Dictionary<string, object>>(json);
        }

        private string JsonEncode(IDictionary<string, object> dict)
        {
            return JsonConvert.SerializeObject(dict);
        }

        private byte[] Base64Decode(object o)
        {
            return Convert.FromBase64String(o?.ToString());
        }

        private byte[] Base64Decode(string s)
        {
            return Convert.FromBase64String(s);
        }

        // I hate PHP ;)
        private string Base64DecodeToString(string s)
        {
            var arr = Convert.FromBase64String(s);
            return Encoding.UTF8.GetString(arr);
        }

        private string Base64Encode(string s)
        {
            var arr = Encoding.UTF8.GetBytes(s);
            return Base64Encode(arr);
        }

        private string Base64Encode(byte[] arr)
        {
            return Convert.ToBase64String(arr);
        }


        private string Hash(byte[] iv, byte[] value)
        {
            var combined = Concat(iv, value);
            byte[] hmacSha256;
            using (var hmac = new HMACSHA256(_aes.Key))
            {
                hmacSha256 = hmac.ComputeHash(combined);
            }
            var raw = BitConverter.ToString(hmacSha256);
            var tidied = raw.Replace("-", "").ToLower();
            return tidied;
        }

        private byte[] Concat(byte[] arr1, byte[] arr2)
        {
            return arr1.Concat(arr2).ToArray();
        }


        private static byte[] EncryptStringToBytes_Aes(
            string plainText, byte[] key, byte[] iv)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            byte[] encrypted;

            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

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

        private static string DecryptStringFromBytes_Aes(
            byte[] cipherText, byte[] key, byte[] iv)
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
                aesAlg.Key = key;
                aesAlg.IV = iv;

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
