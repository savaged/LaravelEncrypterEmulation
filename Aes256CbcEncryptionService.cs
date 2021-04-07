using System.Security.Cryptography;
using System.Text;
using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace CryptoEmulator
{
    public class Aes256CbcEncryptionService
    {
        private static readonly Encoding _encoding = Encoding.UTF8;
        private readonly RijndaelManaged _aes;

        public Aes256CbcEncryptionService(string key)
        {
            _aes = new RijndaelManaged
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
            _aes.GenerateIV();

            ICryptoTransform aesEncrypt =
                _aes.CreateEncryptor(_aes.Key, _aes.IV);
            byte[] buffer = _encoding.GetBytes(plainText);

            var encryptedText = Convert.ToBase64String(
                aesEncrypt.TransformFinalBlock(buffer, 0, buffer.Length));

            var data = Convert.ToBase64String(_aes.IV) + encryptedText;
            byte[] hmacSha256;
            using (var hmac = new HMACSHA256(_aes.Key))
			{
				hmacSha256 = hmac.ComputeHash(_encoding.GetBytes(data));
			}

            var mac = BitConverter.ToString(hmacSha256).Replace("-", "")
                .ToLower();

            var keyValues = new Dictionary<string, object>
                {
                    { "iv", Convert.ToBase64String(_aes.IV) },
                    { "value", encryptedText },
                    { "mac", mac },
                };

            byte[] withMeta = _encoding.GetBytes(
                JsonConvert.SerializeObject(keyValues));

            var value = Convert.ToBase64String(withMeta);
            return value;
        }

        public string Decrypt(string plainText)
        {
            // Base 64 decode
            byte[] base64Decoded = Convert.FromBase64String(plainText);
            var base64DecodedStr = _encoding.GetString(base64Decoded);

            // JSON Decode base64Str
            var payload = 
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    base64DecodedStr);

            _aes.IV = Convert.FromBase64String(payload["iv"]);

            ICryptoTransform aesDecrypt = _aes.CreateDecryptor(
                _aes.Key, _aes.IV);
            byte[] buffer = Convert.FromBase64String(payload["value"]);

            byte[] block = aesDecrypt.TransformFinalBlock(
                buffer, 0, buffer.Length);

            var value = _encoding.GetString(block);
            return value;
        }	

	}
} 