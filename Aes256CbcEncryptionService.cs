using System.Security.Cryptography;
using System.IO;
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
                Key = _encoding.GetBytes(key)
            };
        }

		public string Encrypt(string plainText)
		{
			try
			{
                _aes.GenerateIV();

				ICryptoTransform AESEncrypt = _aes.CreateEncryptor(_aes.Key, _aes.IV);
				byte[] buffer = _encoding.GetBytes(plainText);

				var encryptedText = Convert.ToBase64String(AESEncrypt.TransformFinalBlock(buffer, 0, buffer.Length));

				var mac = "";

				mac = BitConverter.ToString(HmacSHA256(Convert.ToBase64String(_aes.IV) + encryptedText)).Replace("-", "").ToLower();

				var keyValues = new Dictionary<string, object>
				{
					{ "iv", Convert.ToBase64String(_aes.IV) },
					{ "value", encryptedText },
					{ "mac", mac },
				};

				return Convert.ToBase64String(_encoding.GetBytes(JsonConvert.SerializeObject(keyValues)));
			}
			catch (Exception e)
			{
			    throw new Exception("Error encrypting: " + e.Message);
			}
		}

		public string Decrypt(string plainText)
		{
			try
			{
                // Base 64 decode
                byte[] base64Decoded = Convert.FromBase64String(plainText);
				var base64DecodedStr = _encoding.GetString(base64Decoded);

				// JSON Decode base64Str
				var payload = JsonConvert.DeserializeObject<Dictionary<string, string>>(base64DecodedStr);

				_aes.IV = Convert.FromBase64String(payload["iv"]);

				ICryptoTransform AESDecrypt = _aes.CreateDecryptor(_aes.Key, _aes.IV);
				byte[] buffer = Convert.FromBase64String(payload["value"]);

				return _encoding.GetString(AESDecrypt.TransformFinalBlock(buffer, 0, buffer.Length));
			}
			catch (Exception e)
			{
			    throw new Exception("Error decrypting: " + e.Message);
			}
		}

		private byte[] HmacSHA256(string data)
		{
			using (var hmac = new HMACSHA256(_aes.Key))
			{
				return hmac.ComputeHash(_encoding.GetBytes(data));
			}
		}
	}
} 