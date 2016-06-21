using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Text;
using System.Configuration;
using System.Security.Cryptography;
using System.IO;

namespace SSO
{
    static public class WCyberu
    {
        static public bool error { get; set; }
        static private StringBuilder errorDescription = new StringBuilder();

        static public string encoded = string.Empty;
        static public string decoded = string.Empty;
        static private string key;
        static private string iv;

        static string acct = ConfigurationManager.AppSettings.Get("acct");
        static string ssoURL = ConfigurationManager.AppSettings.Get("baseURL");
        static string ouId = ConfigurationManager.AppSettings.Get("ouId");
        static string logoutURL = ConfigurationManager.AppSettings.Get("logoutURL");
        static string timeoutURL = ConfigurationManager.AppSettings.Get("timeoutURL");
        static string errorURL = ConfigurationManager.AppSettings.Get("errorURL");
        static string destURL = ConfigurationManager.AppSettings.Get("destURL");

        static public string GetSecurityToken(string acct, string employeeId, string utc,
          string logout, string timeout, string error, string dest)
        {
            StringBuilder token = new StringBuilder();
            string dateFormat = @"ddd, dd MMM yyyy HH:mm:ss";

            //if (acct == null) return "";
            //if (acct.Length > 0) token.Append("ACCT=" + acct);
            //user identifier is required
            if (employeeId == null) return "";
            if (employeeId.Length > 0) token.Append("empid=").Append(employeeId);

            //append the timestamp, must be UTC
            token.Append(";timestamp=").Append((String.IsNullOrEmpty(utc)) ? DateTime.UtcNow.ToString(dateFormat) : (Convert.ToDateTime(utc).ToString(dateFormat)));

            if (!string.IsNullOrEmpty(error)) token.Append(";ERROR=").Append(error);
            if (!string.IsNullOrEmpty(logout)) token.Append(";LOGOUT=").Append(logout);
            if (!string.IsNullOrEmpty(timeout)) token.Append(";TIMEOUT=").Append(timeout);
            if (!string.IsNullOrEmpty(dest))
                token.Append(";DEST=").Append(dest);


            //get the key and iv
            key = ConfigurationManager.AppSettings.Get("aesKey");
            iv = ConfigurationManager.AppSettings.Get("aesIV");

            Encrypt(token.ToString());
            return encoded;
        }


        #region Encrypt / Decrypt

        static public string Encrypt(string clear)
        {
            error = false;
            UTF8Encoding textConverter = new UTF8Encoding();
            byte[] bToEncrypt = textConverter.GetBytes(clear);

            System.Security.Cryptography.RijndaelManaged aes = new RijndaelManaged();
            aes.Key = HexEncoding.ConvertHexstringToByte(key);
            //aes.GenerateIV();
            aes.IV = HexEncoding.ConvertHexstringToByte(iv);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;
            try
            {
                using (ICryptoTransform encryptor = aes.CreateEncryptor())
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(bToEncrypt, 0, bToEncrypt.Length);
                    cs.FlushFinalBlock();
                    encoded = HexEncoding.BytesToHexString(ms.ToArray());
                    error = false;
                    errorDescription.Length = 0;
                }
            }
            catch (Exception ex)
            {
                errorDescription.AppendFormat("Error: {0}", ex.Message);
                error = true;
            }
            return encoded;
        }

        static public string Decrypt(string clear)
        {
            error = false;
            UTF8Encoding textConverter = new UTF8Encoding();
            byte[] btoDecrypt = HexEncoding.ConvertHexstringToByte(clear);
            byte[] decrypted = null;

            System.Security.Cryptography.RijndaelManaged aes = new RijndaelManaged();
            aes.Key = HexEncoding.ConvertHexstringToByte(key);
            //aes.GenerateIV();
            aes.IV = HexEncoding.ConvertHexstringToByte(iv);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

            try
            {
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                {
                    decrypted = new byte[btoDecrypt.Length];
                    cs.Write(btoDecrypt, 0, btoDecrypt.Length);
                    cs.FlushFinalBlock();
                    decoded = textConverter.GetString(ms.ToArray());
                    error = false;
                    errorDescription.Length = 0;
                }
            }
            catch (Exception ex)
            {
                errorDescription.AppendFormat("Error: {0}", ex.Message);
                error = true;
            }
            return decoded;
        }
        #endregion Encrypt / Decrypt
    }
}