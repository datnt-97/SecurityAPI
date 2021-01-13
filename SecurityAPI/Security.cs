using Ionic.Zip;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecurityAPI
{
    public interface ISecurity
    {
        void ExportFileEncrypt(string fileName, string password);
    }
    public class Security
    {
        interface IAPI
        {
            string GenarateKey(string file, string passwrord);
            string Encrypt(string txt, string key);
            T EncryptValueObject<T>(T txt, string key);
            string Decrypt(string txt, string key);
            T DecryptValueObject<T>(T txt, string key);

        }
        public class API : IAPI
        {
            public string Decrypt(string txt, string key)
            {
                Crypto crypto = new Crypto(key);
                return crypto.Decrypt(txt);
            }
            public T DecryptValueObject<T>(T txt, string key)
            {
                var obj = JObject.FromObject(txt);
                Crypto crypto = new Crypto(key);
                foreach (JProperty property in obj.Properties())
                {
                    property.Value = crypto.Decrypt(property.Value.ToString());
                }
                return obj.ToObject<T>();
            }

            public string Encrypt(string txt, string key)
            {
                Crypto crypto = new Crypto(key);
                return crypto.Encrypt(txt);
            }

            public T EncryptValueObject<T>(T txt, string key)
            {
                var obj = JObject.FromObject(txt);
                Crypto crypto = new Crypto(key);
                foreach (JProperty property in obj.Properties())
                {
                    property.Value = crypto.Encrypt(property.Value.ToString());
                }
                return obj.ToObject<T>();
            }

            public string GenarateKey(string path, string passwrord)
            {
                Crypto crypto = new Crypto("");
                return crypto.GenarateKeyFile(path, passwrord);
            }

            public T EncryptFromFile<T>(T obj, string fileName, string password)
            {
                Crypto crypto = new Crypto("");
                var app = crypto.GetKeyFormFile(fileName, password);
                return EncryptValueObject<T>(obj, app.Key);
            }
            public T DecryptFromFile<T>(T obj, string fileName, string password)
            {
                Crypto crypto = new Crypto("");
                var app = crypto.GetKeyFormFile(fileName, password);
                return DecryptValueObject<T>(obj, app.Key);
            }

        }
        class Crypto
        {
            //public class Utility
            //{
            //    private static string AppSettingPath { get => "appsetting.json"; }
            //    private static string AppSettingPathZIP { get => "appsetting.zip"; }
            //    static string pathConfig = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, AppSettingPath);
            //    static string pathConfigZip = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, AppSettingPathZIP);
            //    private static string Pwd => "P@ssword2021";
            //    public static AppSetting ReadFileConfig(string pwd = "")
            //    {
            //        try
            //        {
            //            using (ZipFile zip = ZipFile.Read(pathConfigZip))
            //            {
            //                zip.Encryption = EncryptionAlgorithm.WinZipAes256;
            //                zip.Password = !string.IsNullOrEmpty(pwd) ? pwd : Pwd; //password for all files
            //                foreach (ZipEntry e in zip)
            //                {
            //                    if (!e.IsDirectory && Path.GetFileName(e.FileName) == Path.GetFileName(AppSettingPath))
            //                    {
            //                        using (MemoryStream stream = new MemoryStream())
            //                        {
            //                            e.Extract(stream);
            //                            var st = JsonConvert.DeserializeObject<AppSetting>(Encoding.ASCII.GetString(stream.ToArray()));
            //                            File.Delete(pathConfig);
            //                            return st;

            //                        }

            //                    }
            //                }
            //            }

            //        }
            //        catch (Exception e)
            //        {
            //        }
            //        return null;


            //    }
            //    public static Stream GenerateStreamFromString(string s)
            //    {
            //        var stream = new MemoryStream();
            //        var writer = new StreamWriter(stream);
            //        writer.Write(s);
            //        writer.Flush();
            //        stream.Position = 0;
            //        return stream;
            //    }
            //    public static bool UpdateConifg(AppSetting appSetting, string pwd = "")
            //    {
            //        try
            //        {
            //            AppSetting js = null;
            //            if (File.Exists(pathConfigZip))
            //            {
            //                js = ReadFileConfig(pwd);
            //            }

            //            string json = JsonConvert.SerializeObject(appSetting);

            //            if (js != null)
            //            {
            //                var d = JObject.FromObject(js);
            //                var s = JObject.FromObject(appSetting);
            //                s.Merge(d);
            //                json = JsonConvert.SerializeObject(s);
            //            }

            //            File.WriteAllText(pathConfig, json);
            //            using (ZipFile zip = new ZipFile())
            //            {
            //                zip.Encryption = EncryptionAlgorithm.WinZipAes256;
            //                zip.Password = !string.IsNullOrEmpty(pwd) ? pwd : Pwd; //password for all files
            //                //zip.AddFile(pathConfig);
            //                zip.AddEntry(AppSettingPath, GenerateStreamFromString(json));
            //                zip.Save(pathConfigZip);
            //            }
            //            File.Delete(pathConfig);
            //            return true;
            //        }
            //        catch (Exception e)
            //        {
            //            throw e;
            //        }
            //    }
            //}
            private static string AppSettingPath { get => "appsetting.json"; }
            private static string AppSettingPathZIP { get => "appsetting.zip"; }

            public Crypto(string key)
            {
                tripleDES = new TripleDESHelper();
                tripleDES.Key = key;
            }
            private TripleDESHelper tripleDES;
            private class TripleDESHelper
            {
                public string Key { get; set; }

                public string Encrypt(string toEncrypt, bool useHashing = true)
                {
                    try
                    {
                        byte[] keyArray;
                        byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(toEncrypt);

                        //System.Windows.Forms.MessageBox.Show(key);
                        //If hashing use get hashcode regards to your key
                        if (useHashing)
                        {
                            //SHA512CryptoServiceProvider sHA512 = new SHA512CryptoServiceProvider();
                            MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                            keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(Key));
                            //keyArray = sHA512.ComputeHash(UTF8Encoding.UTF8.GetBytes(Key));
                            //Always release the resources and flush data
                            // of the Cryptographic service provide. Best Practice

                            hashmd5.Clear();
                            //sHA512.Clear();
                        }
                        else
                            keyArray = UTF8Encoding.UTF8.GetBytes(Key);

                        TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
                        //set the secret key for the tripleDES algorithm
                        tdes.Key = keyArray;
                        //mode of operation. there are other 4 modes.
                        //We choose ECB(Electronic code Book)
                        tdes.Mode = CipherMode.ECB;
                        //padding mode(if any extra byte added)

                        tdes.Padding = PaddingMode.PKCS7;

                        ICryptoTransform cTransform = tdes.CreateEncryptor();
                        //transform the specified region of bytes array to resultArray
                        byte[] resultArray =
                          cTransform.TransformFinalBlock(toEncryptArray, 0,
                          toEncryptArray.Length);
                        //Release resources held by TripleDes Encryptor
                        tdes.Clear();
                        //Return the encrypted data into unreadable string format
                        return Convert.ToBase64String(resultArray, 0, resultArray.Length);
                    }
                    catch
                    {
                        return string.Empty;
                    }
                }

                public string Decrypt(string cipherString, bool useHashing = true)
                {
                    try
                    {


                        byte[] keyArray;
                        //get the byte code of the string

                        byte[] toEncryptArray = Convert.FromBase64String(cipherString);


                        if (useHashing)
                        {
                            //SHA512CryptoServiceProvider sHA512 = new SHA512CryptoServiceProvider();
                            MD5CryptoServiceProvider hashmd5 = new MD5CryptoServiceProvider();
                            keyArray = hashmd5.ComputeHash(UTF8Encoding.UTF8.GetBytes(Key));
                            //keyArray = sHA512.ComputeHash(UTF8Encoding.UTF8.GetBytes(Key));
                            //Always release the resources and flush data
                            // of the Cryptographic service provide. Best Practice

                            hashmd5.Clear();
                            //sHA512.Clear();
                        }
                        else
                        {
                            //if hashing was not implemented get the byte code of the key
                            keyArray = UTF8Encoding.UTF8.GetBytes(Key);
                        }

                        TripleDESCryptoServiceProvider tdes = new TripleDESCryptoServiceProvider();
                        //set the secret key for the tripleDES algorithm
                        tdes.Key = keyArray;
                        //mode of operation. there are other 4 modes. 
                        //We choose ECB(Electronic code Book)

                        tdes.Mode = CipherMode.ECB;
                        //padding mode(if any extra byte added)
                        tdes.Padding = PaddingMode.PKCS7;

                        ICryptoTransform cTransform = tdes.CreateDecryptor();
                        byte[] resultArray = cTransform.TransformFinalBlock(
                                             toEncryptArray, 0, toEncryptArray.Length);
                        //Release resources held by TripleDes Encryptor                
                        tdes.Clear();
                        //return the Clear decrypted TEXT
                        return UTF8Encoding.UTF8.GetString(resultArray);
                    }
                    catch
                    {
                        return string.Empty;
                    }
                }


            }
            private static string GetKeyString(RSAParameters publicKey)
            {
                var stringWriter = new System.IO.StringWriter();
                var xmlSerializer = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
                xmlSerializer.Serialize(stringWriter, publicKey);
                return stringWriter.ToString();

            }
            private string GenarateKey()
            {
                var cryptoServiceProvider = new RSACryptoServiceProvider(2048); //4069 - Długość klucza
                var privateKey = cryptoServiceProvider.ExportParameters(true); //Generowanie klucza prywatnego
                string privateKeyString = GetKeyString(privateKey);
                return privateKeyString;
            }
            public static Stream GenerateStreamFromString(string s)
            {
                var stream = new MemoryStream();
                var writer = new StreamWriter(stream);
                writer.Write(s);
                writer.Flush();
                stream.Position = 0;
                return stream;
            }
            public string GenarateKeyFile(string path, string password)
            {
                SecurityApp securityApp = new SecurityApp();
                securityApp.Key_File = password;
                securityApp.Key = GenarateKey();

                string json = JsonConvert.SerializeObject(securityApp);
                using (ZipFile zip = new ZipFile())
                {
                    zip.Encryption = EncryptionAlgorithm.WinZipAes256;
                    zip.Password = password; //password for all files
                                             //zip.AddFile(pathConfig);
                    zip.AddEntry(AppSettingPath, GenerateStreamFromString(json));
                    zip.Save(Path.Combine(path, AppSettingPathZIP));
                }
                return Path.Combine(path, AppSettingPathZIP);
            }
            public SecurityApp GetKeyFormFile(string file, string password)
            {
                using (ZipFile zip = ZipFile.Read(file))
                {
                    zip.Encryption = EncryptionAlgorithm.WinZipAes256;
                    zip.Password = password; //password for all files
                    foreach (ZipEntry e in zip)
                    {
                        if (!e.IsDirectory && Path.GetFileName(e.FileName) == Path.GetFileName(AppSettingPath))
                        {
                            using (MemoryStream stream = new MemoryStream())
                            {
                                e.Extract(stream);
                                var st = JsonConvert.DeserializeObject<SecurityApp>(Encoding.ASCII.GetString(stream.ToArray()));
                                return st;
                            }

                        }
                    }
                }
                return null;
            }
            public string Encrypt(string textToEncrypt)
            {
                return tripleDES.Encrypt(textToEncrypt);
            }
            public string Decrypt(string textToDecrypt)
            {
                return tripleDES.Decrypt(textToDecrypt);
            }
        }
    }
}
