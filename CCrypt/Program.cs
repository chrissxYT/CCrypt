using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            while(args.Length < 3)
                args = Console.ReadLine().Split(' ');
            if (args[0].ToUpper() == "ENC")
                File.WriteAllText(args[1] + ".ccrypt", Cryptography.Encrypt(File.ReadAllBytes(args[1]), args[2]), Encoding.ASCII);
            else if (args[0].ToUpper() == "DEC")
                File.WriteAllBytes(Path.ChangeExtension(args[1], ""), Cryptography.Decrypt(File.ReadAllText(args[1], Encoding.ASCII), args[2]));
            else
                Main(args);
        }
    }

    static class Cryptography
    {
        public static string Encrypt(byte[] value, string password) => Encrypt<AesManaged>(value, password);

        static string Encrypt<T>(byte[] value, string password) where T : SymmetricAlgorithm, new()
        {
            byte[] encrypted;
            string res = null;
            using (T cipher = new T())
            {
                PasswordDeriveBytes _passwordBytes = new PasswordDeriveBytes(password, Encoding.ASCII.GetBytes("aselrias38490a32"), "SHA1", 2);
                byte[] keyBytes = _passwordBytes.GetBytes(32);

                cipher.Mode = CipherMode.CBC;

                ICryptoTransform encryptor = cipher.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes("8947az34awl34kjq"));
                MemoryStream to = new MemoryStream();
                CryptoStream writer = new CryptoStream(to, encryptor, CryptoStreamMode.Write);

                writer.Write(value, 0, value.Length);
                writer.FlushFinalBlock();
                encrypted = to.ToArray();
                res = Convert.ToBase64String(encrypted);
            }
            GC.Collect();
            return res;
        }

        public static byte[] Decrypt(string value, string password) => Decrypt<AesManaged>(value, password);

        static byte[] Decrypt<T>(string value, string password) where T : SymmetricAlgorithm, new()
        {
            byte[] vb = Convert.FromBase64String(value);
            byte[] decrypted = null;
            byte[] a = null;
            int decryptedByteCount = 0;

            using (T cipher = new T())
            {
                PasswordDeriveBytes _passwordBytes = new PasswordDeriveBytes(password, Encoding.ASCII.GetBytes("aselrias38490a32"), "SHA1", 2);
                byte[] keyBytes = _passwordBytes.GetBytes(32);

                cipher.Mode = CipherMode.CBC;

                ICryptoTransform decryptor = cipher.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes("8947az34awl34kjq"));
                MemoryStream from = new MemoryStream(vb);
                CryptoStream reader = new CryptoStream(from, decryptor, CryptoStreamMode.Read);
                decrypted = new byte[vb.Length];
                decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);
                a = new byte[decryptedByteCount];
                Array.Copy(decrypted, a, decryptedByteCount);
            }
            GC.Collect();
            return a;
        }
    }
}
