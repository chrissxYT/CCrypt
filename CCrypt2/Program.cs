using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using static System.Console;

namespace CCrypt2
{
    static class Program
    {
        static void Main(string[] args)
        {
            while (args.Length < 3)
                args = ReadLine().split_args();
            Write("Password: ");
            string pw = ReadLine();
            if (args[0].ToUpper().StartsWith("E"))
            {
                string of = args[1];
                if (!of.EndsWith(".ccrypt2"))
                    of += ".ccrypt2";
                string[] ifs = get_ifs(args);
                MemoryStream cs = new MemoryStream();
                ZipArchive cz = new ZipArchive(cs, ZipArchiveMode.Create, true, Encoding.Unicode);
                foreach (string infile in ifs)
                    cz.CreateEntryFromFile(infile, Path.GetFileName(infile), CompressionLevel.Optimal);
                cz.Dispose();
                ZipArchive oz = ZipFile.Open(of, ZipArchiveMode.Create, Encoding.ASCII);
                Stream es = oz.CreateEntry("E", CompressionLevel.Optimal).Open();
                byte[] b = new byte[cs.Length];
                cs.Read(b, 0, b.Length);
                b = enc(b, pw);
                es.Write(b, 0, b.Length);
                cs.Close();
                es.Close();
                Stream vs = oz.CreateEntry("V").Open();
                vs.Write(new byte[] { 2 }, 0, 1);
                vs.Close();
                oz.Dispose();
            }
            else if (args[0].ToUpper().StartsWith("D"))
            {
                string od = args[1];
                string inf = args[2];
                ZipArchive iz = ZipFile.Open(inf, ZipArchiveMode.Read, Encoding.ASCII);
                Stream vs = iz.GetEntry("V").Open();
                int i = -1;
                if ((i = vs.ReadByte()) > 2)
                    throw new Exception($"The CCrypt-file-version {i} is too new for this version of the CCrypt-executable.");
                vs.Close();
                Stream es = iz.GetEntry("E").Open();
                byte[] b = new byte[es.Length];
                es.Read(b, 0, b.Length);
                b = dec(b, pw);
                es.Close();
                MemoryStream cs = new MemoryStream(b, false);
                ZipArchive cz = new ZipArchive(cs, ZipArchiveMode.Read, true, Encoding.Unicode);
                foreach (ZipArchiveEntry e in cz.Entries)
                    e.ExtractToFile(Path.Combine(od, e.Name), true);
                cz.Dispose();
                cs.Close();
            }
            else
                WriteLine("e[ncrypt] {outfile} {params infiles[]} OR d[ecrypt] {outdir} {infile}");
        }

        static string[] split_args(this string s)
        {
            string[] args_raw = s.Split(' ');
            List<string> args = new List<string>();
            bool add = false;
            foreach (string a in args_raw)
                if (add)
                {
                    args[args.Count - 1] += $" {a.Replace("\"", "")}";
                    add = !a.Contains("\"");
                }
                else
                {
                    args.Add(a.Replace("\"", ""));
                    add = a.Contains("\"");
                }
            return args.ToArray();
        }

        static string[] get_ifs(string[] args)
        {
            List<string> ifs = new List<string>();
            for (int i = 2; i < args.Length; i++)
                ifs.Add(args[i]);
            return ifs.ToArray();
        }

        static byte[] enc(byte[] vb, string pw)
        {
            byte[] enc;
            using (AesManaged aes = new AesManaged())
            {
                PasswordDeriveBytes pwb = new PasswordDeriveBytes(pw, Encoding.ASCII.GetBytes("aselrias38490a32"), "SHA1", 2);
                byte[] kb = pwb.GetBytes(32);

                aes.Mode = CipherMode.CBC;

                ICryptoTransform transform = aes.CreateEncryptor(kb, Encoding.ASCII.GetBytes("8947az34awl34kjq"));
                MemoryStream to = new MemoryStream();
                CryptoStream cs = new CryptoStream(to, transform, CryptoStreamMode.Write);

                cs.Write(vb, 0, vb.Length);
                cs.FlushFinalBlock();
                enc = to.ToArray();
            }
            GC.Collect();
            return enc;
        }

        static byte[] dec(byte[] vb, string pw)
        {
            byte[] dec = null;
            byte[] a = null;
            int dbc = 0;

            using (AesManaged aes = new AesManaged())
            {
                PasswordDeriveBytes pwb = new PasswordDeriveBytes(pw, Encoding.ASCII.GetBytes("aselrias38490a32"), "SHA1", 2);
                byte[] kb = pwb.GetBytes(32);

                aes.Mode = CipherMode.CBC;

                ICryptoTransform transform = aes.CreateDecryptor(kb, Encoding.ASCII.GetBytes("8947az34awl34kjq"));
                MemoryStream from = new MemoryStream(vb);
                CryptoStream cs = new CryptoStream(from, transform, CryptoStreamMode.Read);
                dec = new byte[vb.Length];
                dbc = cs.Read(dec, 0, dec.Length);
                a = new byte[dbc];
                Array.Copy(dec, a, dbc);
            }
            GC.Collect();
            return a;
        }
    }
}
