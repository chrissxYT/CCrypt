using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using LZ4PCL;
using static System.Console;

namespace CCrypt3
{
    static class Program
    {
        static readonly int DEFAULT_BLOCK_SIZE = 1048576;
        static readonly bool BIG_ENDIAN = !BitConverter.IsLittleEndian;
        static readonly byte[] CCRYPT3_HEADER = new byte[8]
        {
          //C   C   R   Y   P   T   3 <EOT>
            67, 67, 82, 89, 80, 84, 51, 4
        };
        static readonly byte[] IV = new byte[16]
        {
            //FO    CC    OF    FS    ON    OF    AB    IT
            0xF0, 0xCC, 0x0F, 0xF5, 0x00, 0x0F, 0xAB, 0x17,
            //CH    YO    US    OC    CT    HI    SI    S...
            0xC0, 0x00, 0x05, 0x0C, 0xC7, 0x01, 0x51, 0x50
            //yea...serious pseudo random mechanics
        };

        static void Main(string[] args)
        {
            if(ReadKey().Key == ConsoleKey.E)
            {
                Write("Password: ");
                string pw = ReadLine();
                Clear();
                Write("Output file: ");
                string of = ReadLine().Replace("\"", "");
                List<string> ifs = new List<string>();
                WriteLine("Input files:");
                while (true)
                {
                    string s = ReadLine().Replace("\"", "");
                    if (s == "")
                        break;
                    ifs.Add(s);
                }
                FileStream ofs = File.Open(of, FileMode.Create);
                byte[] key = SHA256.Create().ComputeHash(Encoding.Unicode.GetBytes(pw));
                ICryptoTransform aes = new AesManaged().CreateEncryptor(key, IV);
                byte[] bfr = new byte[DEFAULT_BLOCK_SIZE];
                int count = -1;
                ofs.w(CCRYPT3_HEADER);
                ofs.w(bfr.Length);
                foreach(string f in ifs)
                {
                    FileStream s = File.Open(f, FileMode.Open, FileAccess.Read);
                    while ((count = s.Read(bfr, 0, bfr.Length)) > 0)
                    {

                    }
                }
            }
            else
            {
                //decrypt
            }
        }

        static void w(this Stream s, params byte[] b)
        {
            s.Write(b, 0, b.Length);
        }

        static void w(this Stream s, int i)
        {
            byte[] b = BitConverter.GetBytes(i);
            if (BIG_ENDIAN)
                Array.Reverse(b);
            s.Write(b, 0, 4);
        }
    }
}
