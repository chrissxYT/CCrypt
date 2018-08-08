using System;
using System.Collections.Generic;
using static System.Console;

namespace CCrypt3
{
    class Program
    {
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
                //compress all the files into zstd
                //encrypt the output with aes-256
            }
            else
            {
                //decrypt
            }
        }

        //PLACEHOLDERS
        //WILL BE REPLACED WITH CCMPR AND CCRYPTO FUNCTIONS
        static byte[] comp(byte[] u) { return new byte[0]; }
        static byte[] decomp(byte[] c) { return new byte[0]; }
        static byte[] enc(byte[] d) { return new byte[0]; }
        static byte[] dec(byte[] e) { return new byte[0]; }
    }
}
