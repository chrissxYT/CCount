using Microsoft.VisualBasic;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace CCount
{
    public partial class Form1 : Form
    {
        BigInteger count = 0;

        public Form1()
        {
            InitializeComponent();
        }

        void update_ui()
        {
            label1.Text = count.ToString();
            Invalidate();
            Update();
        }

        void button1_Click(object sender, EventArgs e)
        {
            count++;
            update_ui();
        }

        void button2_Click(object sender, EventArgs e)
        {
            count--;
            update_ui();
        }

        void button4_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog()
            {
                AddExtension = true,
                CheckPathExists = true,
                CheckFileExists = true,
                Multiselect = false,
                Title = "Load counter | CCount",
                Filter = "CCounters|*.ccnt;*.eccnt"
            };
            var res = ofd.ShowDialog();
            if (res == DialogResult.OK || res == DialogResult.Yes)
                LoadCounter(ofd.FileName);
        }

        void LoadCounter(string file)
        {
            ZipArchive zip = ZipFile.Open(file, ZipArchiveMode.Read, Encoding.ASCII);
            bool enc = zip.GetEntry("ENC").read()[0] == 0x01;
            byte[] bytes = zip.GetEntry("COUNT").read();
            byte[] hash = zip.GetEntry("HASH").read();
            byte[] label = zip.GetEntry("LABEL").read();
            if (enc)
            {
                string pw = "";
                while (true)
                {
                    pw = Interaction.InputBox("Please enter your password to decrypt:", "Password for opening encryption | CCount");

                    if (pw == "")
                        return;
                    else if (hash.equals(Hash(pw)))
                        break;
                    else
                        MessageBox.Show("Hash-check failed. Your password seems to be invalid.");
                }
                bytes = Decrypt(bytes, pw);
                label = Decrypt(label, pw);
            }
            count = new BigInteger(bytes);
            textBox1.Text = Encoding.UTF8.GetString(label);
            update_ui();
        }

        void save_counter(string file, bool enc)
        {
            byte[] bytes = count.ToByteArray();
            byte[] hash = new byte[0];
            byte[] label = Encoding.UTF8.GetBytes(textBox1.Text);
            if (enc)
            {
                string pw = Interaction.InputBox("Please enter a password to encrypt with: ", "Password for encryption | CCount");
                bytes = Encrypt(bytes, pw);
                label = Encrypt(label, pw);
                hash = Hash(pw);
            }
            ZipArchive zip = ZipFile.Open(file, ZipArchiveMode.Create, Encoding.ASCII);
            zip.add_entry("ENC", enc ? (byte)0x01 : (byte)0x00, CompressionLevel.Fastest);
            zip.add_entry("COUNT", bytes, CompressionLevel.Optimal);
            zip.add_entry("LABEL", label, CompressionLevel.Optimal);
            zip.add_entry("HASH", hash, CompressionLevel.Optimal);
        }



        byte[] Encrypt(byte[] value, string password)
        {
            byte[] encrypted;
            using (var cipher = new AesManaged())
            {
                PasswordDeriveBytes _passwordBytes = new PasswordDeriveBytes(password, Encoding.ASCII.GetBytes("aselrias38490a32"), "SHA1", 2);
                byte[] keyBytes = _passwordBytes.GetBytes(32);

                cipher.Mode = CipherMode.CBC;

                using (ICryptoTransform encryptor = cipher.CreateEncryptor(keyBytes, Encoding.ASCII.GetBytes("8947az34awl34kjq")))
                    using (MemoryStream to = new MemoryStream())
                        using (CryptoStream writer = new CryptoStream(to, encryptor, CryptoStreamMode.Write))
                        {
                            writer.Write(value, 0, value.Length);
                            writer.FlushFinalBlock();
                            encrypted = to.ToArray();
                        }
                cipher.Clear();
            }
            return encrypted;
        }

        byte[] Decrypt(byte[] value, string password)
        {
            byte[] decrypted;
            int lenght = 0;
            using (var cipher = new AesManaged())
            {
                var _passwordBytes = new PasswordDeriveBytes(password, Encoding.ASCII.GetBytes("aselrias38490a32"), "SHA1", 2);
                var keyBytes = _passwordBytes.GetBytes(32);

                cipher.Mode = CipherMode.CBC;

                using (var decryptor = cipher.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes("8947az34awl34kjq")))
                    using (var reader = new CryptoStream(new MemoryStream(value), decryptor, CryptoStreamMode.Read))
                    {
                        decrypted = new byte[value.Length];
                        lenght = reader.Read(decrypted, 0, decrypted.Length);
                    }

                cipher.Clear();
            }
            byte[] Out = new byte[lenght];
            Array.Copy(decrypted, Out, lenght);
            return Out;
        }

        SHA512Managed sha = new SHA512Managed();

        byte[] Hash(string text) => sha.ComputeHash(Encoding.UTF32.GetBytes(text));

        void button3_Click(object sender, EventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                AddExtension = true,
                CheckPathExists = true,
                Title = "Save counter | CCount",
                Filter = "CCounter|*.ccnt"
            };
            var res = sfd.ShowDialog();
            if (res == DialogResult.OK || res == DialogResult.Yes)
                save_counter(sfd.FileName, false);
        }

        void button5_Click(object sender, EventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog()
            {
                AddExtension = true,
                CheckPathExists = true,
                Title = "Save counter | CCount",
                Filter = "Encrypted CCounter|*.eccnt"
            };
            var res = sfd.ShowDialog();
            if (res == DialogResult.OK || res == DialogResult.Yes)
                save_counter(sfd.FileName, true);
        }

        void txt_click(object sender, EventArgs e)
        {
            bool b = false;
            while (!b)
                b = BigInteger.TryParse(Interaction.InputBox("Set the counter to: ", "Sedd dadd counddaa", label1.Text), out count);
            update_ui();
        }
    }

    static class Util
    {
        public static void add_entry(this ZipArchive z, string n, byte[] cts, CompressionLevel comp)
        {
            Stream s = z.CreateEntry(n, comp).Open();
            s.Write(cts, 0, cts.Length);
            s.Close();
            s.Dispose();
        }

        public static void add_entry(this ZipArchive z, string n, byte ct, CompressionLevel comp)
        {
            Stream s = z.CreateEntry(n, comp).Open();
            s.Write(new byte[] { ct }, 0, 1);
            s.Close();
            s.Dispose();
        }

        public static bool equals(this byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
                return false;
            for (int i = 0; i < left.Length; i++)
                if (left[i] != right[i])
                    return false;
            return true;
        }

        public static byte[] read(this ZipArchiveEntry entry)
        {
            Stream s = entry.Open();
            byte[] b = new byte[32767];
            List<byte> bs = new List<byte>();
            int count = -1;
            while ((count = s.Read(b, 0, b.Length)) > 0)
                bs.AddRange(b);
            s.Close();
            s.Dispose();
            return bs.ToArray();
        }
    }
}
