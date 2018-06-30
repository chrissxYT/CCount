using Microsoft.VisualBasic;
using System;
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

        void UpdateUi()
        {
            label1.Text = count.ToString();
            //297 215
            label1.Location = new Point(130 - label1.Text.Length * 10, 50);
            Invalidate();
            Update();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            count++;
            UpdateUi();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if(count != 0)
                count--;
            UpdateUi();
        }

        private void button4_Click(object sender, EventArgs e)
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
            string dir = TempDir;
            ZipFile.ExtractToDirectory(file, dir);
            bool enc = File.ReadAllBytes(dir + "\\ENC")[0] == 0x01;
            byte[] bytes = File.ReadAllBytes(dir + "\\COUNT");
            byte[] hash = File.ReadAllBytes(dir + "\\HASH");
            byte[] label = File.ReadAllBytes(dir + "\\LABEL");
            if (enc)
            {
                string pw = "";
                bool flag = false;
                while (!flag)
                {
                    pw = Interaction.InputBox("Please enter your password to decrypt:", "Password for opening encryption | CCount");
                    if (!AreEqual(hash, Hash(pw)))
                    {
                        flag = false;
                        MessageBox.Show("Hash-check failed. Your password seems to be invalid.");
                    }
                    else
                        flag = true;
                }
                bytes = Decrypt(bytes, pw);
                label = Decrypt(label, pw);
            }
            count = new BigInteger(bytes);
            textBox1.Text = Encoding.UTF8.GetString(label);
            UpdateUi();
        }

        void SaveCounter(string file, bool enc)
        {
            string dir = TempDir;
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
            File.WriteAllBytes(dir + "\\ENC", new byte[] { (byte)(enc ? 0x01 : 0x00) });
            File.WriteAllBytes(dir + "\\COUNT", bytes);
            File.WriteAllBytes(dir + "\\LABEL", label);
            File.WriteAllBytes(dir + "\\HASH", hash);
            ZipFile.CreateFromDirectory(dir, file);
        }

        bool AreEqual(byte[] one, byte[] two)
        {
            if (one.Length != two.Length)
                return false;
            for (int i = 0; i < one.Length; i++)
                if (one[i] != two[i])
                    return false;
            return true;
        }

        static Random r = new Random();

        static string TempDir
        {
            get
            {
                string s = "C:\\Users";
                while (Directory.Exists(s))
                    s = Path.GetTempPath() + '\\' + r.Next();
                Directory.CreateDirectory(s);
                return s;
            }
        }

        static int _iterations = 2;
        static byte[] vectorBytes = Encoding.ASCII.GetBytes("8947az34awl34kjq");
        static byte[] saltBytes = Encoding.ASCII.GetBytes("aselrias38490a32");

        static byte[] Encrypt(byte[] value, string password)
        {
            byte[] encrypted;
            using (var cipher = new AesManaged())
            {
                PasswordDeriveBytes _passwordBytes = new PasswordDeriveBytes(password, saltBytes, "SHA1", _iterations);
                byte[] keyBytes = _passwordBytes.GetBytes(32);

                cipher.Mode = CipherMode.CBC;

                using (ICryptoTransform encryptor = cipher.CreateEncryptor(keyBytes, vectorBytes))
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

        static byte[] Decrypt(byte[] value, string password)
        {
            byte[] decrypted;
            int lenght = 0;
            using (var cipher = new AesManaged())
            {
                var _passwordBytes = new PasswordDeriveBytes(password, saltBytes, "SHA1", _iterations);
                var keyBytes = _passwordBytes.GetBytes(32);

                cipher.Mode = CipherMode.CBC;

                using (var decryptor = cipher.CreateDecryptor(keyBytes, vectorBytes))
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

        static byte[] Hash(string text)
        {
            return new SHA512Managed().ComputeHash(Encoding.UTF32.GetBytes(text));
        }

        private void button3_Click(object sender, EventArgs e)
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
                SaveCounter(sfd.FileName, false);
        }

        private void button5_Click(object sender, EventArgs e)
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
                SaveCounter(sfd.FileName, true);
        }

        private void label1_Click(object sender, EventArgs e)
        {
            bool flag = false;
            while (!flag)
                flag = BigInteger.TryParse(Interaction.InputBox("Set the counter to: ", "Sedd dadd counddaa", label1.Text), out count);
            UpdateUi();
        }
    }
}
