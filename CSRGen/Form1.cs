using Org.BouncyCastle.Crypto.Tls;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CSRGen
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }


        private void textBox8_TextChanged(object sender, EventArgs e)
        {

        }



        private void button1_Click(object sender, EventArgs e)
        {
            string cn = textBox1.Text;
            string org = textBox2.Text;
            string orgun = textBox3.Text;
            string country = textBox4.Text;
            string state = textBox5.Text;
            string city = textBox6.Text;

            try
            {
                Generator.GenPki(cn, org, orgun, city, state, country);
                progressBar1.Value = Generator.status();
                textBox8.AppendText(Generator.csr());
                textBox9.AppendText(Generator.privKey());
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }

        }

        private void button2_Click(object sender, EventArgs e)
        {
            textBox8.Clear();
            textBox9.Clear();
            progressBar1.Value = 0;
        }
    }
}
