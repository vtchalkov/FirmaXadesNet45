﻿namespace TestFirmaXades
{
    partial class FrmPrincipal
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.btnFirmar = new System.Windows.Forms.Button();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.rbEnveloping = new System.Windows.Forms.RadioButton();
            this.btnSeleccionarFichero = new System.Windows.Forms.Button();
            this.txtFichero = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.rbEnveloped = new System.Windows.Forms.RadioButton();
            this.rbExternallyDetached = new System.Windows.Forms.RadioButton();
            this.rbInternnallyDetached = new System.Windows.Forms.RadioButton();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.saveFileDialog1 = new System.Windows.Forms.SaveFileDialog();
            this.label2 = new System.Windows.Forms.Label();
            this.txtURLSellado = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.txtOCSP = new System.Windows.Forms.TextBox();
            this.btnXadesT = new System.Windows.Forms.Button();
            this.btnXadesXL = new System.Windows.Forms.Button();
            this.btnGuardarFirma = new System.Windows.Forms.Button();
            this.btnCargarFirma = new System.Windows.Forms.Button();
            this.btnCoFirmar = new System.Windows.Forms.Button();
            this.label4 = new System.Windows.Forms.Label();
            this.txtIdentificadorPolitica = new System.Windows.Forms.TextBox();
            this.label5 = new System.Windows.Forms.Label();
            this.txtHashPolitica = new System.Windows.Forms.TextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.txtURIPolitica = new System.Windows.Forms.TextBox();
            this.btnContraFirma = new System.Windows.Forms.Button();
            this.label7 = new System.Windows.Forms.Label();
            this.cmbAlgoritmo = new System.Windows.Forms.ComboBox();
            this.btnFirmarHuella = new System.Windows.Forms.Button();
            this.folderBrowserDialog1 = new System.Windows.Forms.FolderBrowserDialog();
            this.btnFirmaMavisa = new System.Windows.Forms.Button();
            this.groupBox1.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnFirmar
            // 
            this.btnFirmar.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.btnFirmar.Location = new System.Drawing.Point(21, 514);
            this.btnFirmar.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnFirmar.Name = "btnFirmar";
            this.btnFirmar.Size = new System.Drawing.Size(100, 28);
            this.btnFirmar.TabIndex = 0;
            this.btnFirmar.Text = "Sign";
            this.btnFirmar.UseVisualStyleBackColor = true;
            this.btnFirmar.Click += new System.EventHandler(this.btnFirmar_Click);
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.rbEnveloping);
            this.groupBox1.Controls.Add(this.btnSeleccionarFichero);
            this.groupBox1.Controls.Add(this.txtFichero);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Controls.Add(this.rbEnveloped);
            this.groupBox1.Controls.Add(this.rbExternallyDetached);
            this.groupBox1.Controls.Add(this.rbInternnallyDetached);
            this.groupBox1.Location = new System.Drawing.Point(16, 10);
            this.groupBox1.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Padding = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.groupBox1.Size = new System.Drawing.Size(808, 217);
            this.groupBox1.TabIndex = 1;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Signature properties";
            // 
            // rbEnveloping
            // 
            this.rbEnveloping.AutoSize = true;
            this.rbEnveloping.Location = new System.Drawing.Point(17, 121);
            this.rbEnveloping.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.rbEnveloping.Name = "rbEnveloping";
            this.rbEnveloping.Size = new System.Drawing.Size(99, 21);
            this.rbEnveloping.TabIndex = 6;
            this.rbEnveloping.Text = "Enveloping";
            this.rbEnveloping.UseVisualStyleBackColor = true;
            // 
            // btnSeleccionarFichero
            // 
            this.btnSeleccionarFichero.Location = new System.Drawing.Point(567, 174);
            this.btnSeleccionarFichero.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnSeleccionarFichero.Name = "btnSeleccionarFichero";
            this.btnSeleccionarFichero.Size = new System.Drawing.Size(37, 28);
            this.btnSeleccionarFichero.TabIndex = 5;
            this.btnSeleccionarFichero.Text = "...";
            this.btnSeleccionarFichero.UseVisualStyleBackColor = true;
            this.btnSeleccionarFichero.Click += new System.EventHandler(this.btnSeleccionarFichero_Click);
            // 
            // txtFichero
            // 
            this.txtFichero.Location = new System.Drawing.Point(17, 175);
            this.txtFichero.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtFichero.Name = "txtFichero";
            this.txtFichero.Size = new System.Drawing.Size(548, 22);
            this.txtFichero.TabIndex = 4;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(13, 154);
            this.label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(123, 17);
            this.label1.TabIndex = 3;
            this.label1.Text = "Original document";
            // 
            // rbEnveloped
            // 
            this.rbEnveloped.AutoSize = true;
            this.rbEnveloped.Location = new System.Drawing.Point(17, 92);
            this.rbEnveloped.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.rbEnveloped.Name = "rbEnveloped";
            this.rbEnveloped.Size = new System.Drawing.Size(96, 21);
            this.rbEnveloped.TabIndex = 2;
            this.rbEnveloped.Text = "Enveloped";
            this.rbEnveloped.UseVisualStyleBackColor = true;
            // 
            // rbExternallyDetached
            // 
            this.rbExternallyDetached.AutoSize = true;
            this.rbExternallyDetached.Location = new System.Drawing.Point(17, 63);
            this.rbExternallyDetached.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.rbExternallyDetached.Name = "rbExternallyDetached";
            this.rbExternallyDetached.Size = new System.Drawing.Size(153, 21);
            this.rbExternallyDetached.TabIndex = 1;
            this.rbExternallyDetached.Text = "Externally detached";
            this.rbExternallyDetached.UseVisualStyleBackColor = true;
            // 
            // rbInternnallyDetached
            // 
            this.rbInternnallyDetached.AutoSize = true;
            this.rbInternnallyDetached.Checked = true;
            this.rbInternnallyDetached.Location = new System.Drawing.Point(17, 33);
            this.rbInternnallyDetached.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.rbInternnallyDetached.Name = "rbInternnallyDetached";
            this.rbInternnallyDetached.Size = new System.Drawing.Size(149, 21);
            this.rbInternnallyDetached.TabIndex = 0;
            this.rbInternnallyDetached.TabStop = true;
            this.rbInternnallyDetached.Text = "Internally detached";
            this.rbInternnallyDetached.UseVisualStyleBackColor = true;
            // 
            // saveFileDialog1
            // 
            this.saveFileDialog1.Filter = "XML|*.xml";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(17, 240);
            this.label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(138, 17);
            this.label2.TabIndex = 2;
            this.label2.Text = "TimeStamp authority";
            // 
            // txtURLSellado
            // 
            this.txtURLSellado.Location = new System.Drawing.Point(21, 261);
            this.txtURLSellado.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtURLSellado.Name = "txtURLSellado";
            this.txtURLSellado.Size = new System.Drawing.Size(352, 22);
            this.txtURLSellado.TabIndex = 3;
            this.txtURLSellado.Text = "http://tss.accv.es:8318/tsa";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(399, 240);
            this.label3.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(90, 17);
            this.label3.TabIndex = 4;
            this.label3.Text = "OCSP server";
            // 
            // txtOCSP
            // 
            this.txtOCSP.Location = new System.Drawing.Point(403, 260);
            this.txtOCSP.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtOCSP.Name = "txtOCSP";
            this.txtOCSP.Size = new System.Drawing.Size(417, 22);
            this.txtOCSP.TabIndex = 5;
            this.txtOCSP.Text = "http://ocsp.dnie.es";
            // 
            // btnXadesT
            // 
            this.btnXadesT.Location = new System.Drawing.Point(435, 549);
            this.btnXadesT.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnXadesT.Name = "btnXadesT";
            this.btnXadesT.Size = new System.Drawing.Size(192, 28);
            this.btnXadesT.TabIndex = 6;
            this.btnXadesT.Text = "Add XADES-T";
            this.btnXadesT.UseVisualStyleBackColor = true;
            this.btnXadesT.Click += new System.EventHandler(this.btnXadesT_Click);
            // 
            // btnXadesXL
            // 
            this.btnXadesXL.Location = new System.Drawing.Point(643, 549);
            this.btnXadesXL.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnXadesXL.Name = "btnXadesXL";
            this.btnXadesXL.Size = new System.Drawing.Size(179, 28);
            this.btnXadesXL.TabIndex = 7;
            this.btnXadesXL.Text = "Add XADES-XL";
            this.btnXadesXL.UseVisualStyleBackColor = true;
            this.btnXadesXL.Click += new System.EventHandler(this.btnXadesXL_Click);
            // 
            // btnGuardarFirma
            // 
            this.btnGuardarFirma.Location = new System.Drawing.Point(692, 486);
            this.btnGuardarFirma.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnGuardarFirma.Name = "btnGuardarFirma";
            this.btnGuardarFirma.Size = new System.Drawing.Size(129, 28);
            this.btnGuardarFirma.TabIndex = 8;
            this.btnGuardarFirma.Text = "Save signature";
            this.btnGuardarFirma.UseVisualStyleBackColor = true;
            this.btnGuardarFirma.Click += new System.EventHandler(this.btnGuardarFirma_Click);
            // 
            // btnCargarFirma
            // 
            this.btnCargarFirma.Location = new System.Drawing.Point(692, 448);
            this.btnCargarFirma.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnCargarFirma.Name = "btnCargarFirma";
            this.btnCargarFirma.Size = new System.Drawing.Size(129, 28);
            this.btnCargarFirma.TabIndex = 9;
            this.btnCargarFirma.Text = "Load signature";
            this.btnCargarFirma.UseVisualStyleBackColor = true;
            this.btnCargarFirma.Click += new System.EventHandler(this.btnCargarFirma_Click);
            // 
            // btnCoFirmar
            // 
            this.btnCoFirmar.Location = new System.Drawing.Point(129, 514);
            this.btnCoFirmar.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnCoFirmar.Name = "btnCoFirmar";
            this.btnCoFirmar.Size = new System.Drawing.Size(100, 28);
            this.btnCoFirmar.TabIndex = 10;
            this.btnCoFirmar.Text = "Co-sign";
            this.btnCoFirmar.UseVisualStyleBackColor = true;
            this.btnCoFirmar.Click += new System.EventHandler(this.btnCoFirmar_Click);
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(17, 309);
            this.label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(167, 17);
            this.label4.TabIndex = 11;
            this.label4.Text = "Signature policy identifier";
            // 
            // txtIdentificadorPolitica
            // 
            this.txtIdentificadorPolitica.Location = new System.Drawing.Point(21, 329);
            this.txtIdentificadorPolitica.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtIdentificadorPolitica.Name = "txtIdentificadorPolitica";
            this.txtIdentificadorPolitica.Size = new System.Drawing.Size(312, 22);
            this.txtIdentificadorPolitica.TabIndex = 12;
            this.txtIdentificadorPolitica.Text = "urn:oid:2.16.724.1.3.1.1.2.1.8";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(365, 309);
            this.label5.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(179, 17);
            this.label5.TabIndex = 13;
            this.label5.Text = "Policy hash value (base64)";
            // 
            // txtHashPolitica
            // 
            this.txtHashPolitica.Location = new System.Drawing.Point(369, 327);
            this.txtHashPolitica.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtHashPolitica.Name = "txtHashPolitica";
            this.txtHashPolitica.Size = new System.Drawing.Size(451, 22);
            this.txtHashPolitica.TabIndex = 14;
            this.txtHashPolitica.Text = "V8lVVNGDCPen6VELRD1Ja8HARFk=";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(20, 375);
            this.label6.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(123, 17);
            this.label6.TabIndex = 15;
            this.label6.Text = "Plicy URL (Xades)";
            // 
            // txtURIPolitica
            // 
            this.txtURIPolitica.Location = new System.Drawing.Point(21, 395);
            this.txtURIPolitica.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.txtURIPolitica.Name = "txtURIPolitica";
            this.txtURIPolitica.Size = new System.Drawing.Size(799, 22);
            this.txtURIPolitica.TabIndex = 16;
            this.txtURIPolitica.Text = "http://administracionelectronica.gob.es/es/ctt/politicafirma/politica_firma_AGE_v" +
    "1_8.pdf";
            // 
            // btnContraFirma
            // 
            this.btnContraFirma.Location = new System.Drawing.Point(129, 550);
            this.btnContraFirma.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnContraFirma.Name = "btnContraFirma";
            this.btnContraFirma.Size = new System.Drawing.Size(100, 28);
            this.btnContraFirma.TabIndex = 17;
            this.btnContraFirma.Text = "Counter-sign";
            this.btnContraFirma.UseVisualStyleBackColor = true;
            this.btnContraFirma.Click += new System.EventHandler(this.btnContraFirma_Click);
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(21, 441);
            this.label7.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(131, 17);
            this.label7.TabIndex = 18;
            this.label7.Text = "Signature algorithm";
            // 
            // cmbAlgoritmo
            // 
            this.cmbAlgoritmo.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbAlgoritmo.FormattingEnabled = true;
            this.cmbAlgoritmo.Items.AddRange(new object[] {
            "RSAwithSHA1",
            "RSAwithSHA256",
            "RSAwithSHA512"});
            this.cmbAlgoritmo.Location = new System.Drawing.Point(21, 462);
            this.cmbAlgoritmo.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.cmbAlgoritmo.Name = "cmbAlgoritmo";
            this.cmbAlgoritmo.Size = new System.Drawing.Size(143, 24);
            this.cmbAlgoritmo.TabIndex = 19;
            // 
            // btnFirmarHuella
            // 
            this.btnFirmarHuella.Location = new System.Drawing.Point(21, 550);
            this.btnFirmarHuella.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnFirmarHuella.Name = "btnFirmarHuella";
            this.btnFirmarHuella.Size = new System.Drawing.Size(100, 28);
            this.btnFirmarHuella.TabIndex = 20;
            this.btnFirmarHuella.Text = "Firmar huella";
            this.btnFirmarHuella.UseVisualStyleBackColor = true;
            this.btnFirmarHuella.Click += new System.EventHandler(this.btnFirmarHuella_Click);
            // 
            // folderBrowserDialog1
            // 
            this.folderBrowserDialog1.Description = "Seleccione la carpeta que contiene los documentos PDF";
            // 
            // btnFirmaMavisa
            // 
            this.btnFirmaMavisa.Location = new System.Drawing.Point(237, 514);
            this.btnFirmaMavisa.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.btnFirmaMavisa.Name = "btnFirmaMavisa";
            this.btnFirmaMavisa.Size = new System.Drawing.Size(123, 28);
            this.btnFirmaMavisa.TabIndex = 21;
            this.btnFirmaMavisa.Text = "Mass sign";
            this.btnFirmaMavisa.UseVisualStyleBackColor = true;
            this.btnFirmaMavisa.Click += new System.EventHandler(this.btnFirmaMavisa_Click);
            // 
            // FrmPrincipal
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(844, 592);
            this.Controls.Add(this.btnFirmaMavisa);
            this.Controls.Add(this.btnFirmarHuella);
            this.Controls.Add(this.cmbAlgoritmo);
            this.Controls.Add(this.label7);
            this.Controls.Add(this.btnContraFirma);
            this.Controls.Add(this.txtURIPolitica);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.txtHashPolitica);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.txtIdentificadorPolitica);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.btnCoFirmar);
            this.Controls.Add(this.btnCargarFirma);
            this.Controls.Add(this.btnGuardarFirma);
            this.Controls.Add(this.btnXadesXL);
            this.Controls.Add(this.btnXadesT);
            this.Controls.Add(this.txtOCSP);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.txtURLSellado);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.btnFirmar);
            this.Margin = new System.Windows.Forms.Padding(4, 4, 4, 4);
            this.Name = "FrmPrincipal";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Test firma Xades";
            this.Load += new System.EventHandler(this.FrmPrincipal_Load);
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button btnFirmar;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.RadioButton rbExternallyDetached;
        private System.Windows.Forms.RadioButton rbInternnallyDetached;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.RadioButton rbEnveloped;
        private System.Windows.Forms.Button btnSeleccionarFichero;
        private System.Windows.Forms.TextBox txtFichero;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.SaveFileDialog saveFileDialog1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox txtURLSellado;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox txtOCSP;
        private System.Windows.Forms.Button btnXadesT;
        private System.Windows.Forms.Button btnXadesXL;
        private System.Windows.Forms.Button btnGuardarFirma;
        private System.Windows.Forms.Button btnCargarFirma;
        private System.Windows.Forms.Button btnCoFirmar;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox txtIdentificadorPolitica;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.TextBox txtHashPolitica;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.TextBox txtURIPolitica;
        private System.Windows.Forms.Button btnContraFirma;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.ComboBox cmbAlgoritmo;
        private System.Windows.Forms.Button btnFirmarHuella;
        private System.Windows.Forms.RadioButton rbEnveloping;
        private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog1;
        private System.Windows.Forms.Button btnFirmaMavisa;
    }
}

