namespace SEWindows
{
    partial class MainForm
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            titlelabel = new Label();
            LogLabel = new Label();
            SuspendLayout();
            // 
            // titlelabel
            // 
            titlelabel.AutoSize = true;
            titlelabel.BackColor = Color.Transparent;
            titlelabel.Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Bold, GraphicsUnit.Point, 134);
            titlelabel.ForeColor = Color.FromArgb(255, 128, 128);
            titlelabel.Location = new Point(12, 9);
            titlelabel.Name = "titlelabel";
            titlelabel.Size = new Size(221, 17);
            titlelabel.TabIndex = 0;
            titlelabel.Text = "🎭SEWindows正在验证这台计算机🎭";
            // 
            // LogLabel
            // 
            LogLabel.AutoSize = true;
            LogLabel.BackColor = Color.Transparent;
            LogLabel.ForeColor = Color.FromArgb(128, 255, 128);
            LogLabel.Location = new Point(12, 26);
            LogLabel.Name = "LogLabel";
            LogLabel.Size = new Size(80, 17);
            LogLabel.TabIndex = 1;
            LogLabel.Text = "等待日志传入\r\n";
            // 
            // MainForm
            // 
            AutoScaleDimensions = new SizeF(7F, 17F);
            AutoScaleMode = AutoScaleMode.Font;
            BackgroundImage = (Image)resources.GetObject("$this.BackgroundImage");
            BackgroundImageLayout = ImageLayout.Stretch;
            ClientSize = new Size(421, 244);
            Controls.Add(LogLabel);
            Controls.Add(titlelabel);
            DoubleBuffered = true;
            Name = "MainForm";
            Text = "SEWindows";
            Load += MainForm_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label titlelabel;
        private Label LogLabel;
    }
}