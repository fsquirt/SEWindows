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
            LogLabel = new Label();
            SuspendLayout();
            // 
            // LogLabel
            // 
            LogLabel.AutoSize = true;
            LogLabel.BackColor = Color.Transparent;
            LogLabel.ForeColor = Color.White;
            LogLabel.Location = new Point(12, 9);
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
            ClientSize = new Size(534, 313);
            Controls.Add(LogLabel);
            DoubleBuffered = true;
            Name = "MainForm";
            Text = "SEWindows";
            Load += MainForm_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion
        private Label LogLabel;
    }
}