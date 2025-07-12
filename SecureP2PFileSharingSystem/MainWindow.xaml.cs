using System.Diagnostics;
using System.IO;
using System.Windows;
using Microsoft.Win32;

namespace SecureP2PFileSharingSystem
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            Task.Run(() => SenderReceiver.StartListener(this));
        }

        private void BrowseButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.Title = "Select a file";
                openFileDialog.Filter = "All files (*.*)|*.*";

                if (openFileDialog.ShowDialog() == true)
                    SelectFileTextBox.Text = openFileDialog.FileName;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void SendButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(SelectFileTextBox.Text))
            {
                MessageBox.Show("Please select a file.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (!File.Exists(SelectFileTextBox.Text))
            {
                MessageBox.Show("File not found.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (string.IsNullOrEmpty(IpAddressTextBox.Text))
            {
                MessageBox.Show("Please enter IP address.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            await SenderReceiver.SendFile(SelectFileTextBox.Text, IpAddressTextBox.Text, this);
        }

        private void DownloadCertificateButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(CertificateNameTextBox.Text))
            {
                MessageBox.Show("Please enter certificate name.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (string.IsNullOrEmpty(CertificatePasswordTextBox.Text))
            {
                MessageBox.Show("Please enter certificate password.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            try
            {
                string scriptPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "Scripts", "GenerateCertificate.ps1");

                var startInfo = new ProcessStartInfo()
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -File \"{scriptPath}\" -CertName \"{CertificateNameTextBox.Text}\" -Password \"{CertificatePasswordTextBox.Text}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                var process = new Process { StartInfo = startInfo };
                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (string.IsNullOrEmpty(error))
                {
                    string certificatePath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "Certificates", "MyCertificate", CertificateNameTextBox.Text + "-public.cer");
                    string downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", CertificateNameTextBox.Text + "-public.cer");
                    File.Copy(certificatePath, downloadsPath, overwrite: true);

                    MessageBox.Show("Certificate downloaded successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                else
                    MessageBox.Show(error, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UploadCertificateButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                OpenFileDialog openFileDialog = new OpenFileDialog();
                openFileDialog.Title = "Select a Certificate file";
                openFileDialog.Filter = "Certificate files (*.cer)|*.cer";

                if (openFileDialog.ShowDialog() == true)
                {
                    string certificatePath = openFileDialog.FileName;
                    string certificateName = Path.GetFileName(certificatePath);

                    string destinationFolder = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "Certificates", "PeersCertificates");
                    Directory.CreateDirectory(destinationFolder);

                    string destinationPath = Path.Combine(destinationFolder, certificateName);
                    File.Copy(certificatePath, destinationPath, overwrite: true);

                    MessageBox.Show("Certificate uploaded successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}