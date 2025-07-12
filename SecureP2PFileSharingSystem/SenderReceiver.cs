using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;

namespace SecureP2PFileSharingSystem
{
    public class SenderReceiver
    {
        private static int Port = 5000;
        private static int BufferSize = 4096;
        private static List<X509Certificate2> TrustedCertificates = [];

        public static async Task StartListener(MainWindow mainWindow)
        {
            TcpListener listener = new TcpListener(IPAddress.Any, Port);
            listener.Start();

            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                Task.Run(() => ReceiveFile(client, mainWindow));
            }
        }

        private static async Task ReceiveFile(TcpClient client, MainWindow mainWindow)
        {
            try
            {
                using (client)
                using (NetworkStream netStream = client.GetStream())
                using (SslStream sslStream = new SslStream(netStream, false))
                {
                    string certificateName = mainWindow.Dispatcher.Invoke(() => mainWindow.CertificateNameTextBox.Text);
                    string certificatePassword = mainWindow.Dispatcher.Invoke(() => mainWindow.CertificatePasswordTextBox.Text);

                    string certificatePath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "Certificates", "MyCertificate", certificateName + "-public.cer");
                    var myCertificate = new X509Certificate2(certificatePath, certificatePassword);

                    await sslStream.AuthenticateAsServerAsync(myCertificate, false, false);

                    using BinaryReader reader = new BinaryReader(sslStream, Encoding.UTF8, leaveOpen: true);
                    using BinaryWriter writer = new BinaryWriter(sslStream, Encoding.UTF8, leaveOpen: true);

                    string fileName = reader.ReadString();
                    long fileSize = reader.ReadInt64();

                    string partPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", fileName + ".part");
                    long existingSize = 0;

                    if (File.Exists(partPath))
                        existingSize = new FileInfo(partPath).Length;

                    writer.Write(existingSize);

                    mainWindow.Dispatcher.Invoke(() => mainWindow.TransferStatusTextBlock.Text = $"Receiving '{fileName}'");

                    using FileStream fileStream = new FileStream(partPath, FileMode.Append, FileAccess.Write);
                    byte[] buffer = new byte[BufferSize];
                    long totalReceived = existingSize;
                    int bytesRead;

                    while (totalReceived < fileSize)
                    {
                        try
                        {
                            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                            var readTask = sslStream.ReadAsync(buffer, 0, buffer.Length, cts.Token);
                            bytesRead = await readTask;

                            if (bytesRead == 0)
                                break;
                        }
                        catch (OperationCanceledException)
                        {
                            throw new IOException("Timed out waiting for data.");
                        }

                        await fileStream.WriteAsync(buffer, 0, bytesRead);
                        totalReceived += bytesRead;

                        mainWindow.Dispatcher.Invoke(() => mainWindow.TransferProgressTextBlock.Text = $"Progress: {100 * totalReceived / fileSize}%");
                    }

                    fileStream.Close();

                    if (totalReceived == fileSize)
                    {
                        string finalPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", fileName);
                        File.Move(partPath, finalPath);

                        MessageBox.Show($"File received and saved as: {Path.GetFileName(finalPath)}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                        MessageBox.Show($"Connection lost. Partial file saved as: {Path.GetFileName(partPath)}", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (IOException)
            {
                MessageBox.Show("Connection lost or timeout occurred. Partial file saved as .part file.", "Warning", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public static async Task SendFile(string filePath, string ipAddress, MainWindow mainWindow)
        {
            try
            {
                string fileName = Path.GetFileName(filePath);
                long fileSize = new FileInfo(filePath).Length;

                using TcpClient client = new TcpClient();
                await client.ConnectAsync(IPAddress.Parse(ipAddress), Port);

                TrustedCertificates = Directory.GetFiles(Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "Certificates", "PeersCertificates"), "*.cer")
                    .Select(path => new X509Certificate2(path))
                    .ToList();

                using NetworkStream netStream = client.GetStream();
                using SslStream sslStream = new SslStream(netStream, false, ValidateServerCertificate);

                await sslStream.AuthenticateAsClientAsync("");

                using BinaryWriter writer = new BinaryWriter(sslStream, Encoding.UTF8, leaveOpen: true);
                using BinaryReader reader = new BinaryReader(sslStream, Encoding.UTF8, leaveOpen: true);

                writer.Write(fileName);
                writer.Write(fileSize);

                long resumeOffset = reader.ReadInt64();
                if (resumeOffset != 0)
                    mainWindow.Dispatcher.Invoke(() => mainWindow.TransferStatusTextBlock.Text = $"Resuming '{fileName}'");
                else
                    mainWindow.Dispatcher.Invoke(() => mainWindow.TransferStatusTextBlock.Text = $"Sending '{fileName}'");

                using FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
                fileStream.Seek(resumeOffset, SeekOrigin.Begin);

                byte[] buffer = new byte[BufferSize];
                int bytesRead;
                long totalSent = resumeOffset;

                while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await sslStream.WriteAsync(buffer, 0, bytesRead);
                    totalSent += bytesRead;

                    mainWindow.Dispatcher.Invoke(() => mainWindow.TransferProgressTextBlock.Text = $"Progress: {100 * totalSent / fileSize}%");
                }

                MessageBox.Show("File sent successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            if (cert == null)
                return false;

            var receivedCert = new X509Certificate2(cert);
            bool trusted = TrustedCertificates.Any(trustedCert => trustedCert.Thumbprint == receivedCert.Thumbprint);

            if (!trusted)
                MessageBox.Show("Server certificate is not trusted.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);

            return trusted;
        }
    }
}
