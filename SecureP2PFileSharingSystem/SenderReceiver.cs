using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecureP2PFileSharingSystem
{
    public class SenderReceiver
    {
        private static int Port = 5000;
        private static int BufferSize = 4096;
        private static string CertName = "A.pfx";
        private static string CertPassword = "A";
        private static List<X509Certificate2> TrustedCertificates = [];

        public static async Task Main(string[] args)
        {
            TrustedCertificates = Directory.GetFiles(Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "Certificates", "PeersCertificates"), "*.cer")
                .Select(path => new X509Certificate2(path))
                .ToList();

            Task.Run(() => StartListener());
            Console.WriteLine("P2P Node started. Type 'send' to send a file, or 'exit' to quit.");

            while (true)
            {
                Console.Write("> ");
                string? command = Console.ReadLine()?.ToLower();

                if (command == "send")
                    await SendFile();
                else if (command == "exit")
                    break;
            }
        }

        private static async Task StartListener()
        {
            TcpListener listener = new TcpListener(IPAddress.Any, Port);
            listener.Start();
            Console.WriteLine($"Listening for incoming files on port {Port}...");

            while (true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();
                Task.Run(() => ReceiveFile(client));
            }
        }

        private static async Task ReceiveFile(TcpClient client)
        {
            try
            {
                using (client)
                using (NetworkStream netStream = client.GetStream())
                using (SslStream sslStream = new SslStream(netStream, false))
                {
                    string certificatePath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", "Certificates", "MyCertificate", CertName);
                    string certificatePassword = CertPassword;
                    var myCertificate = new X509Certificate2(certificatePath, certificatePassword);

                    await sslStream.AuthenticateAsServerAsync(myCertificate, false, false);

                    using BinaryReader reader = new BinaryReader(sslStream, Encoding.UTF8, leaveOpen: true);
                    using BinaryWriter writer = new BinaryWriter(sslStream, Encoding.UTF8, leaveOpen: true);

                    string fileName = reader.ReadString();
                    long fileSize = reader.ReadInt64();

                    string partPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", fileName + ".part");
                    long existingSize = 0;

                    if (File.Exists(partPath))
                        existingSize = new FileInfo(partPath).Length;

                    writer.Write(existingSize);

                    using FileStream fileStream = new FileStream(partPath, FileMode.Append, FileAccess.Write);
                    byte[] buffer = new byte[BufferSize];
                    long totalReceived = existingSize;
                    int bytesRead;

                    while (totalReceived < fileSize)
                    {
                        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));

                        try
                        {
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
                        Console.Write($"\r   Progress: {100 * totalReceived / fileSize}%");
                    }

                    fileStream.Close();

                    if (totalReceived == fileSize)
                    {
                        string finalPath = Path.Combine(Directory.GetCurrentDirectory(), "..", "..", "..", fileName);
                        File.Move(partPath, finalPath);
                        Console.WriteLine($"\nFile received and saved as: {Path.GetFileName(finalPath)}");
                    }
                    else
                    {
                        Console.WriteLine($"\nConnection lost. Partial file saved as: {Path.GetFileName(partPath)}");
                    }
                }
            }
            catch (IOException)
            {
                Console.WriteLine($"\nConnection lost or timeout occurred. Partial file saved as .part file.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\nReceive error: {ex.Message}");
            }
        }

        private static async Task SendFile()
        {
            Console.Write("Enter receiver IP: ");
            string ip = Console.ReadLine().Trim();

            Console.Write("Enter full path of the file to send: ");
            string path = Console.ReadLine().Trim('"');

            if (!File.Exists(path))
            {
                Console.WriteLine("File not found.");
                return;
            }

            string fileName = Path.GetFileName(path);
            long fileSize = new FileInfo(path).Length;

            try
            {
                using TcpClient client = new TcpClient();
                await client.ConnectAsync(IPAddress.Parse(ip), Port);

                using NetworkStream netStream = client.GetStream();
                using SslStream sslStream = new SslStream(netStream, false, ValidateServerCertificate);

                await sslStream.AuthenticateAsClientAsync("");

                using BinaryWriter writer = new BinaryWriter(sslStream, Encoding.UTF8, leaveOpen: true);
                using BinaryReader reader = new BinaryReader(sslStream, Encoding.UTF8, leaveOpen: true);

                writer.Write(fileName);
                writer.Write(fileSize);

                long resumeOffset = reader.ReadInt64();
                if (resumeOffset != 0)
                    Console.WriteLine($"Resuming from byte {resumeOffset}...");
                else
                    Console.WriteLine($"Sending '{fileName}' ({fileSize} bytes)...");

                using FileStream fileStream = new FileStream(path, FileMode.Open, FileAccess.Read);
                fileStream.Seek(resumeOffset, SeekOrigin.Begin);

                byte[] buffer = new byte[BufferSize];
                int bytesRead;
                long totalSent = resumeOffset;

                while ((bytesRead = await fileStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                {
                    await sslStream.WriteAsync(buffer, 0, bytesRead);
                    totalSent += bytesRead;
                    Console.Write($"\r   Progress: {100 * totalSent / fileSize}%");
                }

                Console.WriteLine("\nFile sent successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            if (cert == null)
                return false;

            var receivedCert = new X509Certificate2(cert);
            bool trusted = TrustedCertificates.Any(trustedCert => trustedCert.Thumbprint == receivedCert.Thumbprint);

            if (!trusted)
                Console.WriteLine("Server certificate is NOT trusted!");

            return trusted;
        }
    }
}
