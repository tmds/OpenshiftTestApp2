using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using System.Net;
using System.Text;

namespace mvc
{

    public class Program
    {
        public static void Main(string[] args)
        {
            if (OpenShiftEnvironment.IsOpenShift)
            {
                System.Console.WriteLine("Running in OpenShift -> adding cluster ca bundle");
                using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);
                    string[] lines = File.ReadAllLines(OpenShiftPaths.ClusterCABundle);
                    StringBuilder sb = new StringBuilder();
                    foreach (var line in lines)
                    {
                        if (line.StartsWith("-----BEGIN"))
                        {
                            sb.Clear();
                        }
                        sb.AppendLine(line);
                        if (line.StartsWith("-----END"))
                        {
                            string fileName = Path.GetTempFileName();
                            File.WriteAllText(fileName, sb.ToString());
                            System.Console.WriteLine(sb.ToString());
                            store.Add(new X509Certificate2(fileName));
                        }
                    }
                }
            }
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
            .ConfigureOpenShiftCertificate("/var/run/secrets/dotnet/certs")
            .UseStartup<Startup>();        
    }
}
