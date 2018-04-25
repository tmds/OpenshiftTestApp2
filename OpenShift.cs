namespace RedHat.OpenShift
{
    using System;

    public static class PlatformEnvironment
    {
        public static bool IsOpenShift = !string.IsNullOrEmpty(OpenShiftEnvironment.BuildName);
    }

    public static class OpenShiftEnvironment
    {
        private static string _buildCommit;
        private static string _buildName;
        private static string _buildSource;
        private static string _buildNamespace;
        private static string _buildReference;

        public static string BuildCommit => GetFromEnvironmentVariable("OPENSHIFT_BUILD_COMMIT", ref _buildCommit);
        public static string BuildName => GetFromEnvironmentVariable("OPENSHIFT_BUILD_NAME", ref _buildName);
        public static string BuildSource => GetFromEnvironmentVariable("OPENSHIFT_BUILD_SOURCE", ref _buildSource);
        public static string BuildNamespace => GetFromEnvironmentVariable("OPENSHIFT_BUILD_NAMESPACE", ref _buildNamespace);
        public static string BuildReference => GetFromEnvironmentVariable("OPENSHIFT_BUILD_REFERENCE", ref _buildReference);

        private static string GetFromEnvironmentVariable(string name, ref string cached)
        {
            if (cached == null)
            {
                cached = Environment.GetEnvironmentVariable(name) ?? string.Empty;
            }
            return cached;
        }
    }

    public class OpenShiftIntegrationOptions
    {
        public string CertificateMountPoint { get; set; }
    }
}

namespace Microsoft.AspNetCore.Hosting
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using Microsoft.AspNetCore.Server.Kestrel.Core;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Options;
    using Org.BouncyCastle.Crypto;
    using Org.BouncyCastle.Crypto.Parameters;
    using Org.BouncyCastle.Math;
    using Org.BouncyCastle.OpenSsl;
    using RedHat.OpenShift;

    public static class OpenShiftWebHostBuilderExtensions
    {
        private const string ClusterCABundle = "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt";

        private static bool _setup;

        public static IWebHostBuilder UseOpenShiftIntegration(this IWebHostBuilder builder, Action<OpenShiftIntegrationOptions> configureOptions)
        {
            if (configureOptions == null)
            {
                throw new ArgumentNullException(nameof(configureOptions));
            }

            if (_setup)
            {
                throw new InvalidOperationException($"{nameof(UseOpenShiftIntegration)} was already called.");
            }

            if (PlatformEnvironment.IsOpenShift)
            {
                var openShiftOptions = new OpenShiftIntegrationOptions();
                configureOptions(openShiftOptions);

                string certificateMountPoint = openShiftOptions.CertificateMountPoint;
                bool useHttps = !string.IsNullOrEmpty(certificateMountPoint);

                if (useHttps)
                {
                    builder.UseSetting(WebHostDefaults.ServerUrlsKey, "https://*:8080");
                }

                using (X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser))
                {
                    store.Open(OpenFlags.ReadWrite);

                    List<X509Certificate2> certificates = CertificateLoader.LoadCertificatesFromCABundle(ClusterCABundle);
                    foreach (var cert in certificates)
                    {
                        store.Add(cert);
                    }
                }

                if (useHttps)
                {
                    builder.ConfigureServices(services =>
                    {
                        services.Configure<KestrelServerOptions>(kestrelServerOptions =>
                        {
                            if (!string.IsNullOrEmpty(certificateMountPoint))
                            {
                                kestrelServerOptions.ConfigureHttpsDefaults(httpsOptions =>
                                {
                                    string certificateFile = Path.Combine(certificateMountPoint, "tls.crt");
                                    string keyFile = Path.Combine(certificateMountPoint, "tls.key");
                                    httpsOptions.ServerCertificate = CertificateLoader.LoadCertificateWithKey(certificateFile, keyFile);
                                });
                            }
                        });
                    });
                }
            }

            _setup = true;

            return builder;
        }

        internal static class CertificateLoader
        {
            private const string BeginString = "-----BEGIN ";
            private const string EndString = "-----END ";

            public static List<X509Certificate2> LoadCertificatesFromCABundle(string caBundleFileName)
            {
                var certificates = new List<X509Certificate2>();

                string[] lines = File.ReadAllLines(caBundleFileName);
                StringBuilder sb = new StringBuilder();
                foreach (var line in lines)
                {
                    if (line.StartsWith(BeginString))
                    {
                        sb.Clear();
                    }
                    sb.AppendLine(line);
                    if (line.StartsWith(EndString))
                    {
                        string fileName = Path.GetTempFileName();
                        File.WriteAllText(fileName, sb.ToString());
                        certificates.Add(new X509Certificate2(fileName));
                        File.Delete(fileName);
                    }
                }

                return certificates;
            }

            public static X509Certificate2 LoadCertificateWithKey(string certificateFile, string keyFile)
            {
                var certificate = new X509Certificate2(certificateFile);
                return certificate.CopyWithPrivateKey(ReadPrivateKeyAsRSA(keyFile));
            }

            private static RSA ReadPrivateKeyAsRSA(string keyFile)
            {
                using (var reader = new StreamReader(new MemoryStream(File.ReadAllBytes(keyFile))))
                {
                    var obj = new PemReader(reader).ReadObject();
                    if (obj is AsymmetricCipherKeyPair) {
                        var cipherKey = (AsymmetricCipherKeyPair)obj;
                        obj = cipherKey.Private;
                    }
                    var privKey = (RsaPrivateCrtKeyParameters)obj;
                    return RSA.Create(DotNetUtilities.ToRSAParameters(privKey));
                }
            }

            private static class DotNetUtilities
            {
                /*
                +    // This class was derived from:
                +    // https://github.com/bcgit/bc-csharp/blob/master/crypto/src/security/DotNetUtilities.cs
                +    // License:
                +    // The Bouncy Castle License
                +    // Copyright (c) 2000-2018 The Legion of the Bouncy Castle Inc.
                +    // (https://www.bouncycastle.org)
                +    // Permission is hereby granted, free of charge, to any person obtaining a
                +    // copy of this software and associated documentation files (the "Software"), to deal in the
                +    // Software without restriction, including without limitation the rights to use, copy, modify, merge,
                +    // publish, distribute, sub license, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
                +    // The above copyright notice and this permission notice shall be included
                +    // in all copies or substantial portions of the Software.
                */

                public static RSAParameters ToRSAParameters(RsaPrivateCrtKeyParameters privKey)
                {
                    RSAParameters rp = new RSAParameters();
                    rp.Modulus = privKey.Modulus.ToByteArrayUnsigned();
                    rp.Exponent = privKey.PublicExponent.ToByteArrayUnsigned();
                    rp.P = privKey.P.ToByteArrayUnsigned();
                    rp.Q = privKey.Q.ToByteArrayUnsigned();
                    rp.D = ConvertRSAParametersField(privKey.Exponent, rp.Modulus.Length);
                    rp.DP = ConvertRSAParametersField(privKey.DP, rp.P.Length);
                    rp.DQ = ConvertRSAParametersField(privKey.DQ, rp.Q.Length);
                    rp.InverseQ = ConvertRSAParametersField(privKey.QInv, rp.Q.Length);
                    return rp;
                }

                private static byte[] ConvertRSAParametersField(BigInteger n, int size)
                {
                    byte[] bs = n.ToByteArrayUnsigned();

                    if (bs.Length == size)
                        return bs;

                    if (bs.Length > size)
                        throw new ArgumentException("Specified size too small", "size");

                    byte[] padded = new byte[size];
                    Array.Copy(bs, 0, padded, size - bs.Length, bs.Length);
                    return padded;
                }
            }
        }
    }
}