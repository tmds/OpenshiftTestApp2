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

namespace mvc
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
            .UseKestrel(
                options =>
                options.Listen(new IPEndPoint(IPAddress.Any, 8080), config =>
                config.UseHttps(LoadCert()))
            )
                .UseStartup<Startup>();

        private static X509Certificate2 LoadCert()
        {
            var cert = new X509Certificate2(File.ReadAllBytes(Path.Combine(BasePath, "tls.crt")));
            System.Console.WriteLine(cert.Issuer);
            var certWithPrivate = addPrivateKey(cert, File.ReadAllBytes(Path.Combine(BasePath, "tls.key")));
            System.Console.WriteLine(cert.Issuer);
            return certWithPrivate;
        }

        private static string BasePath = "/var/run/secrets/dotnet/certs";

        /*
        +    // This class was derived from:
        +    // https://github.com/bcgit/bc-csharp/blob/master/crypto/src/security/DotNetUtilities.cs
        +    // Copyright (c) 2000 - 2017 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
        +    //
        +    // Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
        +    // The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
        +    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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

        private static byte[] ConvertRSAParametersField(Org.BouncyCastle.Math.BigInteger n, int size)
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
        public static X509Certificate2 addPrivateKey(X509Certificate2 cert, byte[] keyData)
        {
            using (var reader = new StreamReader(new MemoryStream(keyData)))
            {
                var obj = new PemReader(reader).ReadObject();
                if (obj is AsymmetricCipherKeyPair) {
                    var cipherKey = (AsymmetricCipherKeyPair)obj;
                    obj = cipherKey.Private;
                }
                var rsaKeyParams = (RsaPrivateCrtKeyParameters)obj;
                var rsaKey = RSA.Create(ToRSAParameters(rsaKeyParams));
                return cert.CopyWithPrivateKey(rsaKey);
            }
        }
    }
}
