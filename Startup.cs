using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace mvc
{
    static class CertificateLoader
    {
        public static X509Certificate2 LoadCert(string mountPoint)
        {
            var cert = new X509Certificate2(File.ReadAllBytes(Path.Combine(mountPoint, "tls.crt")));
            System.Console.WriteLine(cert.Issuer);
            var certWithPrivate = addPrivateKey(cert, File.ReadAllBytes(Path.Combine(mountPoint, "tls.key")));
            System.Console.WriteLine(cert.Issuer);
            return certWithPrivate;
        }

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
    public static class OpenShiftEnvironmentExtensions
    {
        public static bool IsOpenShift(IHostingEnvironment environment) => OpenShiftEnvironment.IsOpenShift;
    }

    public static class OpenShiftWebHostBuilderExtensions
    {
        public static IWebHostBuilder ConfigureOpenShiftCertificate(this IWebHostBuilder builder, string mountPoint)
        {
            if (OpenShiftEnvironment.IsOpenShift)
            {
                System.Console.WriteLine("Running in OpenShift -> adding cluster ca bundle");
                builder.UseKestrel(kestrelOptions =>
                    kestrelOptions.ConfigureHttpsDefaults(
                        httpsOptions => httpsOptions.ServerCertificate = CertificateLoader.LoadCert(mountPoint)));
            }
            return builder;
        }
    }

    public static class OpenShiftEnvironment
    {
        private static string _buildCommit;
        private static string _buildName;
        private static string _buildSource;
        private static string _buildNamespace;
        private static string _buildReference;

        public static bool IsOpenShift = !string.IsNullOrEmpty(OpenShiftEnvironment.BuildName);

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

    public static class OpenShiftPaths
    {
        public static string ClusterCABundle => "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt";
        public static string ServiceCertificateFileName = "tls.crt";
        public static string ServiceCertificateKey = "tls.key";
    }

    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });


            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
