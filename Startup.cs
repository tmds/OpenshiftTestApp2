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
using RedHat.OpenShift;

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

    public static class OpenShiftWebHostBuilderExtensions
    {
        public static IWebHostBuilder ConfigureOpenShiftCertificate(this IWebHostBuilder builder, string mountPoint)
        {
            if (ContainerEnvironment.IsOpenShift)
            {
                System.Console.WriteLine("Running in OpenShift -> adding cluster ca bundle");
                builder.UseKestrel(kestrelOptions =>
                    kestrelOptions.ConfigureHttpsDefaults(
                        httpsOptions => httpsOptions.ServerCertificate = CertificateLoader.LoadCert(mountPoint)));
            }
            return builder;
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
            System.Console.WriteLine("Startup.ConfigureServices");
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
            System.Console.WriteLine("Startup.Configure");
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
