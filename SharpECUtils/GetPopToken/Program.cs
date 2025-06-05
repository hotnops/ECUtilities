using Microsoft.Azure.ActiveDirectory.AdsyncManagement.Server;
using Microsoft.Online.Deployment.Client.Framework;
using Microsoft.Online.Deployment.Client.Framework.Utility;
using Microsoft.Online.Deployment.Framework;
using Microsoft.Online.Deployment.PowerShell;
using Microsoft.Online.Deployment.PowerShell.GraphResources;
using Microsoft.Online.Deployment.PowerShell.GraphResources.Models;
using Microsoft.Online.Deployment.PowerShell.Providers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace GetPopToken
{
    internal class Program
    {

        private static X509Certificate2 CreateSelfSignedCertificate(bool useTpmProvider)
        {
            try
            {
                CngKeyCreationParameters cngKeyCreationParameters = new CngKeyCreationParameters();
                cngKeyCreationParameters.KeyCreationOptions = CngKeyCreationOptions.None;
                cngKeyCreationParameters.ExportPolicy = CngExportPolicies.None;
                cngKeyCreationParameters.KeyUsage = CngKeyUsages.Signing;
                if (useTpmProvider)
                {
                    cngKeyCreationParameters.Provider = new CngProvider("Microsoft Platform Crypto Provider");
                }
                else
                {
                    cngKeyCreationParameters.Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;
                    string format = "D:PAI(A;;GR;;;{0})(A;ID;GR;;;SY)";
                    string arg = WindowsIdentity.GetCurrent().User.ToString();
                    string sddlForm = string.Format(CultureInfo.InvariantCulture, format, arg);
                    CryptoKeySecurity cryptoKeySecurity = new CryptoKeySecurity(new CommonSecurityDescriptor(isContainer: false, isDS: false, sddlForm));
                    CngProperty item = new CngProperty("Security Descr", cryptoKeySecurity.GetSecurityDescriptorBinaryForm(), (CngPropertyOptions)4);
                    cngKeyCreationParameters.Parameters.Add(item);
                }

                CngProperty item2 = new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None);
                cngKeyCreationParameters.Parameters.Add(item2);
                string keyName = Guid.NewGuid().ToString();
                CngKey key = CngKey.Create(CngAlgorithm.Rsa, keyName, cngKeyCreationParameters);
                RSA key2 = new RSACng(key);
                CertificateRequest certificateRequest = new CertificateRequest(string.Format("CN={0}", "Entra Connect Sync Provisioning"), key2, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                X509EnhancedKeyUsageExtension item3 = new X509EnhancedKeyUsageExtension(new OidCollection
            {
                new Oid("1.3.6.1.5.5.7.3.2")
            }, critical: false);
                certificateRequest.CertificateExtensions.Add(item3);
                X509KeyUsageExtension item4 = new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: false);
                certificateRequest.CertificateExtensions.Add(item4);
                X509Certificate2 x509Certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMonths(6));
                CertificateUtility.AddCertificate(x509Certificate, StoreLocation.CurrentUser);
                return x509Certificate;
            }
            catch (CryptographicException ex) when (useTpmProvider && (ex.HResult == -2146893776 || ex.HResult == -2146893771))
            {
                throw;
            }
            catch (Exception arg2)
            {
                Tracer.TraceError($"CreateSelfSignedCertificate::Error creating self-signed certificate. UseTpm: {useTpmProvider} Exception : {arg2}");
                throw;
            }
        }

        private static X509Certificate2 CreateSelfSignedCertificateNoTPM()
        {

            X509Certificate2 x509Certificate = CreateSelfSignedCertificate(false);
            //string certificateSHA256HashString = CertificateUtility.GetCertificateSHA256HashString(x509Certificate);
            //Tracer.TraceInformation(1013, string.Format("CreateSelfSignedCertificate:: Created certificate (CertificateThumbprint={0}, CertificateSHA256Hash={1}) with TPM crypto provider.", x509Certificate.Thumbprint, certificateSHA256HashString), Array.Empty<object>());
            return x509Certificate;
        }

        private static Guid ValidateApplicationIdentity(string username)
        {
            Guid result;
            string text;
            if (!AzureAuthenticationProviderFactory.TryParseServicePrincipalCredentials(username, out result, out text))
            {
                throw new InvalidOperationException("Entra Connect Sync is not configured to use Application identity");
            }
            return result;
        }

        private static Guid AddApplicationKey(GraphApplication graphApplication, Guid applicationId, string proof, X509Certificate2 cert)
        {
            KeyCredentialModel keyCredential = new KeyCredentialModel
            {
                Type = "AsymmetricX509Cert",
                Key = cert.GetRawCertData(),
                Usage = "Verify",
                StartDateTime = cert.NotBefore.ToUniversalTime(),
                EndDateTime = cert.NotAfter.ToUniversalTime(),
                DisplayName = "CN=Entra Connect Sync Provisioning"
            };
            return graphApplication.AddKey(applicationId, keyCredential, proof).KeyId.Value;
        }

        public static string GetSha256HashOfCertByIssuedTo(string issuedTo)
        {
            var storeLocations = new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine };
            var storeNames = (StoreName[])Enum.GetValues(typeof(StoreName));

            foreach (var location in storeLocations)
            {
                foreach (var storeName in storeNames)
                {
                    using (var store = new X509Store(storeName, location))
                    {
                        try
                        {
                            store.Open(OpenFlags.ReadOnly);
                            foreach (var cert in store.Certificates)
                            {
                                if (cert.Subject.Equals($"CN={issuedTo}", StringComparison.OrdinalIgnoreCase))
                                {
                                    using (var sha256 = SHA256.Create())
                                    {
                                        byte[] hash = sha256.ComputeHash(cert.GetRawCertData());
                                        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                                    }
                                }
                            }
                        }
                        catch
                        {
                            // Skip inaccessible stores
                            continue;
                        }
                    }
                }
            }

            throw new Exception($"Certificate with Issued To '{issuedTo}' not found.");
        }

        static void Main(string[] args)
        {

            string client_id = args[0];
            string tenant_name = args[1];

            string username = $"{{{client_id}}}@{tenant_name}";
            string password = GetSha256HashOfCertByIssuedTo("Entra Connect Sync Provisioning");

            Guid guid = ValidateApplicationIdentity(username);

            System.Security.SecureString secureString = new System.Security.SecureString();

            foreach (char c in password)
            {
                secureString.AppendChar(c);
            }

            IAzureAuthenticationProvider azureAuthenticationProvider = AzureAuthenticationProviderFactory.CreateAzureAuthenticationProvider(username, secureString, InteractionMode.Desktop);
            ProviderRegistry.Instance.RegisterProvider<IHttpClientProvider, HttpClientProvider>();
            IHttpClient httpClient = ProviderRegistry.Instance.CreateInstance<IHttpClientProvider>(false, Array.Empty<object>()).CreateInstance();

            string proof = azureAuthenticationProvider.GenerateProofOfPossessionToken(guid.ToString());

            string error;
            string token = azureAuthenticationProvider.AcquireServiceToken(AzureService.MSGraph, out error, false);
            Console.WriteLine("POP: " + proof);
            Console.WriteLine("Token: " + token);
        }
    }
}
