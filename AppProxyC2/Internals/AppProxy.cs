using Microsoft.ApplicationProxy.Common.BootstrapDataModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Threading.Tasks;

// A mess of service contracts, data contracts and other horrible stuff that is needed to support this thing
namespace Microsoft.ApplicationProxy.Common.BootstrapDataModel
{
    [ServiceContract]
    public interface IBootstrapService
    {
        [OperationContract]
        Task<BootstrapResponse> ConnectorBootstrapAsync(BootstrapRequest request);
    }

    [DataContract(Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel")]
    public class BootstrapRequest
    {
        [DataMember]
        public bool InitialBootstrap { get; set; }

        [DataMember]
        public int ConsecutiveFailures { get; set; }

        [DataMember]
        public Guid RequestId { get; set; }

        [DataMember]
        public Guid SubscriptionId { get; set; }

        [DataMember]
        public Guid ConnectorId { get; set; }

        [DataMember]
        public string ConnectorVersion { get; set; }

        [DataMember(IsRequired = false)]
        public string AgentVersion { get; set; }

        [DataMember(IsRequired = false)]
        public string AgentSdkVersion { get; set; }

        [DataMember]
        public string ProxyDataModelVersion { get; set; }

        [DataMember]
        public string BootstrapDataModelVersion { get; set; }

        [DataMember]
        public string UpdaterStatus { get; set; }

        [DataMember]
        public string MachineName { get; set; }

        [DataMember]
        public string OperatingSystemVersion { get; set; }

        [DataMember]
        public string OperatingSystemSKU { get; set; }

        [DataMember]
        public string OperatingSystemLocale { get; set; }

        [DataMember]
        public string OperatingSystemLanguage { get; set; }

        [DataMember]
        public bool UseSpnegoAuthentication { get; set; }

        [DataMember]
        public bool UseServiceBusTcpConnectivityMode { get; set; }

        [DataMember]
        public bool IsProxyPortResponseFallbackDisabledFromRegistry { get; set; }

        [DataMember]
        public string CurrentProxyPortResponseMode { get; set; }

        [DataMember]
        public ConnectorPerformanceMetrics PerformanceMetrics { get; set; }

        [DataMember(IsRequired = false)]
        public string TriggerErrors { get; set; }

        [DataMember(IsRequired = false)]
        public string LatestDotNetVersionInstalled { get; set; }

        [DataMember(IsRequired = false)]
        public IEnumerable<RequestMetrics> FailedRequestMetrics { get; set; }

        [DataMember(IsRequired = false)]
        public IEnumerable<RequestMetrics> SuccessRequestMetrics { get; set; }

        [DataMember(IsRequired = false)]
        public IEnumerable<BootstrapClientAddOnRequest> BootstrapAddOnRequests { get; set; }
    }

    [DataContract]
    public class CertificateData
    {
        [DataMember]
        public string Issuer { get; set; }

        [DataMember]
        public string Thumbprint { get; set; }

        [DataMember]
        public string SubjectName { get; set; }
    }

    [DataContract]
    public class RequestMetrics
    {
        [DataMember]
        public CertificateData RequestServerSslCert { get; set; }

        [DataMember]
        public int ConnectionLimit { get; set; }

        [DataMember]
        public int CurrentConnections { get; set; }

        [DataMember]
        public int ConnectionLeaseTimeout { get; set; }

        [DataMember]
        public string ConnectionAddress { get; set; }

        [DataMember]
        public DateTime TimeCollected { get; set; }
    }

    public class AggregatedCpuData
    {
        public DateTime TimeCollected { get; set; }

        public TimeSpan DataCollectionInterval { get; set; }

        public int MaxCpu { get; set; }

        public int AverageCpu { get; set; }
    }

    [DataContract]
    public class ConnectorPerformanceMetrics
    {
        [DataMember]
        public DateTime TimeGenerated { get; set; }

        [DataMember]
        public long LastBootstrapLatency { get; set; }

        [DataMember]
        public IList<AggregatedCpuData> CpuAggregates { get; set; }

        [DataMember(IsRequired = false)]
        public long? CurrentActiveBackendWebSockets { get; set; }

        [DataMember(IsRequired = false)]
        public int? FaultedServiceBusConnectionCount { get; set; }

        [DataMember(IsRequired = false)]
        public int? FaultedWebSocketConnectionCount { get; set; }

        public ConnectorPerformanceMetrics(IList<AggregatedCpuData> cpuAggregates, long bootstrapLatency, int? faultedServiceBusConnectionCount, int? faultedWebSocketConnectionCount, long? activeBackendWebSockets = null)
        {
            this.TimeGenerated = DateTime.UtcNow;
            this.CpuAggregates = cpuAggregates;
            this.LastBootstrapLatency = bootstrapLatency;
            this.CurrentActiveBackendWebSockets = activeBackendWebSockets;
            this.FaultedServiceBusConnectionCount = faultedServiceBusConnectionCount;
            this.FaultedWebSocketConnectionCount = faultedWebSocketConnectionCount;
        }
    }

    [DataContract]
    public class BootstrapClientAddOnType
    {
        [DataMember]
        public string ProviderId { get; set; }

        [DataMember]
        public string AssemblyQualifiedName { get; set; }
    }

    [DataContract(Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel")]
    public class BootstrapClientAddOnRequest
    {
        [DataMember]
        public string AddOnProviderId { get; set; }

        [DataMember]
        public string PayloadJson { get; set; }

        [DataMember]
        public string ErrorMessage { get; set; }

        [DataMember]
        public IEnumerable<BootstrapClientAddOnType> InstalledAddOnTypes { get; set; }
    }

    public enum ConnectorState
    {
        Ok,
        UpdateRequired,
        InfoServiceMessage,
        ErrorServiceMessage
    }

    [DataContract]
    public class ServiceBusSignalingListenerEndpointSettings : SignalingListenerEndpointSettings
    {
        [DataMember]
        public string Scheme { get; set; }

        [DataMember]
        public string Namespace { get; set; }

        [DataMember]
        public string ServicePath { get; set; }

        [DataMember]
        public string SharedAccessKeyName { get; set; }

        [DataMember]
        public string SharedAccessKey { get; set; }

        [DataMember]
        public string Domain { get; set; }

        [DataMember(IsRequired = false)]
        public bool ReliableSessionEnabled { get; set; }
    }

    [DataContract]
    [KnownType(typeof(ServiceBusSignalingListenerEndpointSettings))]
    public class SignalingListenerEndpointSettings
    {
        [DataMember]
        public string Name { get; set; }

        [DataMember]
        public bool IsAvailable { get; set; }
    }

    [DataContract]
    public class BootstrapClientAddOnSettings
    {
        [DataMember]
        public long MaxBootstrapAddOnRequestsLength { get; set; }
    }

    [DataContract(Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel")]
    public class BootstrapClientAddOnResponse
    {
        [DataMember]
        public string AddOnProviderId { get; set; }

        [DataMember]
        public string PayloadJson { get; set; }

        [DataMember]
        public string ErrorMessage { get; set; }
    }

    [DataContract(Namespace = "http://schemas.datacontract.org/2004/07/Microsoft.ApplicationProxy.Common.SignalerDataModel")]
    public class BootstrapResponse
    {
        [DataMember]
        public ConnectorState ConnectorState { get; set; }

        [DataMember]
        public int MaxFailedBootstrapRequests { get; set; }

        [DataMember]
        public long MaxBootstrapAddOnRequestsLength { get; set; }

        [DataMember]
        public string ServiceMessage { get; set; }

        [DataMember]
        public int PeriodicBootstrapIntervalMilliseconds { get; set; }

        [DataMember(IsRequired = false)]
        public TimeSpan DnsLookupCacheTtl { get; set; }

        [DataMember]
        public int ConfigRequestTimeoutMilliseconds { get; set; }

        [DataMember]
        public int PayloadRequestTimeoutMilliseconds { get; set; }

        [DataMember]
        public int LogicalResponseTimeoutMilliseconds { get; set; }

        [DataMember]
        public int BackendSessionTimeoutMilliseconds { get; set; }

        [DataMember]
        public int ConnectionLimit { get; set; }

        [DataMember]
        public int MaxServicePointIdleTimeMilliseconds { get; set; }

        [DataMember]
        public int DnsRefreshTimeoutMilliseconds { get; set; }

        [DataMember]
        public IEnumerable<SignalingListenerEndpointSettings> SignalingListenerEndpoints { get; set; }

        [DataMember]
        public string ResponseEndpointFormat { get; set; }

        [DataMember]
        public string PayloadEndpointFormat { get; set; }

        [DataMember]
        public string ConfigurationEndpointFormat { get; set; }

        [DataMember]
        public string ErrorEndpointFormat { get; set; }

        [DataMember]
        public string TrustRenewEndpoint { get; set; }

        [DataMember]
        public int CheckForTrustRenewPeriodInMinutes { get; set; }

        [DataMember]
        public int MinutesInTrustLifetimeBeforeRenew { get; set; }

        [DataMember]
        public TimeSpan RelayReceiveTimeout { get; set; }

        [DataMember]
        public int ResponseRetryTotalAttempts { get; set; }

        [DataMember]
        public int ResponseRetryInitialDelayMilliseconds { get; set; }

        [DataMember]
        public int ResponseRetryDelayFactor { get; set; }

        [DataMember(IsRequired = false)]
        public TimeSpan ProxyPortResponseFallbackPeriod { get; set; }

        [DataMember(IsRequired = false)]
        public bool ResponseSigningEnabled { get; set; }

        [DataMember(IsRequired = false)]
        public string Triggers { get; set; }

        [DataMember(IsRequired = false)]
        public string ConnectivitySettings { get; set; }

        [DataMember(IsRequired = false)]
        public BootstrapClientAddOnSettings BootstrapClientAddOnSettings { get; set; }

        [DataMember(IsRequired = false)]
        public string BootstrapEndpointOverride { get; set; }

        [DataMember(IsRequired = false)]
        public IEnumerable<BootstrapClientAddOnResponse> BootstrapAddOnResponses { get; set; }
    }
}

namespace Microsoft.ApplicationProxy.Common.ProxyDataModel
{
    [DataContract(Namespace = "")]
    public enum HttpApiFlow
    {
        [EnumMember(Value = "Passthru")]
        Passthru
    }

    [DataContract(Namespace = "")]
    public enum BackendAuthNMode
    {
        [EnumMember(Value = "None")]
        None,

        [EnumMember(Value = "Iwa")]
        Iwa,

        [EnumMember(Value = "AdfsTrustCertificate")]
        AdfsTrustCertificate,

        [EnumMember(Value = "HeaderBasedAuthentication")]
        HeaderBasedAuthentication
    }

    [DataContract(Namespace = "")]
    public enum AlternateLogin
    {
        [EnumMember(Value = "UPN")]
        UPN,

        [EnumMember(Value = "OnPremUPN")]
        OnPremUPN,

        [EnumMember(Value = "UsernameUPN")]
        UsernameUPN,

        [EnumMember(Value = "UsernameOnPremUPN")]
        UsernameOnPremUPN,

        [EnumMember(Value = "OnPremSAMAccountName")]
        OnPremSAMAccountName
    }

    [DataContract(Namespace = "")]
    public enum BackendCertValidationMode
    {
        [EnumMember(Value = "None")]
        None,

        [EnumMember(Value = "ValidateCertificate")]
        ValidateCertificate
    }

    [DataContract(Namespace = "")]
    public class SubscriptionConfiguration
    {
        [DataMember]
        public Dictionary<string, EndPointConfiguration> Endpoints { get; set; }
    }

    [DataContract(Namespace = "")]
    public class EndPointConfiguration
    {
        [DataMember]
        public string Id { get; set; }

        [DataMember]
        public HttpApiFlow ApiFlow { get; set; }

        [DataMember]
        public BackendAuthNMode BackendAuthNMode { get; set; }

        [DataMember]
        public AlternateLogin AlternateLogin { get; set; }

        [DataMember]
        public BackendCertValidationMode BackendCertValidationMode { get; set; }

        [DataMember]
        public string FrontendUrl { get; set; }

        [DataMember]
        public string BackendUrl { get; set; }

        [DataMember]
        public int InactiveTimeoutSec { get; set; }

        [DataMember]
        public string Spn { get; set; }

        [DataMember]
        public bool IsTranslateHostHeaderInRequestEnabled { get; set; }

        [DataMember]
        public bool IsTranslateHostHeaderInResponseEnabled { get; set; }

        [DataMember]
        public string EncryptedClientSecret { get; set; }

        [DataMember]
        public bool EnableLinkTranslation { get; set; }

        [DataMember]
        public bool IsWildCardApp { get; set; }

        [DataMember]
        public bool EnableHttpOnlyCookie { get; set; }

        [DataMember]
        public bool EnableSecureCookie { get; set; }

        [DataMember]
        public bool IsPersistentCookieEnabled { get; set; }
    }
}

namespace Microsoft.ApplicationProxy.Common.RequestContexts
{
    public interface IRequestContext
    {
        Guid RequestId { get; }

        Guid TransactionId { get; }

        Guid SessionId { get; }

        Guid SubscriptionId { get; }
    }

    [DataContract]
    public class RequestContext : IRequestContext
    {
        public RequestContext()
        {
        }

        public RequestContext(IRequestContext requestContext)
        {
        }

        [DataMember]
        public Guid RequestId { get; set; }

        [DataMember]
        public Guid TransactionId { get; set; }

        [DataMember]
        public Guid SessionId { get; set; }

        [DataMember]
        public Guid SubscriptionId { get; set; }
    }
}

namespace Microsoft.ApplicationProxy.Common.SignalingDataModel
{
    public class TcpSocketAttribute : Attribute
    {
    }

    public class UdpSocketAttribute : Attribute
    {
    }

    public enum ProtocolType
    {
        HTTP,

        [TcpSocket]
        TCP,

        PasswordValidation,
        TrustedParty,
        Connect,
        BackendWebSocket,
        HttpForwardingProxy,

        [UdpSocket]
        UDP
    }

    [DataContract(Namespace = "")]
    public class IdentitityData
    {
        [DataMember]
        public string Upn { get; set; }
    }

    [DataContract(Namespace = "")]
    public class HttpContext : ProtocolContext
    {
        public HttpContext()
        {
            base.TrafficProtocol = ProtocolType.HTTP;
        }

        [DataMember]
        public ulong ConnectionId { get; set; }

        [DataMember]
        public string EndPointConfigurationId { get; set; }

        [DataMember]
        public string RequestUrl { get; set; }

        [DataMember]
        public string RequestRawPathAndQuery { get; set; }

        [DataMember]
        public Version HttpVersion { get; set; }

        [DataMember]
        public string RequestVerb { get; set; }

        [DataMember]
        public Dictionary<string, string> Headers { get; set; }

        [DataMember]
        public IdentitityData IdentitityData { get; set; }
    }

    [DataContract(Namespace = "")]
    [KnownType(typeof(HttpContext))]
    public class ProtocolContext
    {
        [DataMember]
        public ProtocolType TrafficProtocol { get; set; }
    }

    [DataContract(Namespace = "")]
    public class TunnelContext
    {
        [DataMember]
        public string ConfigurationHash { get; set; }

        [DataMember]
        public string CorrelationId { get; set; }

        [DataMember]
        public ProtocolContext ProtocolContext { get; set; }

        [DataMember]
        public bool HasPayload { get; set; }
    }

    [DataContract]
    public class SignalMessage : Microsoft.ApplicationProxy.Common.RequestContexts.RequestContext
    {
        [DataMember]
        public string ReturnHost { get; set; }

        [DataMember]
        public int ReturnPort { get; set; }

        [DataMember(IsRequired = false)]
        public bool OverrideServiceHostEnabled { get; set; }

        [DataMember(IsRequired = false)]
        public string OverridenReturnHost { get; set; }

        [DataMember(IsRequired = false)]
        public int OverridenReturnPort { get; set; }

        [DataMember]
        public TunnelContext TunnelContext { get; set; }

        public SignalMessage(RequestContexts.IRequestContext requestContext) : base(requestContext)
        {
        }

        public SignalMessage(ProtocolContext protocolContext)
        {
            this.TunnelContext = new TunnelContext
            {
                HasPayload = false,
                ProtocolContext = protocolContext
            };
        }
    }

    [DataContract]
    public class SignalResult
    {
        public SignalResult(long ackLatency, Guid connectorId)
        {
            this.AckLatency = ackLatency;
            this.ConnectorId = connectorId;
        }

        [DataMember]
        public long AckLatency { get; private set; }

        [DataMember]
        public Guid ConnectorId { get; private set; }
    }

    [DataContract]
    public class ConnectorIsClosingFault
    {
        [DataMember]
        public string Message { get; set; }
    }

    [ServiceContract]
    public interface IConnectorSignalingService
    {
        [OperationContract]
        [FaultContract(typeof(ConnectorIsClosingFault))]
        Task<SignalResult> SignalConnectorAsync(SignalMessage messageProperties);
    }
}