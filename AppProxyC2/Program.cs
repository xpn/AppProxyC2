using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace C2Bus
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            string SubscriptionID = "";
            string ConnectorID = "";
            string Base64CertPFX = "";
            string PFXPassword = "";

            if (ConfigurationManager.AppSettings["SubscriptionID"] != String.Empty)
            {
                SubscriptionID = ConfigurationManager.AppSettings["SubscriptionID"];
            }

            if (ConfigurationManager.AppSettings["ConnectorID"] != String.Empty)
            {
                ConnectorID = ConfigurationManager.AppSettings["ConnectorID"];
            }

            if (ConfigurationManager.AppSettings["Base64CertPFX"] != String.Empty && ConfigurationManager.AppSettings["PFXPassword"] != String.Empty)
            {
                Base64CertPFX = ConfigurationManager.AppSettings["Base64CertPFX"];
                PFXPassword = ConfigurationManager.AppSettings["PFXPassword"];
            }

            Guid subscriptionId = Guid.Parse(SubscriptionID);
            Guid connectorId = Guid.Parse(ConnectorID);
            byte[] certPFX = Convert.FromBase64String(Base64CertPFX);

            Console.WriteLine("App Proxy ExternalC2 POC by @_xpn_\n");
            Console.WriteLine("[*] Targeting Subscription ID {0}", SubscriptionID);
            Console.WriteLine("[*] Using Connector ID {0}", ConnectorID);

            var appproxyc2 = new AppProxyC2(certPFX, PFXPassword, subscriptionId, connectorId);
            appproxyc2.Start();

            Console.WriteLine("Press [Enter] to exit");
            Console.ReadLine();
        }
    }
}