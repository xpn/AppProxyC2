using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace C2Bus
{
    public static class Utils
    {
        public static WebResponse GetResponseWithFailureRetry(this WebRequest request, int retryCount = 20)
        {
            WebResponse response;
            Exception lastException = null;

            for (int i = 0; i < retryCount; i++)
            {
                try
                {
                    response = request.GetResponse();
                    return response;
                }
                catch (Exception e)
                {
                    Thread.Sleep(10000);
                    lastException = e;
                }
            }

            throw lastException;
        }
    }
}