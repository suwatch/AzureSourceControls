// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.Web.Hosting.SourceControls.Utils
{
    internal static class OAuthV1Utils
    {
        private static readonly Random _random = new Random(unchecked((int)DateTime.Now.Ticks));
        private static readonly DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        public static AuthenticationHeaderValue GetOAuthHeader(
            string clientId,
            string clientSecret,
            HttpMethod method,
            string requestUri,
            string redirectUri = null,
            string token = null,
            string tokenSecret = null,
            string scope = null,
            string verifier = null
        )
        {
            var parameters = new Dictionary<string, string>
            {
                { "oauth_consumer_key", clientId },
                { "oauth_signature_method", "HMAC-SHA1" },
                { "oauth_timestamp", GetUtcTimeStamp() },
                { "oauth_nonce", GetNonce() },
                { "oauth_version", "1.0" },
            };

            // this is only needed on request_token leg
            if (!String.IsNullOrEmpty(redirectUri))
            {
                parameters["oauth_callback"] = UrlEncode(redirectUri);
            }

            // this is only needed on CodePlex request_token leg
            if (!String.IsNullOrEmpty(scope))
            {
                parameters["scope"] = UrlEncode(scope);
            }

            // this is only needed on access_token leg
            if (!String.IsNullOrEmpty(verifier))
            {
                parameters["oauth_verifier"] = UrlEncode(verifier);
            }

            // this is general oauth apis
            if (!String.IsNullOrEmpty(token))
            {
                parameters["oauth_token"] = UrlEncode(token);
            }

            var pp = new Dictionary<string, string>(parameters);
            var queryStrings = System.Web.HttpUtility.ParseQueryString(new Uri(requestUri).Query);
            foreach (var queryKey in queryStrings.AllKeys)
            {
                pp.Add(queryKey, UrlEncode(queryStrings[queryKey]));
            }

            var strb = new StringBuilder();
            foreach (var pair in pp.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
            {
                if (strb.Length != 0)
                {
                    strb.Append('&');
                }

                strb.AppendFormat("{0}={1}", pair.Key, pair.Value);
            }

            string data = String.Format(
                CultureInfo.InvariantCulture,
                "{0}&{1}&{2}",
                method.ToString().ToUpperInvariant(),
                UrlEncode(requestUri.Split('?')[0]),
                UrlEncode(strb.ToString()));

            string key = String.Format(
                CultureInfo.InvariantCulture,
                "{0}&{1}",
                UrlEncode(clientSecret),
                String.IsNullOrEmpty(tokenSecret) ? string.Empty : UrlEncode(tokenSecret));

            HMACSHA1 hmacSha1 = new HMACSHA1();
            hmacSha1.Key = Encoding.ASCII.GetBytes(key);
            byte[] hashBytes = hmacSha1.ComputeHash(Encoding.ASCII.GetBytes(data));

            parameters.Add("oauth_signature", UrlEncode(Convert.ToBase64String(hashBytes)));

            strb = new StringBuilder();
            foreach (KeyValuePair<string, string> pair in parameters)
            {
                if (strb.Length != 0)
                {
                    strb.Append(',');
                }

                strb.AppendFormat("{0}=\"{1}\"", pair.Key, pair.Value);
            }

            return new AuthenticationHeaderValue("OAuth", strb.ToString());
        }

        private static string GetUtcTimeStamp()
        {
            // UNIX time of the current UTC time
            TimeSpan ts = DateTime.UtcNow - _epoch;
            return Convert.ToInt64(ts.TotalSeconds).ToString();
        }

        private static string GetNonce()
        {
            const string UnreservedChars = "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

            var chars = new char[8];
            for (int i = 0; i < 8; ++i)
            {
                chars[i] = UnreservedChars[_random.Next(UnreservedChars.Length)];
            }

            return new string(chars);
        }

        // can't use HttpUtility.UrlEncode(str) since it encodes space to + (expected %20).
        // can't use HttpUtility.UrlPathEncode(str) since it does not encodes / (expected %2F).
        private static string UrlEncode(string str)
        {
            const string UnreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            StringBuilder result = new StringBuilder();
            byte[] data = Encoding.UTF8.GetBytes(str);
            int len = data.Length;

            for (int i = 0; i < len; i++)
            {
                int c = data[i];
                if (c < 0x80 && UnreservedChars.IndexOf((char)c) != -1)
                {
                    result.Append((char)c);
                }
                else
                {
                    result.Append('%' + string.Format("{0:X2}", (int)data[i]));
                }
            }

            return result.ToString();
        }
    }
}
