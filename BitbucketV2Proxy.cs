using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using AzureSourceControls.Utils;

namespace AzureSourceControls
{
    public class BitbucketV2Proxy
    {
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly Func<HttpClient> _httpClientFactory;

        public BitbucketV2Proxy(string clientId, string clientSecret, Func<HttpClient> httpClientFactory = null)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _httpClientFactory = httpClientFactory;
        }

        // https://bitbucket.org/site/oauth2/authorize?client_id={client_id}&scope={scope}&response_type=code&redirect_uri={redirect_uri}
        public string GetOAuthUri(string redirectUri)
        {
            CommonUtils.ValidateNullArgument("redirectUri", redirectUri);

            StringBuilder strb = new StringBuilder();
            strb.Append("https://bitbucket.org/site/oauth2/authorize");
            strb.AppendFormat("?client_id={0}", WebUtility.UrlEncode(_clientId));
            if (!String.IsNullOrEmpty(redirectUri))
            {
                strb.AppendFormat("&redirect_uri={0}", WebUtility.UrlEncode(redirectUri));
            }
            strb.Append("&response_type=code");

            return strb.ToString();
        }

        public async Task<OAuthInfo> Authorize(string callbackUri)
        {
            CommonUtils.ValidateNullArgument("_clientId", _clientId);
            CommonUtils.ValidateNullArgument("_clientSecret", _clientSecret);
            CommonUtils.ValidateNullArgument("callbackUri", callbackUri);

            var queryStrings = HttpUtility.ParseQueryString(new Uri(callbackUri).Query);

            // Check for error
            var message = queryStrings["error_description"] ?? queryStrings["error"];
            if (!String.IsNullOrEmpty(message))
            {
                throw new OAuthException("Bitbucket: " + message, HttpStatusCode.Unauthorized, callbackUri);
            }

            var code = queryStrings["code"];
            if (String.IsNullOrEmpty(code))
            {
                throw new OAuthException("Bitbucket: missing code query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            var redirectUri = new Uri(callbackUri);
            redirectUri = new Uri(redirectUri, redirectUri.AbsolutePath);

            var strb = new StringBuilder();

            strb.AppendFormat("code={0}", WebUtility.UrlEncode(code));
            strb.Append("&grant_type=authorization_code");
            strb.AppendFormat("&redirect_uri={0}", WebUtility.UrlEncode(redirectUri.AbsoluteUri));

            var content = new StringContent(strb.ToString());
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.FormUrlEncodedMediaType);
            using (var client = CreateHttpClient())
            {
                string authInfo = string.Format(CultureInfo.InvariantCulture, "{0}:{1}", _clientId, _clientSecret);
                client.DefaultRequestHeaders.Add("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(authInfo)));
                using (var response = await client.PostAsync("https://bitbucket.org/site/oauth2/access_token", content))
                {
                    var info = await ProcessOAuthResponse("Authorize", response);
                    info.expires_at = DateTime.UtcNow.AddSeconds(info.expires_in);
                    return info;
                }
            }
        }

        public async Task<OAuthInfo> RefreshToken(string refreshToken)
        {
            CommonUtils.ValidateNullArgument("_clientId", _clientId);
            CommonUtils.ValidateNullArgument("_clientSecret", _clientSecret);

            var strb = new StringBuilder();

            strb.AppendFormat("refresh_token={0}", WebUtility.UrlEncode(refreshToken));
            strb.Append("&grant_type=refresh_token");

            var content = new StringContent(strb.ToString());
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.FormUrlEncodedMediaType);
            using (var client = CreateHttpClient())
            {
                string authInfo = string.Format(CultureInfo.InvariantCulture, "{0}:{1}", _clientId, _clientSecret);
                client.DefaultRequestHeaders.Add("Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes(authInfo)));
                using (var response = await client.PostAsync("https://bitbucket.org/site/oauth2/access_token", content))
                {
                    var info = await ProcessOAuthResponse("Authorize", response);
                    info.expires_at = DateTime.UtcNow.AddSeconds(info.expires_in);
                    return info;
                }
            }
        }

        public async Task<List<BitbucketV2Repository>> ListRepositories(string role, string token)
        {
            List<BitbucketV2Repository> repos = new List<BitbucketV2Repository>();
            BitbucketV2Paging<BitbucketV2Repository> result = null;
            string url = string.Format(CultureInfo.InvariantCulture, "https://api.bitbucket.org/2.0/repositories?role={0}", role);

            using (var client = CreateHttpClient(token))
            {
                do
                {
                    using (HttpResponseMessage response = await client.GetAsync(url))
                    {
                        result = await this.ProcessResponse<BitbucketV2Paging<BitbucketV2Repository>>("ListRepositories", response);
                        url = result.next;
                        repos.AddRange(result.values);
                    }
                } while (url != null);
            }

            return repos;
        }

        private HttpClient CreateHttpClient(string accessToken = null)
        {
            HttpClient client = _httpClientFactory != null ? _httpClientFactory() : new HttpClient();
            client.MaxResponseContentBufferSize = 1024 * 1024 * 10;
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(Constants.JsonMediaType));
            if (!client.DefaultRequestHeaders.Contains(Constants.UserAgentHeader))
            {
                client.DefaultRequestHeaders.Add(Constants.UserAgentHeader, Constants.MicrosoftAzure);
            }
            if (!String.IsNullOrEmpty(accessToken))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }
            return client;
        }

        private async Task<T> ProcessResponse<T>(string operation, HttpResponseMessage response)
        {
            string content = await response.ReadContentAsync();
            if (response.IsSuccessStatusCode)
            {
                return JsonUtils.Deserialize<T>(content);
            }

            throw CreateOneDriveException(operation, content, response.StatusCode);
        }

        private static OAuthException CreateOneDriveException(string operation, string content, HttpStatusCode statusCode)
        {
            string message = null;
            if (!String.IsNullOrEmpty(content))
            {
                try
                {
                    var detail = JsonUtils.Deserialize<BitbucketError>(content);
                    if (detail != null && detail.error != null)
                    {
                        if (!String.IsNullOrEmpty(detail.error.message))
                        {
                            message = String.Format("Bitbucket {0}: {1}", operation, detail.error.message);
                        }
                    }
                }
                catch (Exception)
                {
                    // no-op
                }
            }

            if (String.IsNullOrEmpty(message))
            {
                message = String.Format("Bitbucket {0}: ({1}) {2}.", operation, (int)statusCode, statusCode);
            }

            return new OAuthException(message, statusCode, content);
        }

        private async Task<OAuthInfo> ProcessOAuthResponse(string operation, HttpResponseMessage response)
        {
            string content = await response.ReadContentAsync();
            if (response.IsSuccessStatusCode)
            {
                return JsonUtils.Deserialize<OAuthInfo>(content);
            }

            throw CreateOAuthException(operation, content, response.StatusCode);
        }

        private static OAuthException CreateOAuthException(string operation, string content, HttpStatusCode statusCode)
        {
            string message = null;
            if (!String.IsNullOrEmpty(content))
            {
                try
                {
                    var error = JsonUtils.Deserialize<OAuthError>(content);
                    if (error != null)
                    {
                        if (!String.IsNullOrEmpty(error.error_description))
                        {
                            message = String.Format("Bitbucket {0}: {1}", operation, error.error_description);
                        }
                        else if (!String.IsNullOrEmpty(error.error))
                        {
                            message = String.Format("Bitbucket {0}: {1}", operation, error.error);
                        }
                    }
                }
                catch (Exception)
                {
                    // no-op
                }
            }

            if (String.IsNullOrEmpty(message))
            {
                message = String.Format("Bitbucket {0}: ({1}) {2}.", operation, (int)statusCode, statusCode);
            }

            return new OAuthException(message, statusCode, content);
        }
    }

    public class OAuthInfo
    {
        public string access_token { get; set; }
        public string scopes { get; set; }
        public int expires_in { get; set; }
        public string refresh_token { get; set; }
        public string token_type { get; set; }
        public DateTime expires_at { get; set; }
    }

    public class OAuthError
    {
        public string error { get; set; }
        public string error_description { get; set; }
    }

    public class BitbucketError
    {
        public BitbucketErrorDetail error { get; set; }
    }
    public class BitbucketErrorDetail
    {
        public string message { get; set; }
    }

    public class BitbucketV2Paging<T>
    {
        public int page { get; set; }
        public int pagelen { get; set; }
        public int size { get; set; }
        public string next { get; set; }
        public string previous { get; set; }
        public T[] values { get; set; }
    }

    public class BitbucketV2Repository
    {
        public DateTime created_on { get; set; }
        public string description { get; set; }
        public string fork_policy { get; set; }
        public string full_name { get; set; }
        public bool has_issues { get; set; }
        public bool has_wiki { get; set; }
        public bool is_private { get; set; }
        public string language { get; set; }
        public BitbucketV2RepositoryLinks links { get; set; }
        public string name { get; set; }
        public BitbucketV2RepositoryOwner owner { get; set; }
        public string scm { get; set; }
        public long size { get; set; }
        public DateTime updated_on { get; set; }
        public string uuid { get; set; }
    }

    public class BitbucketV2RepositoryOwner
    {
        public string display_name { get; set; }
        public string username { get; set; }
        public string uuid { get; set; }
        public BitbucketV2RepositoryOwnerLinks links { get; set; }
    }

    public class BitbucketV2RepositoryOwnerLinks
    {
        public BitbucketV2RepositoryLink avatar { get; set; }
        public BitbucketV2RepositoryLink html { get; set; }
        public BitbucketV2RepositoryLink self { get; set; }
    }

    public class BitbucketV2RepositoryLinks
    {
        public BitbucketV2RepositoryLink avatar { get; set; }
        public BitbucketV2RepositoryLink[] clone { get; set; }
        public BitbucketV2RepositoryLink commits { get; set; }
        public BitbucketV2RepositoryLink forks { get; set; }
        public BitbucketV2RepositoryLink html { get; set; }
        public BitbucketV2RepositoryLink pullrequests { get; set; }
        public BitbucketV2RepositoryLink self { get; set; }
        public BitbucketV2RepositoryLink watchers { get; set; }
    }

    public class BitbucketV2RepositoryLink
    {
        public string href { get; set; }
        public string name { get; set; }
    }
}
