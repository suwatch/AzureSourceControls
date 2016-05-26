using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Web.Hosting.SourceControls.Utils;

namespace Microsoft.Web.Hosting.SourceControls
{
    public class BitbucketV2Proxy
    {
        private const string ApiBaseUrl = " https://api.bitbucket.org/2.0";
        private const string APiV1BaseUrl = "https://api.bitbucket.org/1.0";
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
        public string GetOAuthUri(string state = null, string redirectUri = null)
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
            if (!String.IsNullOrEmpty(state))
            {
                strb.AppendFormat("&state={0}", WebUtility.UrlEncode(state ?? String.Empty));
            }

            return strb.ToString();
        }

        public async Task<OAuthInfo> Authorize(string callbackUri, Action<string> validateState = null)
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

            if (validateState != null)
            {
                validateState(queryStrings["state"]);
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

        public async Task<BitbucketProxy.BitbucketAccountInfo> GetAccoutInfo(string accessToken)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            var userEndpoint = string.Format(CultureInfo.InvariantCulture, "{0}/user", ApiBaseUrl);
            using (var client = CreateHttpClient(accessToken))
            using (var accountResponse = await client.GetAsync(userEndpoint))
            {
                BitbucketProxy.BitbucketAccountInfo account = await this.ProcessResponse<BitbucketProxy.BitbucketAccountInfo>("GetAccoutInfo", accountResponse);

                // v2 api mising firstname and last name
                // BUG: https://bitbucket.org/site/master/issues/12735/missing-firstname-lastname-from-v2-user
                if (string.IsNullOrWhiteSpace(account.first_name) && string.IsNullOrWhiteSpace(account.last_name))
                {
                    string[] names = account.display_name.Split(' ');
                    if (names != null && names.Length == 2)
                    {
                        account.first_name = names[0];
                        account.last_name = names[1];
                    }
                    else
                    {
                        account.first_name = account.display_name;
                        account.last_name = account.display_name;
                    }
                }

                return account;
            }
        }

        public async Task<List<BitbucketProxy.BitbucketRepoInfo>> ListRepositories(string accessToken, string role = "admin")
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("role", role);

            List<BitbucketV2Repository> repos = new List<BitbucketV2Repository>();
            string requestUri = string.Format(CultureInfo.InvariantCulture, "https://api.bitbucket.org/2.0/repositories?role={0}", role);
            using (var client = CreateHttpClient(accessToken))
            {
                do
                {
                    using (var response = await client.GetAsync(requestUri))
                    {
                        var result = await this.ProcessResponse<BitbucketV2Paging<BitbucketV2Repository>>("ListRepositories", response);
                        requestUri = result.next;
                        repos.AddRange(result.values);
                    }
                } while (requestUri != null);
            }

            return repos.Select(r => r.ToRepoInfo()).ToList();
        }

        public async Task<BitbucketProxy.BitbucketRepoInfo> GetRepository(string repoUrl, string accessToken)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);

            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl);
            using (var client = CreateHttpClient(accessToken))
            using (var response = await client.GetAsync(requestUri))
            {
                return (await this.ProcessResponse<BitbucketV2Repository>("GetRepository", response)).ToRepoInfo();
            }
        }

        public async Task<BitbucketProxy.BitbucketBranchInfo[]> ListBranches(string repoUrl, string accessToken)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "refs", "branches");
            using (var client = CreateHttpClient(accessToken))
            {
                List<BitbucketV2Branch> branchResults = await ListPagingItems<BitbucketV2Branch>(client, requestUri, "ListBranches");
                return branchResults.Select(v => v.ToBranchInfo()).ToArray();
            }
        }

        public async Task<StreamContent> DownloadFile(string repoUrl, string path, string accessToken, string branch = "master")
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("path", path);
            CommonUtils.ValidateNullArgument("branch", branch);

            // Missing v2 api to get file content
            // BUG: https://bitbucket.org/site/master/issues/12741/missing-v2-api-to-get-file-content
            var requestUri = String.Format("{0}/{1}/{2}", BitbucketProxyHelper.GetRequestUri(APiV1BaseUrl, repoUrl, "raw"), branch, path);
            using (var client = CreateHttpClient(accessToken))
            using (var response = await client.GetAsync(requestUri))
            {
                if (response.IsSuccessStatusCode)
                {
                    return (StreamContent)response.Content;
                }

                throw CreateOAuthException("DownloadFile", await response.Content.ReadAsStringAsync(), response.StatusCode);
            }
        }

        public async Task AddWebHook(string repoUrl, string accessToken, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);

            var hook = await GetWebHookInfo(repoUrl, accessToken, hookUrl);
            if (hook != null)
            {
                if (string.Equals(hookUrl, hook.url, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                hook.url = hookUrl;
                var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "hooks", hook.uuid);
                using (var client = CreateHttpClient(accessToken))
                using (var response = await client.PutAsJsonAsync(requestUri, hook))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        throw CreateOAuthException("UpdateWebHook", await response.Content.ReadAsStringAsync(), response.StatusCode);
                    }
                }
            }
            else
            {
                hook = new BitbucketV2WebHook();
                hook.active = true;
                hook.description = "Azure Webhook";
                hook.events = new string[] { "repo:push" };
                hook.url = hookUrl;

                var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "hooks");
                using (var client = CreateHttpClient(accessToken))
                using (var response = await client.PostAsJsonAsync(requestUri, hook))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        throw CreateOAuthException("AddWebHook", await response.Content.ReadAsStringAsync(), response.StatusCode);
                    }
                }
            }
        }

        public async Task<bool> RemoveWebHook(string repoUrl, string accessToken, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);

            var hook = await GetWebHookInfo(repoUrl, accessToken, hookUrl);
            if (hook != null)
            {
                var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "hooks", hook.uuid);
                using (var client = CreateHttpClient(accessToken))
                using (var response = await client.DeleteAsync(requestUri))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        throw CreateOAuthException("RemoveWebHook", await response.Content.ReadAsStringAsync(), response.StatusCode);
                    }
                }
            }

            return hook != null;
        }

        public async Task AddSSHKey(string repoUrl, string accessToken, string title, string sshKey)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("title", title);
            CommonUtils.ValidateNullArgument("sshKey", sshKey);

            await RemoveSSHKey(repoUrl, accessToken, sshKey);

            // deploy key only allow read-only access
            var sshKeyInfo = new BitbucketProxy.BitbucketSSHKeyInfo { label = title, key = sshKey };
            // BUG https://bitbucket.org/site/master/issues/12746/missing-v2-api-to-add-remove-deployment
            var requestUri = BitbucketProxyHelper.GetRequestUri(APiV1BaseUrl, repoUrl, "deploy-keys");
            using (var client = CreateHttpClient(accessToken))
            using (var response = await client.PostAsJsonAsync(requestUri, sshKeyInfo))
            {
                if (!response.IsSuccessStatusCode)
                {
                    throw CreateOAuthException("AddSSHKey", await response.Content.ReadAsStringAsync(), response.StatusCode);
                }
            }
        }

        public async Task<bool> RemoveSSHKey(string repoUrl, string accessToken, string sshKey)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("sshKey", sshKey);

            var sshKeyInfo = await GetSSHKey(repoUrl, accessToken, sshKey);
            if (sshKeyInfo != null)
            {
                var requestUri = BitbucketProxyHelper.GetRequestUri(APiV1BaseUrl, repoUrl, "deploy-keys", sshKeyInfo.pk);
                using (var client = CreateHttpClient(accessToken))
                {
                    using (var response = await client.DeleteAsync(requestUri))
                    {
                        if (!response.IsSuccessStatusCode)
                        {
                            throw CreateOAuthException("RemoveSSHKey", await response.Content.ReadAsStringAsync(), response.StatusCode);
                        }
                    }
                }
            }

            return sshKeyInfo != null;
        }

        /// <summary>
        /// Get Webhook service from v1 API
        /// </summary>
        public async Task<BitbucketProxy.BitbucketHookInfo> GetService(string repoUrl, string accessToken, string serviceUrl)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("serviceUrl", serviceUrl);

            var serviceUri = new Uri(serviceUrl);
            var requestUri = BitbucketProxyHelper.GetRequestUri(APiV1BaseUrl, repoUrl, "services");
            using (var client = CreateHttpClient(accessToken))
            using (HttpResponseMessage response = await client.GetAsync(requestUri))
            {
                BitbucketProxy.BitbucketHookInfo[] services = await ProcessResponse<BitbucketProxy.BitbucketHookInfo[]>("GetService", response);
                return services.FirstOrDefault(service =>
                {
                    if (service.service != null && service.service.url != null && string.Equals(service.service.type, "POST", StringComparison.OrdinalIgnoreCase))
                    {
                        Uri configUri;
                        if (Uri.TryCreate(service.service.url, UriKind.Absolute, out configUri))
                        {
                            return string.Equals(serviceUri.Host, configUri.Host, StringComparison.OrdinalIgnoreCase);
                        }
                    }

                    return false;
                });
            }
        }

        /// <summary>
        /// Remove Webhook service from v1 API
        /// </summary>
        public async Task<bool> RemoveService(string repoUrl, string accessToken, string serviceUrl)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("serviceUrl", serviceUrl);

            var service = await GetService(repoUrl, accessToken, serviceUrl);
            if (service != null)
            {
                var requestUri = BitbucketProxyHelper.GetRequestUri(APiV1BaseUrl, repoUrl, "services", service.id);
                using (var client = CreateHttpClient(accessToken))
                using (HttpResponseMessage response = await client.DeleteAsync(requestUri))
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        throw CreateOAuthException("RemoveService", await response.Content.ReadAsStringAsync(), response.StatusCode);
                    }
                }
            }

            return service != null;
        }

        private async Task<List<T>> ListPagingItems<T>(HttpClient client, string initRequestUri, string operationName)
        {
            // For security and performence purpose, only read the first 30 pages
            int count = 30;
            var results = new List<T>();
            while (!string.IsNullOrWhiteSpace(initRequestUri) && count-- > 0)
            {
                using (HttpResponseMessage response = await client.GetAsync(initRequestUri))
                {
                    var pagingResult = await ProcessResponse<BitbucketV2Paging<T>>(operationName, response);
                    results.AddRange(pagingResult.values);
                    initRequestUri = pagingResult.next;
                }
            }

            return results;
        }

        private async Task<BitbucketProxy.BitbucketSSHKeyFullInfo> GetSSHKey(string repoUrl, string accessToken, string sshKey)
        {
            var requestUri = BitbucketProxyHelper.GetRequestUri(APiV1BaseUrl, repoUrl, "deploy-keys");

            using (var client = CreateHttpClient(accessToken))
            using (var response = await client.GetAsync(requestUri))
            {
                var sshKeys = await this.ProcessResponse<BitbucketProxy.BitbucketSSHKeyFullInfo[]>("GetSSHKey", response);
                return sshKeys.FirstOrDefault(info => BitbucketProxy.SSHKeyEquals(info.key, sshKey));
            }
        }

        private async Task<BitbucketV2WebHook> GetWebHookInfo(string repoUrl, string accessToken, string hookUrl)
        {
            var hookUri = new Uri(hookUrl);
            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "hooks");
            using (var client = CreateHttpClient(accessToken))
            {
                List<BitbucketV2WebHook> webhookResults = await ListPagingItems<BitbucketV2WebHook>(client, requestUri, "GetWebHookInfo");
                return webhookResults.FirstOrDefault(w =>
                {
                    Uri configUri;
                    if (Uri.TryCreate(w.url, UriKind.Absolute, out configUri))
                    {
                        return string.Equals(hookUri.Host, configUri.Host, StringComparison.OrdinalIgnoreCase);
                    }

                    return false;
                });
            }
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

            throw CreateBitbucketException(operation, content, response.StatusCode);
        }

        private static OAuthException CreateBitbucketException(string operation, string content, HttpStatusCode statusCode)
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

            public BitbucketProxy.BitbucketRepoInfo ToRepoInfo()
            {
                return new BitbucketProxy.BitbucketRepoInfo
                {
                    owner = owner.username,
                    scm = scm,
                    name = name,
                    slug = full_name.Split('/').Last(),
                    is_private = is_private
                };
            }
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

        public class BitbucketV2BranchTarget
        {
            public string hash { get; set; }
        }

        public class BitbucketV2Branch
        {
            public string name { get; set; }
            public BitbucketV2BranchTarget target { get; set; }

            // Missing "mainbranch" property from v2 api
            // BUG: https://bitbucket.org/site/master/issues/12740/missing-mainbranch-property-on-get-branch
            public BitbucketProxy.BitbucketBranchInfo ToBranchInfo()
            {
                var info = new BitbucketProxy.BitbucketBranchInfo();
                info.changeset = this.target.hash;
                info.name = this.name;
                return info;
            }
        }

        public class BitbucketV2WebHook
        {
            public string uuid { get; set; }
            public string url { get; set; }
            public bool active { get; set; }
            public string type { get; set; }
            public string[] events { get; set; }
            public string description { get; set; }

            public BitbucketProxy.BitbucketHookInfo ToBitbucketHookInfo()
            {
                var info = new BitbucketProxy.BitbucketHookInfo();
                info.id = this.uuid;
                info.service = new BitbucketProxy.BitbucketServiceInfo();
                info.service.type = type;
                info.service.fields = new BitbucketProxy.BitbucketFieldInfo[] {
                    new BitbucketProxy.BitbucketFieldInfo()
                    {
                        name= "URL",
                        value= url
                    }
                };

                return info;
            }
        }
    }
}
