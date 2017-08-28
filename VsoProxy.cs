// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Globalization;
using System.IO;
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
    public class VsoProxy
    {
        private const string VsoApiVersion = "1.0";
        private const string VsoApiUri = "https://app.vssps.visualstudio.com";
        private const string VsoAccountSuffix = "visualstudio.com";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly Func<HttpClientHandler, HttpClient> _httpClientFactory;

        private string _apiUri;
        private string _accountSuffix;

        public VsoProxy(string clientId = null, string clientSecret = null, Func<HttpClientHandler, HttpClient> httpClientFactory = null)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _apiUri = VsoApiUri;
            _accountSuffix = VsoAccountSuffix;
            _httpClientFactory = httpClientFactory;
        }

        public string ApiUri
        {
            get { return String.IsNullOrEmpty(_apiUri) ? VsoApiUri : _apiUri; }
            set { _apiUri = value; }
        }

        public string AccountSuffix
        {
            get { return String.IsNullOrEmpty(_accountSuffix) ? VsoAccountSuffix : _accountSuffix; }
            set { _accountSuffix = value; }
        }

        public string TFSImpersonate
        {
            get;
            set;
        }

        public string GetOAuthUri(string state = null, string redirectUri = null)
        {
            CommonUtils.ValidateNullArgument("_clientId", _clientId);

            const string response_type = "Assertion";
            const string scope = "vso.code";

            StringBuilder strb = new StringBuilder();
            strb.AppendFormat("{0}/oauth2/authorize", ApiUri);
            strb.AppendFormat("?client_id={0}", WebUtility.UrlEncode(_clientId));
            strb.AppendFormat("&scope={0}", WebUtility.UrlEncode(scope));
            strb.AppendFormat("&response_type={0}", WebUtility.UrlEncode(response_type));
            strb.AppendFormat("&state={0}", WebUtility.UrlEncode(state ?? String.Empty));
            if (!String.IsNullOrEmpty(redirectUri))
            {
                strb.AppendFormat("&redirect_uri={0}", WebUtility.UrlEncode(redirectUri));
            }

            return strb.ToString();
        }

        public async Task<OAuthInfo> Authorize(string callbackUri, Action<string> validateState = null)
        {
            CommonUtils.ValidateNullArgument("_clientSecret", _clientSecret);
            CommonUtils.ValidateNullArgument("callbackUri", callbackUri);

            var uri = new Uri(callbackUri);
            var redirectUri = uri.GetLeftPart(UriPartial.Path);
            var queryStrings = HttpUtility.ParseQueryString(uri.Query);

            // Check for error
            var message = queryStrings["error_description"] ?? queryStrings["error"];
            if (!String.IsNullOrEmpty(message))
            {
                throw new OAuthException("Tfs: " + message, HttpStatusCode.Unauthorized, callbackUri);
            }

            if (validateState != null)
            {
                validateState(queryStrings["state"]);
            }

            var code = queryStrings["code"];
            if (String.IsNullOrEmpty(code))
            {
                throw new OAuthException("Tfs: missing code query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            var content = new StringContent(GeneratePostData(redirectUri, code: code));
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.FormUrlEncodedMediaType);

            var requestUri = String.Format("{0}/oauth2/token", ApiUri);
            using (var client = CreateHttpClient())
            {
                using (var response = await client.PostAsync(requestUri, content))
                {
                    return await ProcessResponse<OAuthInfo>("Authorize", response);
                }
            }
        }

        // (203) NonAuthoritativeInformation means token expired
        // Note: refresh token can only be used once and every refresh gets a new one
        public async Task<OAuthInfo> RefreshToken(string redirectUri, string refreshToken)
        {
            CommonUtils.ValidateNullArgument("_clientSecret", _clientSecret);
            CommonUtils.ValidateNullArgument("refreshToken", refreshToken);
            CommonUtils.ValidateNullArgument("redirectUri", redirectUri);

            var content = new StringContent(GeneratePostData(redirectUri, refreshToken: refreshToken));
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.FormUrlEncodedMediaType);

            var requestUri = String.Format("{0}/oauth2/token", ApiUri);
            using (var client = CreateHttpClient())
            {
                using (var response = await client.PostAsync(requestUri, content))
                {
                    return await ProcessResponse<OAuthInfo>("RefreshToken", response);
                }
            }
        }

        private string GeneratePostData(string redirectUri, string code = null, string refreshToken = null)
        {
            var strb = new StringBuilder();
            strb.Append("client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            strb.AppendFormat("&client_assertion={0}", _clientSecret);
            if (!String.IsNullOrEmpty(code))
            {
                strb.Append("&grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer");
                strb.AppendFormat("&assertion={0}", code);
            }
            else
            {
                strb.Append("&grant_type=refresh_token");
                strb.AppendFormat("&assertion={0}", refreshToken);
            }
            strb.AppendFormat("&redirect_uri={0}", redirectUri);
            return strb.ToString();
        }

        public async Task<TfsProfileInfo> GetProfile(string accessToken)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            var requestUri = String.Format("{0}/_apis/profile/profiles/me?api-version={1}", ApiUri, VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var result = await ProcessResponse<TfsProfileInfo>("GetProfile", response);
                    return result;
                }
            }
        }

        public async Task<TfsAccountInfo[]> ListAccounts(string accessToken, string profileId = null)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            if (String.IsNullOrEmpty(profileId))
            {
                var profile = await GetProfile(accessToken);
                profileId = profile.id;
            }

            var requestUri = String.Format("{0}/_apis/accounts?ownerId={1}&api-version={2}", ApiUri, profileId, VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var result = await ProcessResponse<TfsResult<TfsAccountInfo>>("ListAccounts", response);
                    return result.value;
                }
            }
        }

        public async Task<TfsAccountInfo> GetAccount(string accessToken, string accountName)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("accountName", accountName);

            var requestUri = String.Format("{0}/_apis/accounts/{1}?api-version={2}", ApiUri, accountName, VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    return await ProcessResponse<TfsAccountInfo>(String.Format("GetAccount({0})", TFSImpersonate), response);
                }
            }
        }

        public async Task<string> GetAccountGitEndpoint(string accessToken, string accountName)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("accountName", accountName);

            TfsConnectionData connData = await GetConnectionData(accessToken, accountName);
            CommonUtils.ValidateNullArgument("connData", connData);
            CommonUtils.ValidateNullArgument("connData.locationServiceData", connData.locationServiceData);
            CommonUtils.ValidateNullArgument("connData.locationServiceData.serviceDefinitions", connData.locationServiceData.serviceDefinitions);

            TfsServiceDefinitions definition = connData.locationServiceData.serviceDefinitions.FirstOrDefault(s => string.Equals("git", s.displayName, StringComparison.OrdinalIgnoreCase));
            if (definition != null && definition.locationMappings != null)
            {
                TfsLocationMapping locationMapping = definition.locationMappings.FirstOrDefault(lm => string.Equals("HostGuidAccessMapping", lm.accessMappingMoniker, StringComparison.OrdinalIgnoreCase));
                CommonUtils.ValidateNullArgument("locationMapping", locationMapping);
                CommonUtils.ValidateNullArgument("locationMapping.location", locationMapping.location);
                return locationMapping.location;
            }

            throw new InvalidOperationException("Failed to query VSTS location service.");
        }

        public async Task<TfsConnectionData> GetConnectionData(string accessToken, string accountName)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("accountName", accountName);

            var requestUri = String.Format("https://{0}.vssps.{1}/DefaultCollection/_apis/connectionData?connectOptions=IncludeServices&api-version={2}", accountName, AccountSuffix, VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            using (var response = await client.GetAsync(requestUri))
            {
                return await ProcessResponse<TfsConnectionData>("GetConnectionData", response);
            }
        }

        public async Task<TfsRepositoryInfo[]> ListRepositories(string accessToken, string accountEndpoint)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("accountEndpoint", accountEndpoint);

            string requestUri = String.Format("{0}/_apis/git/repositories?api-version={1}", accountEndpoint.TrimEnd('/'), VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var result = await ProcessResponse<TfsResult<TfsRepositoryInfo>>(String.Format("ListRepositories({0})", TFSImpersonate), response);
                    return result.value;
                }
            }
        }

        // TODO, suwatch: to remove since no longer used
        public async Task<TfsRepositoryInfo> GetRepository(string accessToken, string repoUrl, string accountEndpoint)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accountEndpoint", accountEndpoint);

            var repositories = await ListRepositories(accessToken, accountEndpoint);
            var repository = repositories.FirstOrDefault(r => !String.IsNullOrEmpty(r.RepoUrl) &&
                (String.Equals(r.RepoUrl, repoUrl, StringComparison.OrdinalIgnoreCase) ||
                 String.Equals(r.RepoUrl.Replace("/DefaultCollection", string.Empty), repoUrl.Replace("/DefaultCollection", string.Empty), StringComparison.OrdinalIgnoreCase)));
            if (repository == null)
            {
                throw new InvalidOperationException("Vso GetRepository: Cannot find repository " + repoUrl);
            }

            return repository;
        }

        public async Task<TfsVstsInfo> GetVstsInfo(string accessToken, string repoUrl)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);

            var requestUri = String.Format("{0}/vsts/info", repoUrl.Trim('/'));
            using (var client = CreateTfsClient(accessToken))
            using (var response = await client.GetAsync(requestUri))
            {
                return await ProcessResponse<TfsVstsInfo>("GetVstsInfo", response);
            }
        }

        public async Task<TfsWebHookInfo[]> ListWebHooks(string accessToken, string accountEndpoint)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("accountEndpoint", accountEndpoint);

            var requestUri = string.Format(CultureInfo.InvariantCulture, "{0}/_apis/hooks/subscriptions?api-version={1}&publisherId=tfs", accountEndpoint.TrimEnd('/'), VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var hooks = await ProcessResponse<TfsResult<TfsWebHookInfo>>("GetWebHookInfo", response);
                    return hooks.value.ToArray();
                }
            }
        }

        public async Task<TfsWebHookInfo[]> ListWebHooks(string accessToken, TfsRepositoryInfo repository, string accountEndpoint)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);
            CommonUtils.ValidateNullArgument("accountEndpoint", accountEndpoint);

            var requestUri = string.Format(CultureInfo.InvariantCulture, "{0}/_apis/hooks/subscriptions?api-version={1}&publisherId=tfs", accountEndpoint.TrimEnd('/'), VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var hooks = await ProcessResponse<TfsResult<TfsWebHookInfo>>("GetWebHookInfo", response);
                    return hooks.value.Where(hook =>
                    {
                        if (repository.project != null && hook.publisherInputs != null && hook.consumerInputs != null && hook.consumerInputs.url != null)
                        {
                            return String.Equals(repository.id, hook.publisherInputs.repository, StringComparison.OrdinalIgnoreCase)
                                && String.Equals(repository.project.id, hook.publisherInputs.projectId, StringComparison.OrdinalIgnoreCase);
                        }

                        return false;
                    }).ToArray();
                }
            }
        }

        public async Task<TfsWebHookInfo[]> QueryWebHooks(string accessToken, TfsRepositoryInfo repository, string accountEndpoint)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);
            CommonUtils.ValidateNullArgument("accountEndpoint", accountEndpoint);

            var requestUri = string.Format(CultureInfo.InvariantCulture, "{0}/_apis/hooks/subscriptionsQuery?api-version=3.1", accountEndpoint.TrimEnd('/'));
            using (var client = CreateTfsClient(accessToken))
            {
                var query = new TfsWebHookQuery
                {
                    publisherId = "tfs",
                    publisherInputFilters = new[]
                    {
                        new TfsWebHookFilter
                        {
                            conditions = new[]
                            {
                                new TfsQueryCondition
                                {
                                    inputId = "repository",
                                    @operator = "equals",
                                    inputValue = repository.id
                                }
                            }
                        }
                    }
                };

                using (var response = await client.PostAsJsonAsync(requestUri, query))
                {
                    var hooks = await ProcessResponse<TfsWebHookResult>("QueryWebHooks", response);
                    return hooks.results.Where(hook =>
                    {
                        if (repository.project != null && hook.publisherInputs != null && hook.consumerInputs != null && hook.consumerInputs.url != null)
                        {
                            return String.Equals(repository.id, hook.publisherInputs.repository, StringComparison.OrdinalIgnoreCase)
                                && String.Equals(repository.project.id, hook.publisherInputs.projectId, StringComparison.OrdinalIgnoreCase);
                        }

                        return false;
                    }).ToArray();
                }
            }
        }

        public async Task<TfsWebHookInfo> AddWebHook(string accessToken, TfsRepositoryInfo repository, string accountEndpoint, string hookUrl, string branch = null)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);
            CommonUtils.ValidateNullArgument("accountEndpoint", accountEndpoint);

            await RemoveWebHook(accessToken, repository, accountEndpoint, hookUrl);

            var hookUri = new Uri(hookUrl);
            var hook = new TfsWebHookInfo();
            hook.eventType = "git.push";
            hook.consumerActionId = "deployWebApp";
            hook.consumerId = "azureAppService";
            hook.consumerInputs = new TfsConsumerInputs();
            hook.consumerInputs.url = String.Format("{0}://{1}{2}", hookUri.Scheme, hookUri.Authority, hookUri.PathAndQuery);

            var creds = String.IsNullOrEmpty(hookUri.UserInfo) ? new string[0] : hookUri.UserInfo.Split(':');
            hook.consumerInputs.basicAuthUsername = creds.Length > 0 ? creds[0] : null;
            hook.consumerInputs.basicAuthPassword = creds.Length > 1 ? creds[1] : null;
            hook.publisherId = "tfs";
            hook.publisherInputs = new TfsPublisherInputs();
            hook.publisherInputs.branch = branch ?? "master";
            hook.publisherInputs.projectId = repository.project.id;
            hook.publisherInputs.repository = repository.id;

            var repoUri = new Uri(repository.url);
            var requestUri = String.Format("{0}/_apis/hooks/subscriptions?api-version={1}", accountEndpoint.TrimEnd('/'), VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.PostAsJsonAsync(requestUri, hook))
                {
                    return await ProcessResponse<TfsWebHookInfo>("AddWebHook", response);
                }
            }
        }

        public async Task<bool> TestWebHook(string accessToken, TfsRepositoryInfo repository, string accountEndpoint, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);
            CommonUtils.ValidateNullArgument("accountEndpoint", accountEndpoint);

            var hook = await GetWebHookInfo(accessToken, repository, accountEndpoint, hookUrl);
            if (hook == null)
            {
                throw new InvalidOperationException("Vso TestWebHook: no hook found for " + repository.RepoUrl);
            }

            var hookUri = new Uri(hookUrl);
            var test = new TfsTestHookInfo();
            test.subscriptionId = hook.id;
            test.details = new TfsTestHookDetails();
            test.details.eventType = "git.push";
            test.details.consumerActionId = "deployWebApp";
            test.details.consumerId = "azureAppService";
            test.details.publisherId = "tfs";

            var creds = String.IsNullOrEmpty(hookUri.UserInfo) ? new string[0] : hookUri.UserInfo.Split(':');
            test.details.consumerInputs = new TfsConsumerInputs();
            test.details.consumerInputs.url = String.Format("{0}://{1}{2}", hookUri.Scheme, hookUri.Authority, hookUri.PathAndQuery);
            test.details.consumerInputs.basicAuthUsername = creds.Length > 0 ? creds[0] : null;
            test.details.consumerInputs.basicAuthPassword = creds.Length > 1 ? creds[1] : null;

            var repoUri = new Uri(repository.url);
            var requestUri = String.Format("{0}/_apis/hooks/testNotifications?api-version={1}", accountEndpoint.TrimEnd('/'), VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.PostAsJsonAsync(requestUri, test))
                {
                    return await ProcessEmptyResponse("TestWebHook", response);
                }
            }
        }

        public async Task<bool> RemoveWebHook(string accessToken, TfsRepositoryInfo repository, string accountEndpoint, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);
            CommonUtils.ValidateNullArgument("accountEndpoint", accountEndpoint);

            var hook = await GetWebHookInfo(accessToken, repository, accountEndpoint, hookUrl);
            if (hook == null)
            {
                return false;
            }

            var requestUri = String.Format("{0}?api-version={1}", hook.url, VsoApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.DeleteAsync(requestUri))
                {
                    return await ProcessEmptyResponse("RemoveWebHook", response);
                }
            }
        }

        private async Task<TfsWebHookInfo> GetWebHookInfo(string accessToken, TfsRepositoryInfo repository, string accountEndpoint, string hookUrl)
        {
            var hooks = await QueryWebHooks(accessToken, repository, accountEndpoint);
            var hookUri = new Uri(hookUrl);
            return hooks.FirstOrDefault(hook => String.Equals(new Uri(hook.consumerInputs.url).Host, hookUri.Host, StringComparison.OrdinalIgnoreCase));
        }

        private async Task<T> ProcessResponse<T>(string operation, HttpResponseMessage response)
        {
            string content = await response.ReadContentAsync();
            if (response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.NonAuthoritativeInformation)
            {
                return JsonUtils.Deserialize<T>(content);
            }

            throw CreateOAuthException(operation, content, response.StatusCode);
        }

        private async Task<bool> ProcessEmptyResponse(string operation, HttpResponseMessage response)
        {
            string content = await response.ReadContentAsync();
            if (response.IsSuccessStatusCode && response.StatusCode != HttpStatusCode.NonAuthoritativeInformation)
            {
                return true;
            }

            throw CreateOAuthException(operation, content, response.StatusCode);
        }

        private HttpClient CreateTfsClient(string accessToken)
        {
            var client = CreateHttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            if (!String.IsNullOrEmpty(TFSImpersonate))
            {
                client.DefaultRequestHeaders.Add("X-TFS-Impersonate", "Microsoft.IdentityModel.Claims.ClaimsIdentity;" + TFSImpersonate);
            }
            client.DefaultRequestHeaders.Add("X-TFS-FedAuthRedirect", "Suppress");
            return client;
        }

        private HttpClient CreateHttpClient()
        {
            HttpClient client = _httpClientFactory != null ? _httpClientFactory(null) : new HttpClient();
            client.MaxResponseContentBufferSize = 1024 * 1024 * 10;
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue(Constants.JsonMediaType));
            if (!client.DefaultRequestHeaders.Contains(Constants.UserAgentHeader))
            {
                client.DefaultRequestHeaders.Add(Constants.UserAgentHeader, Constants.MicrosoftAzure);
            }
            return client;
        }

        private static OAuthException CreateOAuthException(string operation, string content, HttpStatusCode statusCode)
        {
            string message = null;
            if (!String.IsNullOrEmpty(content) && content.StartsWith("{"))
            {
                var error = JsonUtils.Deserialize<OAuthError>(content);
                if (error != null)
                {
                    if (!String.IsNullOrEmpty(error.ErrorDescription))
                    {
                        message = String.Format("Vso {0}: {1}", operation, FixupErrorMessage(error.ErrorDescription));
                    }
                    else if (!String.IsNullOrEmpty(error.Error))
                    {
                        message = String.Format("Vso {0}: {1}", operation, FixupErrorMessage(error.Error));
                    }
                    else if (!String.IsNullOrEmpty(error.Message))
                    {
                        message = String.Format("Vso {0}: {1}", operation, FixupErrorMessage(error.Message));
                    }
                }
            }

            if (!String.IsNullOrEmpty(content) && content.StartsWith("TF"))
            {
                message = String.Format("Vso {0}: {1}", operation, content);
            }

            if (String.IsNullOrEmpty(message))
            {
                message = String.Format("Vso {0}: ({1}) {2}.", operation, (int)statusCode, statusCode);
            }

            return new OAuthException(message, statusCode, content);
        }

        private static string FixupErrorMessage(string message)
        {
            if (!String.IsNullOrEmpty(message) && message.IndexOf("Access Denied", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return String.Format("Failed because you are not an administrator on the VSTS project.  {0}", message);
            }

            return message;
        }

        public class TfsResult<T>
        {
            public int count { get; set; }
            public T[] value { get; set; }
        }

        public class TfsWebHookInfo
        {
            public string id { get; set; }
            public string url { get; set; }
            public string consumerActionId { get; set; }
            public string consumerId { get; set; }
            public TfsConsumerInputs consumerInputs { get; set; }
            public string publisherId { get; set; }
            public string eventType { get; set; }
            public TfsPublisherInputs publisherInputs { get; set; }
        }

        public class TfsWebHookQuery
        {
            public string publisherId { get; set; }
            public TfsWebHookFilter[] publisherInputFilters { get; set; }
        }

        public class TfsWebHookResult : TfsWebHookQuery
        {
            public TfsWebHookInfo[] results { get; set; }
        }

        public class TfsWebHookFilter
        {
            public TfsQueryCondition[] conditions { get; set; }
        }

        public class TfsQueryCondition
        {
            public string inputId { get; set; }
            public string @operator { get; set; }
            public string inputValue { get; set; }
        }

        public class TfsConsumerInputs
        {
            public string basicAuthUsername { get; set; }
            public string url { get; set; }
            public string basicAuthPassword { get; set; }
        }

        public class TfsPublisherInputs
        {
            public string branch { get; set; }
            public string projectId { get; set; }
            public string repository { get; set; }
        }

        public class TfsTestHookInfo
        {
            public string subscriptionId { get; set; }
            public TfsTestHookDetails details { get; set; }
        }

        public class TfsTestHookDetails
        {
            public string consumerActionId { get; set; }
            public string consumerId { get; set; }
            public TfsConsumerInputs consumerInputs { get; set; }
            public string publisherId { get; set; }
            public string eventType { get; set; }
        }

        public class TfsProfileInfo
        {
            public string displayName { get; set; }
            public string publicAlias { get; set; }
            public string emailAddress { get; set; }
            public int coreRevision { get; set; }
            public string timeStamp { get; set; }
            public string id { get; set; }
            public int revision { get; set; }
        }

        public class TfsAccountInfo
        {
            public string accountId { get; set; }
            public string accountUri { get; set; }
            public string accountName { get; set; }
            public string organizationName { get; set; }
            public string accountType { get; set; }
            public string accountOwner { get; set; }
            public string accountStatus { get; set; }
        }

        public class TfsBranchInfo
        {
            public string name { get; set; }
            public string objectId { get; set; }
            public string url { get; set; }
        }

        public class TfsRepositoryInfo : TfsInfo
        {
            public string RepoUrl { get { return remoteUrl; } }
            public TfsInfo project { get; set; }
            public string defaultBranch { get; set; }
            public string remoteUrl { get; set; }
        }

        public class TfsInfo
        {
            public string id { get; set; }
            public string name { get; set; }
            public string url { get; set; }
        }

        public class TfsVstsInfo
        {
            public string serverUrl { get; set; }
            public TfsInfo collection { get; set; }
            public TfsRepositoryInfo repository { get; set; }
        }

        public class OAuthInfo
        {
            public string token_type { get; set; }
            public string scope { get; set; }
            public string access_token { get; set; }
            public string refresh_token { get; set; }
            public string expires_in
            {
                get
                {
                    return ((int)expires.Subtract(DateTime.UtcNow).TotalSeconds).ToString();
                }
                set
                {
                    var secs = Int32.Parse(value);
                    expires = DateTime.UtcNow.AddSeconds(secs);
                }
            }

            public DateTime expires { get; private set; }
        }

        public class OAuthError
        {
            // oauth error
            public string Error { get; set; }
            public string ErrorDescription { get; set; }
            public string Message { get; set; }
        }

        public class TfsLocationMapping
        {
            public string accessMappingMoniker { get; set; }
            public string location { get; set; }
        }

        public class TfsServiceDefinitions
        {
            public string displayName { get; set; }
            public TfsLocationMapping[] locationMappings { get; set; }
        }

        public class TfsLocationServiceData
        {
            public TfsServiceDefinitions[] serviceDefinitions { get; set; }
        }

        public class TfsConnectionData
        {
            public TfsLocationServiceData locationServiceData { get; set; }
        }
    }
}
