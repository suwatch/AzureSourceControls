// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using AzureSourceControls.Utils;

namespace AzureSourceControls
{
    public class VsoProxy
    {
        private const string ApiVersion = "1.0";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly Func<HttpClient> _httpClientFactory;

        public VsoProxy(string clientId = null, string clientSecret = null, Func<HttpClient> httpClientFactory = null)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _httpClientFactory = httpClientFactory;
        }

        public string GetOAuthUri(string state = null, string redirectUri = null)
        {
            CommonUtils.ValidateNullArgument("_clientId", _clientId);

            const string response_type = "Assertion";
            const string scope = "preview_api_all preview_msdn_licensing";

            StringBuilder strb = new StringBuilder();
            strb.Append("https://app.vssps.visualstudio.com/oauth2/authorize");
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

            using (var client = CreateHttpClient())
            {
                using (var response = await client.PostAsync("https://app.vssps.visualstudio.com/oauth2/token", content))
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

            using (var client = CreateHttpClient())
            {
                using (var response = await client.PostAsync("https://app.vssps.visualstudio.com/oauth2/token", content))
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

            var requestUri = String.Format("https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version={0}", ApiVersion);
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

            var requestUri = String.Format("https://app.vssps.visualstudio.com/_apis/accounts?ownerId={0}&api-version={1}", profileId, ApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var result = await ProcessResponse<TfsResult<TfsAccountInfo>>("ListAccounts", response);
                    return result.value;
                }
            }
        }

        public async Task<TfsRepositoryInfo[]> ListRepositories(string accessToken, string accountName = null)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            if (String.IsNullOrEmpty(accountName))
            {
                var tasks = new List<Task<TfsRepositoryInfo[]>>();
                foreach (var account in await ListAccounts(accessToken))
                {
                    tasks.Add(ListRepositories(accessToken, account.accountName));
                }

                var results = await Task.WhenAll(tasks);

                return results.SelectMany(r => r).ToArray();
            }

            var requestUri = String.Format("https://{0}.VisualStudio.com/DefaultCollection/_apis/git/repositories?api-version={1}", accountName, ApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var result = await ProcessResponse<TfsResult<TfsRepositoryInfo>>("ListRepositories", response);
                    return result.value;
                }
            }
        }

        public async Task<TfsRepositoryInfo> GetRepository(string accessToken, string repoUrl)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);

            var repositories = await ListRepositories(accessToken);
            var repository = repositories.FirstOrDefault(r => String.Equals(r.RepoUrl, repoUrl));
            if (repository == null)
            {
                throw new InvalidOperationException("Vso GetRepository: Cannot find repository " + repoUrl);
            }

            return repository;
        }

        public async Task<TfsBranchInfo[]> ListBranches(string accessToken, TfsRepositoryInfo repository)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);

            var requestUri = String.Format("{0}/refs?api-version={1}", repository.url, ApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var result = await ProcessResponse<TfsResult<TfsBranchInfo>>("ListBranches", response);
                    return result.value;
                }
            }
        }

        public async Task<TfsWebHookInfo[]> ListWebHooks(string accessToken, TfsRepositoryInfo repository)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);

            var url = new Uri(repository.url);
            var requestUri = String.Format("{0}://{1}/DefaultCollection/_apis/hooks/subscriptions?api-version={2}", url.Scheme, url.Authority, ApiVersion);
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

        public async Task<TfsWebHookInfo> AddWebHook(string accessToken, TfsRepositoryInfo repository, string hookUrl, string branch = null)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);

            await RemoveWebHook(accessToken, repository, hookUrl);

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
            var requestUri = String.Format("{0}://{1}/DefaultCollection/_apis/hooks/subscriptions?api-version={2}", repoUri.Scheme, repoUri.Authority, ApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.PostAsJsonAsync(requestUri, hook))
                {
                    return await ProcessResponse<TfsWebHookInfo>("AddWebHook", response);
                }
            }
        }

        public async Task<bool> TestWebHook(string accessToken, TfsRepositoryInfo repository, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);

            var hook = await GetWebHookInfo(accessToken, repository, hookUrl);
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
            var requestUri = String.Format("{0}://{1}/DefaultCollection/_apis/hooks/testNotifications?api-version={2}", repoUri.Scheme, repoUri.Authority, ApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.PostAsJsonAsync(requestUri, test))
                {
                    return await ProcessEmptyResponse("TestWebHook", response);
                }
            }
        }

        public async Task<bool> RemoveWebHook(string accessToken, TfsRepositoryInfo repository, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("repository", repository);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);

            var hook = await GetWebHookInfo(accessToken, repository, hookUrl);
            if (hook == null)
            {
                return false;
            }

            var requestUri = String.Format("{0}?api-version={1}", hook.url, ApiVersion);
            using (var client = CreateTfsClient(accessToken))
            {
                using (var response = await client.DeleteAsync(requestUri))
                {
                    return await ProcessEmptyResponse("RemoveWebHook", response);
                }
            }
        }

        private async Task<TfsWebHookInfo> GetWebHookInfo(string accessToken, TfsRepositoryInfo repository, string hookUrl)
        {
            var hooks = await ListWebHooks(accessToken, repository);
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
            HttpClient client = CreateHttpClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            return client;
        }

        private HttpClient CreateHttpClient()
        {
            HttpClient client = _httpClientFactory != null ? _httpClientFactory() : new HttpClient();
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
                        message = String.Format("Vso {0}: {1}", operation, error.ErrorDescription);
                    }
                    else if (!String.IsNullOrEmpty(error.Error))
                    {
                        message = String.Format("Vso {0}: {1}", operation, error.Error);
                    }
                    else if (!String.IsNullOrEmpty(error.Message))
                    {
                        message = String.Format("Vso {0}: {1}", operation, error.Message);
                    }
                }
            }

            if (String.IsNullOrEmpty(message))
            {
                message = String.Format("Vso {0}: ({1}) {2}.", operation, (int)statusCode, statusCode);
            }

            return new OAuthException(message, statusCode, content);
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
    }
}
