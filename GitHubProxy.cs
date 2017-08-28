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
using Microsoft.Web.Hosting.SourceControls.Utils;

namespace Microsoft.Web.Hosting.SourceControls
{
    public class GitHubProxy
    {
        private const string SSHPrefix = "ssh-rsa ";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly Func<HttpClientHandler, HttpClient> _httpClientFactory;

        public GitHubProxy(string clientId = null, string clientSecret = null, Func<HttpClientHandler, HttpClient> httpClientFactory = null)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _httpClientFactory = httpClientFactory;
        }

        public string GetOAuthUri(string state = null, string redirectUri = null)
        {
            CommonUtils.ValidateNullArgument("_clientId", _clientId);

            StringBuilder strb = new StringBuilder();
            strb.Append("https://github.com/login/oauth/authorize");
            strb.AppendFormat("?client_id={0}", WebUtility.UrlEncode(_clientId));
            if (!String.IsNullOrEmpty(redirectUri))
            {
                strb.AppendFormat("&redirect_uri={0}", WebUtility.UrlEncode(redirectUri));
            }
            strb.Append("&scope=repo");
            strb.AppendFormat("&state={0}", WebUtility.UrlEncode(state ?? String.Empty));

            return strb.ToString();
        }

        public async Task<string> Authorize(string callbackUri, Action<string> validateState = null)
        {
            CommonUtils.ValidateNullArgument("_clientId", _clientId);
            CommonUtils.ValidateNullArgument("_clientSecret", _clientSecret);
            CommonUtils.ValidateNullArgument("callbackUri", callbackUri);

            var queryStrings = HttpUtility.ParseQueryString(new Uri(callbackUri).Query);

            // Check for error
            var message = queryStrings["error_description"] ?? queryStrings["error"];
            if (!String.IsNullOrEmpty(message))
            {
                throw new OAuthException("GitHub: " + message, HttpStatusCode.Unauthorized, callbackUri);
            }

            if (validateState != null)
            {
                validateState(queryStrings["state"]);
            }

            var code = queryStrings["code"];
            if (String.IsNullOrEmpty(code))
            {
                throw new OAuthException("GitHub: missing code query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            var strb = new StringBuilder();
            strb.AppendFormat("client_id={0}", WebUtility.UrlEncode(_clientId));
            strb.AppendFormat("&client_secret={0}", WebUtility.UrlEncode(_clientSecret));
            strb.AppendFormat("&code={0}", WebUtility.UrlEncode(code));

            var content = new StringContent(strb.ToString());
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.FormUrlEncodedMediaType);

            using (var client = CreateHttpClient())
            {
                using (var response = await client.PostAsync("https://github.com/login/oauth/access_token", content))
                {
                    var info = await ProcessResponse<OAuthInfo>("Authorize", response);
                    return info.access_token;
                }
            }
        }

        public async Task<IEnumerable<GitHubRepoInfo>> ListRepositories(string accessToken)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            var tasks = new[]
            {
                ListRepos(accessToken),
                ListOrgRepos(accessToken)
            };

            await Task.WhenAll(tasks);

            return CommonUtils.ConcatEnumerable(tasks.Select(t => t.Result));
        }

        public async Task<GitHubAccountInfo> GetAccountInfo(string accessToken)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            var requestUri = "https://api.github.com/user";
            using (var client = CreateGitHubClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    return await ProcessResponse<GitHubAccountInfo>("GetAccountInfo", response);
                }
            }
        }

        public async Task<GitHubRepoInfo> GetRepository(string repoUrl, string accessToken)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            var requestUri = GetRequestUri(repoUrl);

            try
            {
                using (var client = CreateGitHubClient(accessToken))
                using (var response = await client.GetAsync(requestUri))
                {
                    return await ProcessResponse<GitHubRepoInfo>("GetRepository", response);
                }
            }
            catch (OAuthException oae)
            {
                // repo might be renamed
                if (oae.StatusCode != HttpStatusCode.NotFound)
                {
                    throw;
                }
            }

            // handle rename case
            using (var handler = new HttpClientHandler() { AllowAutoRedirect = false })
            using (var client = CreateGitHubClient(accessToken, handler))
            using (var response = await client.GetAsync(requestUri))
            {
                string content = await response.ReadContentAsync();
                if (response.StatusCode != HttpStatusCode.MovedPermanently)
                {
                    throw CreateOAuthException("GetRepository", content, response.StatusCode);
                }
                // sample result payload: {"message":"Moved Permanently","url":"https://api.github.com/repositories/42146335","documentation_url":"https://developer.github.com/v3/#http-redirects"}
                var renameResult = JsonUtils.Deserialize<RenamedRepoResult>(content);
                // get rename url
                requestUri = renameResult.url;
            }

            // query renamed repo
            using (var client = CreateGitHubClient(accessToken))
            using (var response = await client.GetAsync(requestUri))
            {
                return await ProcessResponse<GitHubRepoInfo>("GetRepository", response);
            }
        }

        public async Task<IEnumerable<GitHubBranchInfo>> ListBranches(string repoUrl, string accessToken)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            var requestUri = GetRequestUri(repoUrl, "branches");
            using (var client = CreateGitHubClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    return await ProcessResponse<IEnumerable<GitHubBranchInfo>>("ListBranches", response);
                }
            }
        }

        public async Task<StreamContent> DownloadFile(string repoUrl, string path, string accessToken, string branch = "master")
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("path", path);
            CommonUtils.ValidateNullArgument("branch", branch);

            var requestUri = String.Format("{0}?ref={1}", GetRequestUri(repoUrl, "contents", path), branch);
            using (var client = CreateGitHubClient(accessToken))
            {
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github.v3.raw"));
                var response = await client.GetAsync(requestUri);
                if (response.IsSuccessStatusCode)
                {
                    return (StreamContent)response.Content;
                }

                throw CreateOAuthException("DownloadFile", String.Empty, response.StatusCode);
            }
        }

        static private string GetRequestUri(string repoUrl, params string[] paths)
        {
            // repoUrl is the clone (https or ssh) url
            var parts = repoUrl.Split(new[] { ':', '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                throw new ArgumentException(repoUrl + " is invalid!");
            }

            var name = parts[parts.Length - 1];
            if (name.EndsWith(".git", StringComparison.OrdinalIgnoreCase))
            {
                parts[parts.Length - 1] = name.Substring(0, name.Length - 4);
            }

            if (paths == null || paths.Length == 0)
            {
                return String.Format("https://api.github.com/repos/{0}/{1}", parts[parts.Length - 2], parts[parts.Length - 1]);
            }
            else
            {
                return String.Format("https://api.github.com/repos/{0}/{1}/{2}", parts[parts.Length - 2], parts[parts.Length - 1], String.Join("/", paths));
            }
        }

        public async Task<GitHubHookInfo> AddWebHook(string repoUrl, string accessToken, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);

            var hook = await GetWebHookInfo(repoUrl, accessToken, hookUrl);
            string id = null;
            if (hook != null)
            {
                if (string.Equals(hookUrl, hook.config.url, StringComparison.OrdinalIgnoreCase))
                {
                    return hook;
                }

                id = hook.id;
            }

            var hookInfo = new CreateGitHubHookInfo(hookUrl);
            if (String.IsNullOrEmpty(id))
            {
                var requestUri = GetRequestUri(repoUrl, "hooks");
                using (var client = CreateGitHubClient(accessToken))
                {
                    using (var response = await client.PostAsJsonAsync(requestUri, hookInfo))
                    {
                        return await ProcessResponse<GitHubHookInfo>("AddWebHook", response);
                    }
                }
            }
            else
            {
                var requestUri = GetRequestUri(repoUrl, "hooks", id);
                using (var client = CreateGitHubClient(accessToken))
                {
                    using (var response = await client.PatchAsJsonAsync(requestUri, hookInfo))
                    {
                        return await ProcessResponse<GitHubHookInfo>("UpdateWebHook", response);
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
            if (hook == null)
            {
                return false;
            }

            var requestUri = GetRequestUri(repoUrl, "hooks", hook.id);
            using (var client = CreateGitHubClient(accessToken))
            {
                using (var response = await client.DeleteAsync(requestUri))
                {
                    return await ProcessEmptyResponse("RemoveWebHook", response);
                }
            }
        }

        public async Task<GitHubSSHKeyInfo> AddSSHKey(string repoUrl, string accessToken, string title, string sshKey)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("title", title);
            CommonUtils.ValidateNullArgument("sshKey", sshKey);

            // GitHub: Deploy keys are immutable. If you need to update a key, remove the key and create a new one instead.
            await RemoveSSHKey(repoUrl, accessToken, sshKey);

            // only need read-only access for deploy key
            var sshKeyInfo = new GitHubSSHKeyInfo { title = title, key = sshKey, read_only = true };
            var requestUri = GetRequestUri(repoUrl, "keys");
            using (var client = CreateGitHubClient(accessToken))
            {
                using (var response = await client.PostAsJsonAsync(requestUri, sshKeyInfo))
                {
                    return await ProcessResponse<GitHubSSHKeyInfo>("AddSSHKey", response);
                }
            }
        }

        public async Task<bool> RemoveSSHKey(string repoUrl, string accessToken, string sshKey)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("sshKey", sshKey);

            var sshKeyInfo = await GetSSHKey(repoUrl, accessToken, sshKey);
            if (sshKeyInfo == null)
            {
                return false;
            }

            var requestUri = GetRequestUri(repoUrl, "keys", sshKeyInfo.id);
            using (var client = CreateGitHubClient(accessToken))
            {
                using (var response = await client.DeleteAsync(requestUri))
                {
                    return await ProcessEmptyResponse("RemoveSSHKey", response);
                }
            }
        }

        private async Task<GitHubSSHKeyInfo> GetSSHKey(string repoUrl, string accessToken, string sshKey)
        {
            var requestUri = GetRequestUri(repoUrl, "keys");
            using (var client = CreateGitHubClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var sshKeys = await ProcessResponse<GitHubSSHKeyInfo[]>("GetSSHKey", response);
                    return sshKeys.FirstOrDefault(ssh => SSHKeyEquals(sshKey, ssh.key));
                }
            }
        }

        private bool SSHKeyEquals(string src, string dst)
        {
            if (!src.StartsWith(SSHPrefix) || src.Length <= SSHPrefix.Length ||
                !dst.StartsWith(SSHPrefix) || dst.Length <= SSHPrefix.Length)
            {
                return String.Equals(src, dst);
            }

            return String.Equals(
                src.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[1],
                dst.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)[1]);
        }

        private async Task<GitHubHookInfo> GetWebHookInfo(string repoUrl, string accessToken, string hookUrl)
        {
            var hookUri = new Uri(hookUrl);
            var requestUri = GetRequestUri(repoUrl, "hooks");
            using (var client = CreateGitHubClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var hooks = await ProcessResponse<GitHubHookInfo[]>("GetWebHookInfo", response);
                    return hooks.FirstOrDefault(hook =>
                    {
                        if (String.Equals("web", hook.name, StringComparison.OrdinalIgnoreCase))
                        {
                            Uri configUri;
                            if (Uri.TryCreate(hook.config.url, UriKind.Absolute, out configUri))
                            {
                                return String.Equals(hookUri.Host, configUri.Host, StringComparison.OrdinalIgnoreCase);
                            }
                        }

                        return false;
                    });
                }
            }
        }

        private async Task<IEnumerable<GitHubRepoInfo>> ListOrgRepos(string accessToken)
        {
            var orgs = await ListOrgs(accessToken);

            if (orgs != null || orgs.Count() > 0)
            {
                var tasks = new List<Task<IEnumerable<GitHubRepoInfo>>>();
                foreach (var login in orgs)
                {
                    tasks.Add(ListRepos(accessToken, login));
                }

                await Task.WhenAll(tasks);

                return CommonUtils.ConcatEnumerable(tasks.Select(t => t.Result));
            }

            return Enumerable.Empty<GitHubRepoInfo>();
        }

        private async Task<IEnumerable<string>> ListOrgs(string accessToken)
        {
            StringBuilder strb = new StringBuilder();
            strb.AppendFormat("https://api.github.com/user/orgs?per_page={0}", "100");

            using (var client = CreateGitHubClient(accessToken))
            {
                using (var response = await client.GetAsync(strb.ToString()))
                {
                    var orgs = await ProcessResponse<GitHubOrgInfo[]>("ListOrgs", response);
                    return orgs.Select(o => o.login);
                }
            }
        }

        private async Task<IEnumerable<GitHubRepoInfo>> ListRepos(string accessToken, string orgLogin = null)
        {
            StringBuilder strb = new StringBuilder();
            if (orgLogin == null)
            {
                strb.Append("https://api.github.com/user/repos");
            }
            else
            {
                strb.AppendFormat("https://api.github.com/orgs/{0}/repos", orgLogin);
            }

            strb.AppendFormat("?per_page={0}", "100");
            strb.AppendFormat("&sort={0}", "updated");

            using (var client = CreateGitHubClient(accessToken))
            {
                using (var response = await client.GetAsync(strb.ToString()))
                {
                    return await IterateReposAsync(accessToken, response);
                }
            }
        }

        private async Task<IEnumerable<GitHubRepoInfo>> IterateReposAsync(string accessToken, HttpResponseMessage response, IEnumerable<GitHubRepoInfo> results = null, int loop = 0)
        {
            // we cap out at 10 iterations.
            if (loop < 10 && response.IsSuccessStatusCode && response.Headers.Contains("link"))
            {
                // link header: <https://api.github.com/organizations/1065621/repos?access_token=5d229be44442a299950aa3386bdb279384bd5dfb&page=2&per_page=10&sort=updated>; rel="next", <https://api.github.com/organizations/1065621/repos?access_token=5d229be44442a299950aa3386bdb279384bd5dfb&page=6&per_page=10&sort=updated>; rel="last"
                string values = response.Headers.GetValues("link").FirstOrDefault();
                if (!string.IsNullOrEmpty(values))
                {
                    string[] pairs = values.Split(new[] { '<', '>', ';', ',', ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (pairs.Length >= 2)
                    {
                        Uri url = null;
                        if (Uri.TryCreate(pairs[0], UriKind.Absolute, out url) && pairs[1] == "rel=\"next\"")
                        {
                            var second = await ProcessReposResponse(response);
                            var totals = results != null ? results.Concat(second) : second;

                            using (var client = CreateGitHubClient(accessToken))
                            {
                                using (var next = await client.GetAsync(url))
                                {
                                    return await IterateReposAsync(accessToken, next, totals, loop + 1);
                                }
                            }
                        }
                    }
                }
            }

            var repoInfo = await ProcessReposResponse(response);
            return results != null ? results.Concat(repoInfo) : repoInfo;
        }

        private async Task<IEnumerable<GitHubRepoInfo>> ProcessReposResponse(HttpResponseMessage response)
        {
            var repos = await ProcessResponse<GitHubRepoInfo[]>("ListRepos", response);
            return repos.Where(repo => repo.permissions == null || repo.permissions.admin);
        }

        private async Task<T> ProcessResponse<T>(string operation, HttpResponseMessage response)
        {
            string content = await response.ReadContentAsync();
            if (response.IsSuccessStatusCode)
            {
                return JsonUtils.Deserialize<T>(content);
            }

            throw CreateOAuthException(operation, content, response.StatusCode);
        }

        private async Task<bool> ProcessEmptyResponse(string operation, HttpResponseMessage response)
        {
            string content = await response.ReadContentAsync();
            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            throw CreateOAuthException(operation, content, response.StatusCode);
        }

        private HttpClient CreateGitHubClient(string accessToken, HttpClientHandler handler = null)
        {
            HttpClient client = CreateHttpClient(handler);
            if (!String.IsNullOrEmpty(accessToken))
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("token", accessToken);
            }
            return client;
        }

        private HttpClient CreateHttpClient(HttpClientHandler handler = null)
        {
            HttpClient client = _httpClientFactory != null ? _httpClientFactory(handler) : new HttpClient();
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
            if (!String.IsNullOrEmpty(content))
            {
                var error = JsonUtils.Deserialize<OAuthError>(content);
                if (error != null)
                {
                    if (!String.IsNullOrEmpty(error.error_description))
                    {
                        message = String.Format("GitHub {0}: {1}", operation, error.error_description);
                    }
                    else if (error.errors != null && error.errors.Length > 0 && !String.IsNullOrEmpty(error.errors[0].message))
                    {
                        message = String.Format("GitHub {0}: {1}", operation, error.errors[0].message);
                    }
                    else if (!String.IsNullOrEmpty(error.message))
                    {
                        message = String.Format("GitHub {0}: {1}", operation, error.message);
                    }
                }
            }

            if (String.IsNullOrEmpty(message))
            {
                message = String.Format("GitHub {0}: ({1}) {2}.", operation, (int)statusCode, statusCode);
            }

            return new OAuthException(message, statusCode, content);
        }

        public class GitHubAccountInfo
        {
            public string login { get; set; }
            public string id { get; set; }
            public string email { get; set; }
            public string name { get; set; }
        }

        public class GitHubRepoInfo
        {
            public string RepoUrl { get { return @private ? ssh_url : clone_url; } }
            public PermissionsInfo permissions { get; set; }
            public string full_name { get; set; }
            public string html_url { get; set; }
            public bool @private { get; set; }
            public string url { get; set; }
            public string ssh_url { get; set; }
            public string clone_url { get; set; }
        }

        public class GitHubBranchInfo
        {
            public string name { get; set; }
            public GitHubCommitInfo commit { get; set; }
        }

        public class GitHubCommitInfo
        {
            public string sha { get; set; }
        }

        public class GitHubOrgInfo
        {
            public string login { get; set; }
        }

        public class PermissionsInfo
        {
            public bool admin { get; set; }
        }

        public class GitHubHookInfo
        {
            public string url { get; set; }

            public string updated_at { get; set; }

            public string created_at { get; set; }

            public string name { get; set; }

            public string[] events { get; set; }

            public string active { get; set; }

            public GitHubHookConfigInfo config { get; set; }

            public GitHubHookLastResponse last_response { get; set; }

            public string id { get; set; }
        }

        public class GitHubHookConfigInfo
        {
            public string url { get; set; }
        }

        public class GitHubHookLastResponse
        {
            public string status { get; set; }

            public string message { get; set; }

            public int? code { get; set; }
        }

        public class CreateGitHubHookInfo
        {
            public CreateGitHubHookInfo(string hookUrl)
            {
                this.name = "web";
                this.active = true;
                this.config = new CreateGitHubHookConfigInfo(hookUrl);
            }

            public string name { get; set; }

            public bool active { get; set; }

            public CreateGitHubHookConfigInfo config { get; set; }
        }

        public class CreateGitHubHookConfigInfo
        {
            public CreateGitHubHookConfigInfo(string url)
            {
                this.url = url;
                this.content_type = "form";
                this.insecure_ssl = "1";
            }

            public string url { get; set; }

            public string content_type { get; set; }

            public string insecure_ssl { get; set; }
        }

        public class GitHubSSHKeyInfo
        {
            public string id { get; set; }
            public string title { get; set; }
            public string key { get; set; }
            public bool read_only { get; set; }
        }

        public class OAuthInfo
        {
            public string token_type { get; set; }
            public string scope { get; set; }
            public string access_token { get; set; }
        }

        public class OAuthError
        {
            // oauth error
            public string error { get; set; }
            public string error_description { get; set; }
            public string error_uri { get; set; }

            // api error
            public string message { get; set; }
            public OAuthErrorDetail[] errors { get; set; }
        }

        public class OAuthErrorDetail
        {
            public string resource { get; set; }
            public string code { get; set; }
            public string field { get; set; }
            public string message { get; set; }
        }

        public class RenamedRepoResult
        {
            public string message { get; set; }
            public string url { get; set; }
        }
    }
}
