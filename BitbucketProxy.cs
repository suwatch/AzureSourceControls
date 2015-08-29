// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using AzureSourceControls.Utils;

namespace AzureSourceControls
{
    public class BitbucketProxy
    {
        private const string SSHPrefix = "ssh-rsa ";

        private readonly BitbucketProvider _provider;

        public BitbucketProxy(string clientId, string clientSecret, Func<HttpClient> httpClientFactory = null)
        {
            _provider = new BitbucketProvider(clientId, clientSecret, httpClientFactory);
        }

        public async Task<OAuthV1Info> GetOAuthInfo(string redirectUri)
        {
            CommonUtils.ValidateNullArgument("redirectUri", redirectUri);

            return await _provider.GetOAuthInfo(redirectUri);
        }

        public async Task<OAuthV1Info> Authorize(string callbackUri, string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("callbackUri", callbackUri);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var queryStrings = HttpUtility.ParseQueryString(new Uri(callbackUri).Query);
            var oauth_token = queryStrings["oauth_token"];
            if (String.IsNullOrEmpty(oauth_token))
            {
                throw new OAuthException("Bitbucket Authorize: missing oauth_token query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            if (!String.Equals(oauth_token, token))
            {
                throw new OAuthException("Bitbucket Authorize: mismatch oauth token.", HttpStatusCode.Unauthorized, callbackUri);
            }

            var oauth_verifier = queryStrings["oauth_verifier"];
            if (String.IsNullOrEmpty(oauth_verifier))
            {
                throw new OAuthException("Bitbucket Authorize: missing oauth_verifier query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            return await _provider.Authorize(oauth_verifier, token, tokenSecret);
        }

        public async Task<BitbucketAccountInfo> GetAccoutInfo(string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var user = await _provider.GetAsync<BitbucketUserInfo>("GetAccoutInfo", "https://api.bitbucket.org/1.0/user/", token, tokenSecret);
            return user.user;
        }

        public async Task<IEnumerable<BitbucketRepoInfo>> ListRepositories(string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            return await _provider.GetAsync<BitbucketRepoInfo[]>("ListRepositories", "https://api.bitbucket.org/1.0/user/repositories/", token, tokenSecret);
        }

        public async Task<BitbucketRepoInfo> GetRepository(string repoUrl, string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var requestUri = GetRequestUri(repoUrl);
            return await _provider.GetAsync<BitbucketRepoInfo>("GetRepository", requestUri, token, tokenSecret);
        }

        public async Task<IEnumerable<BitbucketBranchInfo>> ListBranches(string repoUrl, string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var requestUri = GetRequestUri(repoUrl, "branches");
            var branches = await _provider.GetAsync<Dictionary<string, BitbucketBranchInfo>>("ListBranches", requestUri, token, tokenSecret);
            return branches.Select(p =>
            {
                p.Value.name = p.Key;
                return p.Value;
            });
        }

        public async Task AddWebHook(string repoUrl, string token, string tokenSecret, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);

            var hook = await GetWebHookInfo(repoUrl, token, tokenSecret, hookUrl);
            if (hook != null)
            {
                if (string.Equals(hookUrl, hook.service.url, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }

                var requestUri = GetRequestUri(repoUrl, "services", hook.id);
                await _provider.PutAsJsonAsync("AddWebHook", requestUri, token, tokenSecret, new CreateBitbucketHookInfo(hookUrl));
            }
            else
            {
                var requestUri = GetRequestUri(repoUrl, "services");
                var content = new StringContent(String.Format("type=POST;URL={0}", hookUrl), Encoding.UTF8, "application/text");
                await _provider.PostAsync("UpdateWebHook", requestUri, token, tokenSecret, content);
            }
        }

        public async Task<bool> RemoveWebHook(string repoUrl, string token, string tokenSecret, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);

            var hook = await GetWebHookInfo(repoUrl, token, tokenSecret, hookUrl);
            if (hook != null)
            {
                var requestUri = GetRequestUri(repoUrl, "services", hook.id);
                await _provider.DeleteAsync("RemoveWebHook", requestUri, token, tokenSecret);
            }

            return hook != null;
        }

        public async Task AddSSHKey(string repoUrl, string token, string tokenSecret, string title, string sshKey)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);
            CommonUtils.ValidateNullArgument("title", title);
            CommonUtils.ValidateNullArgument("sshKey", sshKey);

            await RemoveSSHKey(repoUrl, token, tokenSecret, sshKey);

            // deploy key only allow read-only access
            var sshKeyInfo = new BitbucketSSHKeyInfo { label = title, key = sshKey };
            var requestUri = GetRequestUri(repoUrl, "deploy-keys");
            await _provider.PostAsJsonAsync("AddSSHKey", requestUri, token, tokenSecret, sshKeyInfo);
        }

        public async Task<bool> RemoveSSHKey(string repoUrl, string token, string tokenSecret, string sshKey)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);
            CommonUtils.ValidateNullArgument("sshKey", sshKey);

            var sshKeyInfo = await GetSSHKey(repoUrl, token, tokenSecret, sshKey);
            if (sshKeyInfo != null)
            {
                var requestUri = GetRequestUri(repoUrl, "deploy-keys", sshKeyInfo.pk);
                await _provider.DeleteAsync("RemoveSSHKey", requestUri, token, tokenSecret);
            }

            return sshKeyInfo != null;
        }

        public async Task<Privilege[]> GetPrivilege(string repoUrl, string userName, string token, string tokenSecret)
        {
            BitbucketRepoInfo repo = await this.GetRepository(repoUrl, token, tokenSecret);
            string requestUri = string.Format(
                CultureInfo.InvariantCulture,
                @"https://api.bitbucket.org/1.0/privileges/{0}/{1}/{2}",
                repo.owner,
                repo.slug,
                userName);

            return await _provider.GetAsync<Privilege[]>("GetPrivilege", requestUri, token, tokenSecret);
        }

        private async Task<BitbucketSSHKeyFullInfo> GetSSHKey(string repoUrl, string token, string tokenSecret, string sshKey)
        {
            var requestUri = GetRequestUri(repoUrl, "deploy-keys");
            var sshKeys = await _provider.GetAsync<BitbucketSSHKeyFullInfo[]>("GetSSHKey", requestUri, token, tokenSecret);
            return sshKeys.FirstOrDefault(info => SSHKeyEquals(info.key, sshKey));
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

        private async Task<BitbucketHookInfo> GetWebHookInfo(string repoUrl, string token, string tokenSecret, string hookUrl)
        {
            var hookUri = new Uri(hookUrl);
            var requestUri = GetRequestUri(repoUrl, "services");
            var services = await _provider.GetAsync<BitbucketHookInfo[]>("GetWebHookInfo", requestUri, token, tokenSecret);

            return services.FirstOrDefault(service =>
            {
                if (service.service != null && service.service.url != null && string.Equals(service.service.type, "POST", StringComparison.OrdinalIgnoreCase))
                {
                    Uri configUri;
                    if (Uri.TryCreate(service.service.url, UriKind.Absolute, out configUri))
                    {
                        return string.Equals(hookUri.Host, configUri.Host, StringComparison.OrdinalIgnoreCase);
                    }
                }

                return false;
            });
        }

        static private string GetRequestUri(string repoUrl, params string[] paths)
        {
            // repoId is the clone (https or ssh) url
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
                return String.Format("https://api.bitbucket.org/1.0/repositories/{0}/{1}", parts[parts.Length - 2], parts[parts.Length - 1]);
            }
            else
            {
                return String.Format("https://api.bitbucket.org/1.0/repositories/{0}/{1}/{2}", parts[parts.Length - 2], parts[parts.Length - 1], String.Join("/", paths));
            }
        }

        class BitbucketProvider : OAuthV1Provider
        {
            public BitbucketProvider(string clientId, string clientSecret, Func<HttpClient> httpClientFactory)
                : base(clientId, clientSecret, httpClientFactory)
            {
            }

            public override string Name
            {
                get { return "Bitbucket"; }
            }

            public override string OAuthRequestTokenUri
            {
                get { return "https://bitbucket.org/!api/1.0/oauth/request_token"; }
            }

            public override string OAuthAuthorizeUri
            {
                get { return "https://bitbucket.org/!api/1.0/oauth/authenticate"; }
            }

            public override string OAuthAccessTokenUri
            {
                get { return "https://bitbucket.org/!api/1.0/oauth/access_token"; }
            }

            public override string GetErrorMessage(string content)
            {
                return content;
            }
        }

        public class BitbucketUserInfo
        {
            public BitbucketAccountInfo user { get; set; }
        }

        public class BitbucketAccountInfo
        {
            public string username { get; set; }
            public string first_name { get; set; }
            public string last_name { get; set; }
            public string display_name { get; set; }
            public string resource_uri { get; set; }
        }

        public class BitbucketSSHKeyFullInfo : BitbucketSSHKeyInfo
        {
            public string pk { get; set; }
        }

        public class BitbucketSSHKeyInfo
        {
            public string label { get; set; }

            public string key { get; set; }
        }

        public class BitbucketHookInfo
        {
            public string id { get; set; }

            public BitbucketServiceInfo service { get; set; }
        }

        public class CreateBitbucketHookInfo
        {
            public CreateBitbucketHookInfo(string hookUrl)
            {
                this.URL = hookUrl;
            }

            public string URL { get; set; }
        }

        public class BitbucketServiceInfo
        {
            public BitbucketFieldInfo[] fields { get; set; }

            public string type { get; set; }

            public string url
            {
                get
                {
                    BitbucketFieldInfo info = this.fields == null ? null : this.fields.FirstOrDefault(field => string.Equals(field.name, "URL", StringComparison.OrdinalIgnoreCase));
                    return info == null ? null : info.value;
                }
            }
        }

        public class BitbucketFieldInfo
        {
            public string name { get; set; }

            public string value { get; set; }
        }

        public class BitbucketRepoInfo
        {
            public string RepoUrl
            {
                get
                {
                    if (String.Equals(scm, "hg", StringComparison.OrdinalIgnoreCase))
                    {
                        return String.Format(is_private ? "ssh://hg@bitbucket.org/{0}/{1}" : "https://bitbucket.org/{0}/{1}", this.owner, this.slug);
                    }
                    else
                    {
                        return String.Format(is_private ? "git@bitbucket.org:{0}/{1}.git" : "https://bitbucket.org/{0}/{1}.git", this.owner, this.slug);
                    }
                }
            }

            public string owner { get; set; }

            public string scm { get; set; }

            public string name { get; set; }

            public string slug { get; set; }

            public bool is_private { get; set; }

            public string url
            {
                get { return String.Format("https://api.bitbucket.org/1.0/repositories/{0}/{1}", this.owner, this.slug); }
            }
        }

        public class BitbucketBranchInfo
        {
            public string name { get; set; }
            public string raw_node { get; set; }
            public string message { get; set; }
        }

        public class Privilege
        {
            public string privilege { get; set; }
            public string repo { get; set; }
            public BitbucketAccountInfo user { get; set; }
        }

        #region V2 API
        /// <summary>
        /// List repo by role
        /// </summary>
        /// <param name="role">Can be "owner|admin|contributor|member"</param>
        /// <param name="token"></param>
        /// <param name="tokenSecret"></param>
        /// <returns></returns>
        public async Task<List<BitbucketV2Repository>> ListRepositoriesV2(string role, string token, string tokenSecret)
        {
            List<BitbucketV2Repository> repos = new List<BitbucketV2Repository>();
            BitbucketV2Paging<BitbucketV2Repository> result = null;
            string url = string.Format("https://api.bitbucket.org/2.0/repositories?role={0}", role);

            do
            {
                result = await _provider.GetAsync<BitbucketV2Paging<BitbucketV2Repository>>(
                    "ListRepositoriesV2",
                    url,
                    token,
                    tokenSecret);

                url = result.next;
                repos.AddRange(result.values);
            } while (url != null);

            return repos;
        }
        #endregion
    }
}