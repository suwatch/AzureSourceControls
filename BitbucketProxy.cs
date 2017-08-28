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
using Microsoft.Web.Hosting.SourceControls.Utils;

namespace Microsoft.Web.Hosting.SourceControls
{
    public class BitbucketProxy
    {
        private const string SSHPrefix = "ssh-rsa ";
        private const string ApiBaseUrl = "https://api.bitbucket.org/1.0";
        private readonly BitbucketProvider _provider;

        public BitbucketProxy(string clientId, string clientSecret, Func<HttpClientHandler, HttpClient> httpClientFactory = null)
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

        public async Task<List<BitbucketRepoInfo>> ListRepositories(string token, string tokenSecret, string role = "admin")
        {
            var repos = new List<BitbucketV2Proxy.BitbucketV2Repository>();
            string url = string.Format("https://api.bitbucket.org/2.0/repositories?role={0}", role);

            do
            {
                var result = await _provider.GetAsync<BitbucketV2Proxy.BitbucketV2Paging<BitbucketV2Proxy.BitbucketV2Repository>>(
                    "ListRepositories",
                    url,
                    token,
                    tokenSecret);

                url = result.next;
                repos.AddRange(result.values);
            } while (url != null);

            return repos.Select(r => r.ToRepoInfo()).ToList();
        }

        // Deprecated due to better V2 api
        //public async Task<IEnumerable<BitbucketRepoInfo>> ListRepositories(string token, string tokenSecret)
        //{
        //    CommonUtils.ValidateNullArgument("token", token);
        //    CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);
        //    return await _provider.GetAsync<BitbucketRepoInfo[]>("ListRepositories", "https://api.bitbucket.org/1.0/user/repositories/", token, tokenSecret);
        //}

        public async Task<BitbucketRepoInfo> GetRepository(string repoUrl, string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl);
            return await _provider.GetAsync<BitbucketRepoInfo>("GetRepository", requestUri, token, tokenSecret);
        }

        public async Task<BitbucketBranchInfo[]> ListBranches(string repoUrl, string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "branches-tags");
            var info = await _provider.GetAsync<BitbucketProxy.BitbucketBranchesTagsInfo>("ListBranches", requestUri, token, tokenSecret);
            return info.branches;
        }

        public async Task<StreamContent> DownloadFile(string repoUrl, string path, string token, string tokenSecret, string branch = "master")
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("path", path);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);
            CommonUtils.ValidateNullArgument("branch", branch);

            var requestUri = String.Format("{0}/{1}/{2}", BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "raw"), branch, path);
            return await _provider.GetStreamAsync("DownloadFile", requestUri, token, tokenSecret);
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

                var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "services", hook.id);
                await _provider.PutAsJsonAsync("UpdateWebHook", requestUri, token, tokenSecret, new CreateBitbucketHookInfo(hookUrl));
            }
            else
            {
                var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "services");
                var content = new StringContent(String.Format("type=POST;URL={0}", hookUrl), Encoding.UTF8, "application/text");
                await _provider.PostAsync("AddWebHook", requestUri, token, tokenSecret, content);
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
                var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "services", hook.id);
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
            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "deploy-keys");
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
                var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "deploy-keys", sshKeyInfo.pk);
                await _provider.DeleteAsync("RemoveSSHKey", requestUri, token, tokenSecret);
            }

            return sshKeyInfo != null;
        }

        private async Task<BitbucketSSHKeyFullInfo> GetSSHKey(string repoUrl, string token, string tokenSecret, string sshKey)
        {
            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "deploy-keys");
            var sshKeys = await _provider.GetAsync<BitbucketSSHKeyFullInfo[]>("GetSSHKey", requestUri, token, tokenSecret);
            return sshKeys.FirstOrDefault(info => SSHKeyEquals(info.key, sshKey));
        }

        internal static bool SSHKeyEquals(string src, string dst)
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
            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "services");
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

        public async Task<BitbucketHookInfo[]> ListWebHooks(string repoUrl, string token, string tokenSecret)
        {
            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "services");
            return await _provider.GetAsync<BitbucketHookInfo[]>("ListWebHooks", requestUri, token, tokenSecret);
        }

        public async Task<BitbucketSSHKeyFullInfo[]> ListSSHKeys(string repoUrl, string token, string tokenSecret)
        {
            var requestUri = BitbucketProxyHelper.GetRequestUri(ApiBaseUrl, repoUrl, "deploy-keys");
            return await _provider.GetAsync<BitbucketSSHKeyFullInfo[]>("ListSSHKeys", requestUri, token, tokenSecret);
        }

        class BitbucketProvider : OAuthV1Provider
        {
            public BitbucketProvider(string clientId, string clientSecret, Func<HttpClientHandler, HttpClient> httpClientFactory)
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

        public class BitbucketBranchesTagsInfo
        {
            public BitbucketBranchInfo[] branches { get; set; }
        }

        public class BitbucketBranchInfo
        {
            public string name { get; set; }
            public string changeset { get; set; }
            public bool mainbranch { get; set; }
        }
    }
}