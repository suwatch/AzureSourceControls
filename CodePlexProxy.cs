// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Web.Hosting.SourceControls.Utils;

namespace Microsoft.Web.Hosting.SourceControls
{
    public class CodePlexProxy
    {
        private readonly CodePlexProvider _provider;

        public CodePlexProxy(string clientId, string clientSecret, Func<HttpClient> httpClientFactory = null)
        {
            _provider = new CodePlexProvider(clientId, clientSecret, httpClientFactory);
        }

        public async Task<OAuthV1Info> GetOAuthInfo(string redirectUri)
        {
            CommonUtils.ValidateNullArgument("redirectUri", redirectUri);

            return await _provider.GetOAuthInfo(redirectUri, scope: "project_info,test_web_hook");
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
                throw new OAuthException("CodePlex Authorize: missing oauth_token query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            if (!String.Equals(oauth_token, token))
            {
                throw new OAuthException("CodePlex Authorize: mismatch oauth token.", HttpStatusCode.Unauthorized, callbackUri);
            }

            var oauth_verifier = queryStrings["oauth_verifier"];
            if (String.IsNullOrEmpty(oauth_verifier))
            {
                throw new OAuthException("CodePlex Authorize: missing oauth_verifier query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            return await _provider.Authorize(oauth_verifier, token, tokenSecret);
        }

        public async Task<CodePlexAccountInfo> GetAccountInfo(string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var requestUri = String.Format("https://www.codeplex.com/api/user");
            return await _provider.GetAsync<CodePlexAccountInfo>("GetAccountInfo", requestUri, token, tokenSecret);
        }

        public async Task<IEnumerable<CodePlexProjectInfo>> ListProjects(string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var requestUri = "https://www.codeplex.com/api/user/repos?expanded=true&role=coordinator";
            var projects = await _provider.GetAsync<CodePlexProject[]>("ListProjects", requestUri, token, tokenSecret);
            return projects.Select(p => p.Project);
        }

        public async Task<CodePlexProjectInfo> GetProject(string repoUrl, string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var requestUri = GetRequestUri(repoUrl);
            return await _provider.GetAsync<CodePlexProjectInfo>("GetProject", requestUri, token, tokenSecret);
        }

        public async Task AddWebHook(string repoUrl, string token, string tokenSecret, string hookUrl)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);
            CommonUtils.ValidateNullArgument("hookUrl", hookUrl);

            var requestUri = GetRequestUri(repoUrl);
            var projectInfo = new PatchCodePlexWebHookInfo
            {
                WebHook = new CodePlexWebHookInfo
                {
                    Host = "Azure",
                    Url = hookUrl
                }
            };

            await _provider.PatchAsJsonAsync("AddWebHook", requestUri, token, tokenSecret, projectInfo);
        }

        public async Task RemoveWebHook(string repoUrl, string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("repoUrl", repoUrl);
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            var requestUri = GetRequestUri(repoUrl);
            var projectInfo = new PatchCodePlexWebHookInfo
            {
                WebHook = new CodePlexWebHookInfo
                {
                    Host = "None"
                }
            };

            await _provider.PatchAsJsonAsync("RemoveWebHook", requestUri, token, tokenSecret, projectInfo);
        }

        static private string GetRequestUri(string repoUrl)
        {
            // repoId is the clone (https or ssh) url
            var parts = repoUrl.Split(new[] { ':', '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
            {
                throw new ArgumentException(repoUrl + " is invalid!");
            }

            return String.Format("https://www.codeplex.com/api/projects/{0}", parts[parts.Length - 1]);
        }

        class CodePlexProvider : OAuthV1Provider
        {
            public CodePlexProvider(string clientId, string clientSecret, Func<HttpClient> httpClientFactory)
                : base(clientId, clientSecret, httpClientFactory)
            {
            }

            public override string Name
            {
                get { return "CodePlex"; }
            }

            public override string OAuthRequestTokenUri
            {
                get { return "https://www.codeplex.com/oauth/requesttoken"; }
            }

            public override string OAuthAuthorizeUri
            {
                get { return "https://www.codeplex.com/oauth/authorizeuser"; }
            }

            public override string OAuthAccessTokenUri
            {
                get { return "https://www.codeplex.com/oauth/accesstoken"; }
            }

            public override string GetErrorMessage(string content)
            {
                return content;
            }
        }

        public class CodePlexAccountInfo
        {
            public string MemberSince { get; set; }
            public string UserName { get; set; }
        }

        public class CodePlexProject
        {
            public CodePlexProjectInfo Project { get; set; }
        }

        public class CodePlexProjectInfo
        {
            public string RepoUrl { get { return SourceControl.Url; } }
            public string Name { get; set; }
            public string Description { get; set; }
            public string Url { get; set; }
            public CodePlexSourceControlInfo SourceControl { get; set; }
            public CodePlexWebHookInfo WebHook { get; set; }

            public class CodePlexSourceControlInfo
            {
                public string ServerType { get; set; }
                public string Url { get; set; }
            }
        }

        public class CodePlexWebHookInfo
        {
            public string Host { get; set; }
            public string Url { get; set; }
        }

        public class PatchCodePlexWebHookInfo
        {
            public CodePlexWebHookInfo WebHook { get; set; }
        }
    }
}