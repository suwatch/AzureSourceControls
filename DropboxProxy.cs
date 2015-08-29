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
    public class DropboxProxy
    {
        private readonly DropboxProvider _provider;

        public DropboxProxy(string clientId, string clientSecret, Func<HttpClient> httpClientFactory = null)
        {
            _provider = new DropboxProvider(clientId, clientSecret, httpClientFactory);
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
                throw new OAuthException("Dropbox Authorize: missing oauth_token query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            if (!String.Equals(oauth_token, token))
            {
                throw new OAuthException("Dropbox Authorize: mismatch oauth token.", HttpStatusCode.Unauthorized, callbackUri);
            }

            var uid = queryStrings["uid"];
            if (String.IsNullOrEmpty(uid))
            {
                throw new OAuthException("Dropbox Authorize: missing uid query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            return await _provider.Authorize(uid, token, tokenSecret);
        }

        public async Task<DropboxAccountInfo> GetAccountInfo(string token, string tokenSecret)
        {
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);

            return await _provider.GetAsync<DropboxAccountInfo>("GetAccountInfo", "https://api.dropbox.com/1/account/info", token, tokenSecret);
        }

        public async Task<IEnumerable<string>> ListFolders(string token, string tokenSecret, string appName)
        {
            CommonUtils.ValidateNullArgument("token", token);
            CommonUtils.ValidateNullArgument("tokenSecret", tokenSecret);
            CommonUtils.ValidateNullArgument("appName", appName);

            var info = await _provider.GetAsync<DropboxMetadataInfo>("ListFolders", "https://api.dropbox.com/1/metadata/sandbox", token, tokenSecret);
            return info.contents.Where(c => c.is_dir)
                .Select(c => String.Format("https://www.dropbox.com/home/Apps/{0}/{1}", appName, c.path.Trim('/')));
        }

        public async Task<bool> CreateFolder(string token, string tokenSecret, string path)
        {
            path = '/' + path.Trim('/').Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries).Last();

            var folders = await ListFolders(token, tokenSecret, "app");
            if (!FolderExists(folders, path))
            {
                var requestUri = String.Format("https://api.dropbox.com/1/fileops/create_folder?root=sandbox&path={0}", path);
                return await _provider.PostAsync("CreateFolder", requestUri, token, tokenSecret, null);
            }

            return false;
        }

        private bool FolderExists(IEnumerable<string> folders, string path)
        {
            folders = folders.Select(folder => '/' + folder.Trim('/').Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries).Last());
            return folders.Any(folder => String.Equals(folder, path, StringComparison.OrdinalIgnoreCase));
        }

        public class DropboxMetadataInfo
        {
            public string path { get; set; }
            public bool is_dir { get; set; }
            public List<DropboxMetadataInfo> contents { get; set; }
        }

        public class DropboxAccountInfo
        {
            public string Id
            {
                get { return email; }
            }

            public string display_name { get; set; }

            public string email { get; set; }
        }

        class DropboxProvider : OAuthV1Provider
        {
            public DropboxProvider(string clientId, string clientSecret, Func<HttpClient> httpClientFactory)
                : base(clientId, clientSecret, httpClientFactory)
            {
            }

            public override string Name
            {
                get { return "Dropbox"; }
            }

            public override string OAuthRequestTokenUri
            {
                get { return "https://api.dropbox.com/1/oauth/request_token"; }
            }

            public override string OAuthAuthorizeUri
            {
                get { return "https://www.dropbox.com/1/oauth/authorize"; }
            }

            public override string OAuthAccessTokenUri
            {
                get { return "https://api.dropbox.com/1/oauth/access_token"; }
            }

            public override string GetErrorMessage(string content)
            {
                if (!String.IsNullOrEmpty(content))
                {
                    var info = JsonUtils.Deserialize<OAuthError>(content);
                    if (info != null)
                    {
                        return info.error;
                    }
                }

                return content;
            }
        }

        public class OAuthError
        {
            public string error { get; set; }
        }
    }
}