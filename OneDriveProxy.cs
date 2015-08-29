// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

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
    // to create application, https://account.live.com/developers/applications/index
    public class OneDriveProxy
    {
        public const string OneDriveApiAppUriPrefix = @"https://api.onedrive.com/v1.0/drive/special/approot:/";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly Func<HttpClient> _httpClientFactory;

        public OneDriveProxy(string clientId = null, string clientSecret = null, Func<HttpClient> httpClientFactory = null)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _httpClientFactory = httpClientFactory;
        }

        // https://login.live.com/oauth20_authorize.srf?client_id={client_id}&scope={scope}&response_type=token&redirect_uri={redirect_uri}
        public string GetOAuthUri(string state = null, string redirectUri = null)
        {
            CommonUtils.ValidateNullArgument("_clientId", _clientId);

            StringBuilder strb = new StringBuilder();
            strb.Append("https://login.live.com/oauth20_authorize.srf");
            strb.AppendFormat("?client_id={0}", WebUtility.UrlEncode(_clientId));
            if (!String.IsNullOrEmpty(redirectUri))
            {
                strb.AppendFormat("&redirect_uri={0}", WebUtility.UrlEncode(redirectUri));
            }
            strb.AppendFormat("&scope={0}", WebUtility.UrlEncode("onedrive.appfolder wl.basic wl.offline_access wl.emails"));
            strb.Append("&response_type=code");
            strb.AppendFormat("&state={0}", WebUtility.UrlEncode(state ?? String.Empty));

            return strb.ToString();
        }

        // https://login.live.com/oauth20_authorize.srf?code=df6aa589-1080-b241-b410-c4dff65dbf7c
        // https://onedrive.test.com/Home/Contact?error=invalid_scope&error_description=The%20provided%20value%20for%20the%20input%20parameter%20%27scope%27%20is%20not%20valid.%20The%20scope%20%27onedrive.appfolder%27%20does%20not%20exist.&state=this%20is%20state
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
                throw new OAuthException("OneDrive: " + message, HttpStatusCode.Unauthorized, callbackUri);
            }

            if (validateState != null)
            {
                validateState(queryStrings["state"]);
            }

            var code = queryStrings["code"];
            if (String.IsNullOrEmpty(code))
            {
                throw new OAuthException("OneDrive: missing code query string.", HttpStatusCode.Unauthorized, callbackUri);
            }

            var redirectUri = new Uri(callbackUri);
            redirectUri = new Uri(redirectUri, redirectUri.AbsolutePath);

            var strb = new StringBuilder();
            strb.AppendFormat("client_id={0}", WebUtility.UrlEncode(_clientId));
            strb.AppendFormat("&client_secret={0}", WebUtility.UrlEncode(_clientSecret));
            strb.AppendFormat("&redirect_uri={0}", WebUtility.UrlEncode(redirectUri.AbsoluteUri));
            strb.AppendFormat("&code={0}", WebUtility.UrlEncode(code));
            strb.Append("&grant_type=authorization_code");

            var content = new StringContent(strb.ToString());
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.FormUrlEncodedMediaType);
            using (var client = CreateHttpClient())
            {
                using (var response = await client.PostAsync("https://login.live.com/oauth20_token.srf", content))
                {
                    var info = await ProcessOAuthResponse("Authorize", response);
                    info.redirect_uri = redirectUri.AbsoluteUri;
                    info.expires_at = DateTime.UtcNow.AddSeconds(info.expires_in);
                    return info;
                }
            }
        }

        public async Task<OAuthInfo> RefreshToken(string redirectUri, string refreshToken)
        {
            var strb = new StringBuilder();
            strb.AppendFormat("client_id={0}", WebUtility.UrlEncode(_clientId));
            strb.AppendFormat("&client_secret={0}", WebUtility.UrlEncode(_clientSecret));
            strb.AppendFormat("&redirect_uri={0}", WebUtility.UrlEncode(redirectUri));
            strb.AppendFormat("&refresh_token={0}", WebUtility.UrlEncode(refreshToken));
            strb.Append("&grant_type=refresh_token");

            var content = new StringContent(strb.ToString());
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.FormUrlEncodedMediaType);
            using (var client = CreateHttpClient())
            {
                using (var response = await client.PostAsync("https://login.live.com/oauth20_token.srf", content))
                {
                    var info = await ProcessOAuthResponse("Authorize", response);
                    info.redirect_uri = redirectUri;
                    info.expires_at = DateTime.UtcNow.AddSeconds(info.expires_in);
                    return info;
                }
            }
        }

        public async Task<LiveAccountInfo> GetAccountInfo(string accessToken)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            var requestUri = String.Format("https://apis.live.net/v5.0/me");
            using (var client = CreateHttpClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    return await ProcessResponse<LiveAccountInfo>("GetAccountInfo", response);
                }
            }
        }

        public async Task<OneDriveItem[]> ListFolders(string accessToken)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);

            var requestUri = String.Format("https://api.onedrive.com/v1.0/drive/special/approot/children");
            using (var client = CreateHttpClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var items = await ProcessResponse<OneDriveItemCollection>("ListFolders", response);
                    return items.value;
                }
            }
        }

        public async Task<OneDriveItem> EnsureFolder(string accessToken, string path)
        {
            try
            {
                return await this.CreateFolder(accessToken, path);
            }
            catch (OAuthException oae)
            {
                if (oae.StatusCode != HttpStatusCode.Conflict)
                    throw;
            }

            return await this.GetFolder(accessToken, path);
        }

        public async Task<OneDriveItem> CreateFolder(string accessToken, string path)
        {
            const string payloadFormat = "{{\"name\":\"{0}\",\"folder\":{{}}}}";

            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("path", path);

            var content = new StringContent(String.Format(payloadFormat, path), Encoding.UTF8, Constants.JsonMediaType);
            var requestUri = String.Format("https://api.onedrive.com/v1.0/drive/special/approot/children");
            using (var client = CreateHttpClient(accessToken))
            {
                using (var response = await client.PostAsync(requestUri, content))
                {
                    return await ProcessResponse<OneDriveItem>("CreateFolder", response);
                }
            }
        }

        public async Task<OneDriveItem> GetFolder(string accessToken, string path)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("path", path);

            var requestUri = GetRequestUri(path);
            using (var client = CreateHttpClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    return await ProcessResponse<OneDriveItem>("GetFolder", response);
                }
            }
        }

        public async Task<bool> IsFolderExisted(string accessToken, string path)
        {
            try
            {
                await GetFolder(accessToken, path);
                return true;
            }
            catch (OAuthException oae)
            {
                if (oae.StatusCode == HttpStatusCode.NotFound)
                {
                    return false;
                }

                throw;
            }
        }

        public async Task<OneDriveItem> GetFile(string accessToken, string path)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("path", path);

            var requestUri = GetRequestUri(path);
            using (var client = CreateHttpClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    return await ProcessResponse<OneDriveItem>("GetFile", response);
                }
            }
        }

        public async Task<StreamContent> GetFileContent(string accessToken, string path)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("path", path);

            var requestUri = GetRequestUri(path);
            requestUri = await GetItemUri(accessToken, requestUri) + "/content";
            using (var client = CreateHttpClient(accessToken))
            {
                var response = await client.GetAsync(requestUri);
                return (StreamContent)response.Content;
            }
        }

        public async Task<OneDriveChangeCollection> GetChanges(string accessToken, string path, string cursor)
        {
            CommonUtils.ValidateNullArgument("accessToken", accessToken);
            CommonUtils.ValidateNullArgument("path", path);

            var requestUri = GetRequestUri(path);
            requestUri = await GetItemUri(accessToken, requestUri) + "/view.changes";

            var result = new OneDriveChangeCollection();
            using (var client = CreateHttpClient(accessToken))
            {
                var next = cursor;
                var ids = new Dictionary<string, ItemInfo>();
                Dictionary<string, object> changes = null;
                var serializer = JsonUtils.CreateJsonSerializer();
                do
                {
                    var uri = requestUri;
                    if (!String.IsNullOrEmpty(next))
                    {
                        uri = String.Format("{0}?token={1}", requestUri, next);
                    }

                    using (var response = await client.GetAsync(uri))
                    {
                        changes = await ProcessResponse<Dictionary<string, object>>("GetChanges", response);
                    }

                    if (changes.ContainsKey("@changes.resync"))
                    {
                        if (String.IsNullOrEmpty(next))
                        {
                            throw new InvalidOperationException("Unable to sync OneDrive @changes.resync is " + changes["@changes.resync"]);
                        }

                        // resync
                        next = null;
                        changes["@changes.hasMoreChanges"] = true;
                        result = new OneDriveChangeCollection();
                        continue;
                    }

                    var items = serializer.ConvertToType<OneDriveItemCollection>(changes);

                    // changes
                    result.AddRange(GetChanges(items, ids));

                    // set next token
                    next = (string)changes["@changes.token"];

                } while ((bool)changes["@changes.hasMoreChanges"]);

                result.Cursor = next;
                return result;
            }
        }

        private IEnumerable<OneDriveChange> GetChanges(OneDriveItemCollection items, Dictionary<string, ItemInfo> ids)
        {
            foreach (var item in items.value)
            {
                ids[item.id] = new ItemInfo
                {
                    name = item.name,
                    parentId = item.parentReference.id
                };

                var path = GetPath(ids, item);
                if (item.deleted != null)
                {
                    yield return new OneDriveChange
                    {
                        Path = path,
                        IsDeleted = true
                    };
                }
                else
                {
                    yield return new OneDriveChange
                    {
                        ContentUri = String.Format("https://api.onedrive.com/v1.0/drive/items/{0}", item.id),
                        Path = path,
                        IsFile = item.file != null,
                        LastModifiedUtc = item.lastModifiedDateTime.ToUniversalTime()
                    };
                }
            }
        }

        private string GetPath(Dictionary<string, ItemInfo> ids, OneDriveItem item)
        {
            var path = item.name;
            var parentId = item.parentReference.id;
            while (true)
            {
                ItemInfo info;
                if (!ids.TryGetValue(parentId, out info))
                {
                    return path;
                }

                path = String.Format(@"{0}\{1}", info.name, path);
                parentId = info.parentId;
            }
        }

        class ItemInfo
        {
            public string name { get; set; }
            public string parentId { get; set; }
        }

        private async Task<string> GetItemUri(string accessToken, string requestUri)
        {
            using (var client = CreateHttpClient(accessToken))
            {
                using (var response = await client.GetAsync(requestUri))
                {
                    var item = await ProcessResponse<OneDriveItem>("GetItemUri", response);
                    return String.Format("https://api.onedrive.com/v1.0/drive/items/{0}", item.id);
                }
            }
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

        private async Task<T> ProcessResponse<T>(string operation, HttpResponseMessage response)
        {
            string content = await response.ReadContentAsync();
            if (response.IsSuccessStatusCode)
            {
                return JsonUtils.Deserialize<T>(content);
            }

            throw CreateOneDriveException(operation, content, response.StatusCode);
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
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("bearer", accessToken);
            }
            return client;
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
                            message = String.Format("OneDrive {0}: {1}", operation, error.error_description);
                        }
                        else if (!String.IsNullOrEmpty(error.error))
                        {
                            message = String.Format("OneDrive {0}: {1}", operation, error.error);
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
                message = String.Format("OneDrive {0}: ({1}) {2}.", operation, (int)statusCode, statusCode);
            }

            return new OAuthException(message, statusCode, content);
        }

        // https://onedrive.github.io/resources/error.htm
        private static OAuthException CreateOneDriveException(string operation, string content, HttpStatusCode statusCode)
        {
            string message = null;
            if (!String.IsNullOrEmpty(content))
            {
                try
                {
                    var detail = JsonUtils.Deserialize<OneDriveError>(content);
                    if (detail != null && detail.error != null)
                    {
                        if (!String.IsNullOrEmpty(detail.error.message))
                        {
                            message = String.Format("OneDrive {0}: {1}", operation, detail.error.message);
                        }
                        else if (!String.IsNullOrEmpty(detail.error.code))
                        {
                            message = String.Format("OneDrive {0}: {1}", operation, detail.error.code);
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
                message = String.Format("OneDrive {0}: ({1}) {2}.", operation, (int)statusCode, statusCode);
            }

            return new OAuthException(message, statusCode, content);
        }

        public class LiveAccountInfo
        {
            public string id { get; set; }
            public string name { get; set; }
            public string first_name { get; set; }
            public string last_name { get; set; }
            public string link { get; set; }
            public string gender { get; set; }
            public string locale { get; set; }
            public DateTime updated_time { get; set; }
            public LiveEmailInfo emails { get; set; }
        }

        public class LiveEmailInfo
        {
            public string preferred { get; set; }
            public string account { get; set; }
            public string personal { get; set; }
            public string business { get; set; }
        }

        public class OneDriveItemCollection
        {
            public OneDriveItem[] value { get; set; }
        }

        public class OneDriveItem
        {
            public string id { get; set; }
            public string name { get; set; }
            public int size { get; set; }
            public string cTag { get; set; }
            public string eTag { get; set; }
            public DateTime createdDateTime { get; set; }
            public DateTime lastModifiedDateTime { get; set; }
            public OneDriveFolderFacet folder { get; set; }
            public OneDriveFileFacet file { get; set; }

            public Dictionary<string, object> deleted { get; set; }
            public OneDriveParentReference parentReference { get; set; }
            public string repoUrl { get { return string.Format(CultureInfo.InvariantCulture, "{0}{1}", OneDriveApiAppUriPrefix, name); } }
        }

        public class OneDriveParentReference
        {
            public string id { get; set; }
            public string driveId { get; set; }
        }

        public class OneDriveFolderFacet
        {
            public int childCount { get; set; }
        }

        public class OneDriveFileFacet
        {
            public OneDriveFileHashes hashes { get; set; }
            public string mimeType { get; set; }
        }

        public class OneDriveFileHashes
        {
            public string crc32Hash { get; set; }
            public string sha1Hash { get; set; }
        }

        // https://onedrive.github.io/resources/error.htm
        public class OneDriveError
        {
            public OneDriveErrorDetail error { get; set; }
        }

        public class OneDriveErrorDetail
        {
            public string code { get; set; }
            public string message { get; set; }
            public OneDriveErrorDetail innererror { get; set; }
        }

        public class OAuthInfo
        {
            public string token_type { get; set; }
            public int expires_in { get; set; }
            public string scope { get; set; }
            public string access_token { get; set; }
            public string authentication_token { get; set; }
            public string refresh_token { get; set; }
            public string user_id { get; set; }
            public string redirect_uri { get; set; }
            public DateTime expires_at { get; set; }
        }

        public class OAuthError
        {
            // oauth error
            public string lc { get; set; }
            public string error { get; set; }
            public string error_description { get; set; }
        }

        public class OneDriveChangeCollection : List<OneDriveChange>
        {
            public string Cursor { get; set; }
        }

        public class OneDriveChange
        {
            public string Path { get; set; }
            public bool IsFile { get; set; }
            public bool IsDeleted { get; set; }
            public string ContentUri { get; set; }
            public DateTime LastModifiedUtc { get; set; }
        }

        private static string GetRequestUri(string path)
        {
            Uri uri;
            if (Uri.TryCreate(path, UriKind.Absolute, out uri))
            {
                return path;
            }
            else
            {
                return string.Format(CultureInfo.InvariantCulture, "{0}{1}", OneDriveApiAppUriPrefix, path);
            }
        }
    }
}