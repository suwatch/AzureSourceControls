// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using AzureSourceControls.Utils;

namespace AzureSourceControls
{
    public abstract class OAuthV1Provider
    {
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly Func<HttpClient> _httpClientFactory;

        protected OAuthV1Provider(string clientId, string clientSecret, Func<HttpClient> httpClientFactory)
        {
            CommonUtils.ValidateNullArgument("clientId", clientId);
            CommonUtils.ValidateNullArgument("clientSecret", clientSecret);

            _clientId = clientId;
            _clientSecret = clientSecret;
            _httpClientFactory = httpClientFactory;
        }

        public abstract string Name
        {
            get;
        }

        public abstract string OAuthRequestTokenUri
        {
            get;
        }

        public abstract string OAuthAuthorizeUri
        {
            get;
        }

        public abstract string OAuthAccessTokenUri
        {
            get;
        }

        public virtual async Task<OAuthV1Info> GetOAuthInfo(string redirectUri, string scope = null)
        {
            string token = null;
            string tokenSecret = null;
            using (HttpClient client = CreateHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = OAuthV1Utils.GetOAuthHeader(
                    _clientId, 
                    _clientSecret, 
                    HttpMethod.Post,
                    requestUri: OAuthRequestTokenUri,
                    redirectUri: redirectUri,
                    scope: scope);
                using (var response = await client.PostAsync(OAuthRequestTokenUri, null))
                {
                    string content = null;
                    if (response.Content != null)
                    {
                        content = await response.Content.ReadAsStringAsync();
                    }

                    if (!response.IsSuccessStatusCode)
                    {
                        // content is html (not json).  pass null explicitly
                        throw new OAuthException(String.Format("{0} GetOAuthInfo: {1}", Name, GetErrorMessage(null, response.StatusCode)), response.StatusCode, content);
                    }

                    var query = HttpUtility.ParseQueryString(content);
                    
                    token = query["oauth_token"];
                    if (String.IsNullOrEmpty(token))
                    {
                        throw new OAuthException(String.Format("{0} GetOAuthInfo: Missing oauth_token.", Name), response.StatusCode, content);
                    }

                    tokenSecret = query["oauth_token_secret"];
                    if (String.IsNullOrEmpty(tokenSecret))
                    {
                        throw new OAuthException(String.Format("{0} GetOAuthInfo: Missing oauth_token_secret.", Name), response.StatusCode, content);
                    }
                }
            }

            StringBuilder strb = new StringBuilder();
            strb.Append(OAuthAuthorizeUri);
            strb.AppendFormat("?oauth_token={0}", WebUtility.UrlEncode(token));
            strb.AppendFormat("&oauth_callback={0}", WebUtility.UrlEncode(redirectUri));

            return new OAuthV1Info(strb.ToString(), token, tokenSecret);
        }

        public virtual async Task<OAuthV1Info> Authorize(string verifier, string token, string tokenSecret)
        {
            using (HttpClient client = CreateHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = OAuthV1Utils.GetOAuthHeader(
                    _clientId, 
                    _clientSecret, 
                    HttpMethod.Post,
                    requestUri: OAuthAccessTokenUri, 
                    token: token, 
                    tokenSecret: tokenSecret,
                    verifier: verifier);
                using (var response = await client.PostAsync(OAuthAccessTokenUri, null))
                {
                    string content = null;
                    if (response.Content != null)
                    {
                        content = await response.Content.ReadAsStringAsync();
                    }

                    if (!response.IsSuccessStatusCode)
                    {
                        // content is html (not json).  pass null explicitly
                        throw new OAuthException(String.Format("{0} Authorize: {1}", Name, GetErrorMessage(null, response.StatusCode)), response.StatusCode, content);
                    }

                    var query = HttpUtility.ParseQueryString(content);

                    token = query["oauth_token"];
                    if (String.IsNullOrEmpty(token))
                    {
                        throw new OAuthException(String.Format("{0} Authorize: Missing oauth_token.", Name), response.StatusCode, content);
                    }

                    tokenSecret = query["oauth_token_secret"];
                    if (String.IsNullOrEmpty(tokenSecret))
                    {
                        throw new OAuthException(String.Format("{0} Authorize: Missing oauth_token_secret.", Name), response.StatusCode, content);
                    }

                    return new OAuthV1Info(null, token, tokenSecret);
                }
            }
        }

        public virtual async Task<T> GetAsync<T>(string operation, string requestUri, string token, string tokenSecret)
        {
            using (HttpClient client = CreateHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = OAuthV1Utils.GetOAuthHeader(
                    _clientId,
                    _clientSecret,
                    HttpMethod.Get,
                    requestUri,
                    token: token,
                    tokenSecret: tokenSecret);
                using (var response = await client.GetAsync(requestUri))
                {
                    return await ProcessResponse<T>(operation, response);
                }
            }
        }

        public virtual async Task<bool> PatchAsJsonAsync<T>(string operation, string requestUri, string token, string tokenSecret, T value)
        {
            using (HttpClient client = CreateHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = OAuthV1Utils.GetOAuthHeader(
                    _clientId,
                    _clientSecret,
                    new HttpMethod("PATCH"),
                    requestUri,
                    token: token,
                    tokenSecret: tokenSecret);
                using (var response = await client.PatchAsJsonAsync(requestUri, value))
                {
                    return await ProcessEmptyResponse(operation, response);
                }
            }
        }

        public virtual async Task<bool> PostAsJsonAsync<T>(string operation, string requestUri, string token, string tokenSecret, T value)
        {
            using (HttpClient client = CreateHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = OAuthV1Utils.GetOAuthHeader(
                    _clientId,
                    _clientSecret,
                    HttpMethod.Post,
                    requestUri,
                    token: token,
                    tokenSecret: tokenSecret);

                using (var response = await client.PostAsJsonAsync(requestUri, value))
                {
                    return await ProcessEmptyResponse(operation, response);
                }
            }
        }

        public virtual async Task<bool> PostAsync(string operation, string requestUri, string token, string tokenSecret, HttpContent content)
        {
            using (HttpClient client = CreateHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = OAuthV1Utils.GetOAuthHeader(
                    _clientId,
                    _clientSecret,
                    HttpMethod.Post,
                    requestUri,
                    token: token,
                    tokenSecret: tokenSecret);

                using (var response = await client.PostAsync(requestUri, content))
                {
                    return await ProcessEmptyResponse(operation, response);
                }
            }
        }

        public virtual async Task<bool> PutAsJsonAsync<T>(string operation, string requestUri, string token, string tokenSecret, T value)
        {
            using (HttpClient client = CreateHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = OAuthV1Utils.GetOAuthHeader(
                    _clientId,
                    _clientSecret,
                    HttpMethod.Put,
                    requestUri,
                    token: token,
                    tokenSecret: tokenSecret);

                using (var response = await client.PutAsJsonAsync(requestUri, value))
                {
                    return await ProcessEmptyResponse(operation, response);
                }
            }
        }

        public virtual async Task<bool> DeleteAsync(string operation, string requestUri, string token, string tokenSecret)
        {
            using (HttpClient client = CreateHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = OAuthV1Utils.GetOAuthHeader(
                    _clientId,
                    _clientSecret,
                    HttpMethod.Delete,
                    requestUri,
                    token: token,
                    tokenSecret: tokenSecret);

                using (var response = await client.DeleteAsync(requestUri))
                {
                    return await ProcessEmptyResponse(operation, response);
                }
            }
        }

        private async Task<T> ProcessResponse<T>(string operation, HttpResponseMessage response)
        {
            string content = await response.ReadContentAsync();
            if (response.IsSuccessStatusCode)
            {
                return JsonUtils.Deserialize<T>(content);
            }

            throw new OAuthException(String.Format("{0} {1}: {2}", Name, operation, GetErrorMessage(null, response.StatusCode)), response.StatusCode, content);
        }

        private async Task<bool> ProcessEmptyResponse(string operation, HttpResponseMessage response)
        {
            string content = await response.ReadContentAsync();
            if (response.IsSuccessStatusCode)
            {
                return true;
            }

            throw new OAuthException(String.Format("{0} {1}: {2}", Name, operation, GetErrorMessage(null, response.StatusCode)), response.StatusCode, content);
        }

        private string GetErrorMessage(string content, HttpStatusCode statusCode)
        {
            var message = GetErrorMessage(content);
            if (!String.IsNullOrEmpty(message))
            {
                return message;
            }

            return String.Format("({0}) {1}.", (int)statusCode, statusCode);
        }

        public abstract string GetErrorMessage(string content);

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
    }
}