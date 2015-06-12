// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace AzureSourceControls.Utils
{
    internal static class JsonUtils
    {
        private static object _syncLock = new object();

        public static Func<JavaScriptSerializer> JavaScriptSerializerFactory
        {
            get;
            set;
        }

        public static JavaScriptSerializer CreateJsonSerializer()
        {
            return JavaScriptSerializerFactory != null ? JavaScriptSerializerFactory() : new JavaScriptSerializer();
        }

        public static async Task<string> ReadContentAsync(this HttpResponseMessage response)
        {
            if (response.Content != null)
            {
                return await response.Content.ReadAsStringAsync();
            }

            return null;
        }

        public static T Deserialize<T>(string content)
        {
            if (String.IsNullOrEmpty(content))
            {
                return default(T);
            }

            var serializer = JsonUtils.CreateJsonSerializer();
            return serializer.Deserialize<T>(content);
        }

        public static async Task<HttpResponseMessage> PutAsJsonAsync<T>(this HttpClient client, string requestUri, T value)
        {
            var serializer = JsonUtils.CreateJsonSerializer();
            var content = new StringContent(serializer.Serialize(value));
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.JsonMediaType);

            return await client.PutAsync(requestUri, content);
        }

        public static async Task<HttpResponseMessage> PostAsJsonAsync<T>(this HttpClient client, string requestUri, T value)
        {
            var serializer = JsonUtils.CreateJsonSerializer();
            var content = new StringContent(serializer.Serialize(value));
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.JsonMediaType);

            Console.WriteLine(serializer.Serialize(value));

            return await client.PostAsync(requestUri, content);
        }

        public static async Task<HttpResponseMessage> PatchAsJsonAsync<T>(this HttpClient client, string requestUri, T value)
        {
            var serializer = JsonUtils.CreateJsonSerializer();
            var content = new StringContent(serializer.Serialize(value));
            content.Headers.ContentType = new MediaTypeHeaderValue(Constants.JsonMediaType);

            var method = new HttpMethod("PATCH");
            var request = new HttpRequestMessage(method, requestUri)
            {
                Content = content
            };

            return await client.SendAsync(request);
        }
    }
}
