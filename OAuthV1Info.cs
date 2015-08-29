// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;

namespace Microsoft.Web.Hosting.SourceControls
{
    public class OAuthV1Info
    {
        public OAuthV1Info(string uri, string token, string tokenSecret)
        {
            Uri = uri;
            Token = token;
            TokenSecret = tokenSecret;
        }

        public string Uri
        {
            get;
            private set;
        }

        public string Token
        {
            get;
            private set;
        }

        public string TokenSecret
        {
            get;
            private set;
        }
    }
}
