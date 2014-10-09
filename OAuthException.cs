// ----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Net;

namespace AzureSourceControls
{
    public class OAuthException : Exception
    {
        public OAuthException(string message)
            : base(message)
        {
        }

        public OAuthException(string message, HttpStatusCode httpStatusCode, string httpContent)
            : base(message)
        {
            StatusCode = httpStatusCode;
            Content = httpContent;
        }

        public HttpStatusCode StatusCode
        {
            get;
            private set;
        }

        public string Content
        {
            get;
            private set;
        }
    }
}