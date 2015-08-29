// ---------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Web.Hosting.SourceControls.Utils
{
    public static class CommonUtils
    {
        public static void ValidateNullArgument(string argName, object argValue)
        {
            if (argValue == null)
            {
                throw new ArgumentException(String.Format("Argument '{0}' cannot be null.", argName));
            }
        }

        public static void ValidateNullArgument(string argName, string argValue)
        {
            if (String.IsNullOrEmpty(argValue))
            {
                throw new ArgumentException(String.Format("Argument '{0}' cannot be null or empty string.", argName));
            }
        }

        public static IEnumerable<T> ConcatEnumerable<T>(IEnumerable<IEnumerable<T>> results)
        {
            foreach (var result in results)
            {
                foreach (var value in result)
                {
                    yield return value;
                }
            }
        }
    }
}
