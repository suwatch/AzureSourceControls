using System;

namespace Microsoft.Web.Hosting.SourceControls
{
    public class BitbucketProxyHelper
    {
        internal static string GetRequestUri(string apiBaseUrl, string repoUrl, params string[] paths)
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
                return String.Format("{0}/repositories/{1}/{2}", apiBaseUrl, parts[parts.Length - 2], parts[parts.Length - 1]);
            }
            else
            {
                return String.Format("{0}/repositories/{1}/{2}/{3}", apiBaseUrl, parts[parts.Length - 2], parts[parts.Length - 1], string.Join("/", paths));
            }
        }
    }
}
