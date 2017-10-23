#region Copyright

// 
// DotNetNuke® - http://www.dotnetnuke.com
// Copyright (c) 2002-2014
// by DotNetNuke Corporation
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation 
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and 
// to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions 
// of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED 
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
// DEALINGS IN THE SOFTWARE.

#endregion


using System.IO;
using System.Net;
using System.Text;

#region Usings

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Web;
using System.Web.Script.Serialization;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Authentication.OAuth;

#endregion


namespace DotNetNuke.Authentication.Azure.Components
{
    public class AzureClient : OAuthClientBase
    {
        #region Constructors

        private JwtSecurityToken JwtSecurityToken { get; set; }


        public AzureClient(int portalId, AuthMode mode) 
            : base(portalId, mode, "Azure")
        {
            var config = new AzureConfig("Azure", portalId);

            TokenMethod = HttpMethod.POST;
            if (!string.IsNullOrEmpty(config.TokenEndpoint))
            {
                TokenEndpoint = new Uri(config.TokenEndpoint);
            }
            if (!string.IsNullOrEmpty(config.AuthorizationEndpoint))
            {
                AuthorizationEndpoint = new Uri(config.AuthorizationEndpoint);
            }
            if (!string.IsNullOrEmpty(config.GraphEndpoint))
            {
                MeGraphEndpoint = new Uri(config.GraphEndpoint);
            }

            Scope = "openid";

            AuthTokenName = "AzureUserToken";
            APIResource = config.AppIdUri;
            OAuthVersion = "2.0";
            LoadTokenCookie(String.Empty);
            JwtSecurityToken = null;
            
        }

        #endregion
        protected override TimeSpan GetExpiry(string responseText)
        {
            var jsonSerializer = new JavaScriptSerializer();
            var tokenDictionary = jsonSerializer.DeserializeObject(responseText) as Dictionary<string, object>;

            return new TimeSpan(0, 0, Convert.ToInt32(tokenDictionary["expires_in"]));
        }

        protected override string GetToken(string responseText)
        {
            if (string.IsNullOrEmpty(responseText))
            {
                throw new Exception("There was an error processing the credentials. Contact your system administrator.");
            }
            var jsonSerializer = new JavaScriptSerializer();
            var tokenDictionary = jsonSerializer.DeserializeObject(responseText) as Dictionary<string, object>;
            var token = Convert.ToString(tokenDictionary["access_token"]);
            JwtSecurityToken = new JwtSecurityToken(Convert.ToString(tokenDictionary["id_token"]));                        
            return token;
        }

        public override TUserData GetCurrentUser<TUserData>()
        {
            LoadTokenCookie(String.Empty);

            if (!IsCurrentUserAuthorized() || JwtSecurityToken == null)
            {
                return null;
            }
            var claims = JwtSecurityToken.Claims.ToArray();
            var user = new AzureUserData()
            {
                AzureFirstName = claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.GivenName).Value,
                AzureLastName = claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.FamilyName).Value,
                AzureDisplayName = claims.FirstOrDefault(x => x.Type == "name").Value,
                Email = claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.UniqueName).Value,
                Id = claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.UniqueName).Value
            };
            return user as TUserData;
        }

        public override AuthorisationResult Authorize()
        {
            string errorReason = HttpContext.Current.Request.Params["error_reason"];
            bool userDenied = (errorReason != null);
            if (userDenied)
            {
                return AuthorisationResult.Denied;
            }

            if (!HaveVerificationCode())
            {
                var parameters = new List<QueryParameter>
                {
                    new QueryParameter("scope", Scope),
                    new QueryParameter("client_id", APIKey),
                    new QueryParameter("redirect_uri", HttpContext.Current.Server.UrlEncode(CallbackUri.ToString())),
                    new QueryParameter("state", Service),
                    new QueryParameter("response_type", "id_token"),
                    new QueryParameter("p", "B2C_1_Signup")
                };

                HttpContext.Current.Response.Redirect(AuthorizationEndpoint + "?" + parameters.ToNormalizedString(), true);
                return AuthorisationResult.RequestingCode;
            }

            ExchangeCodeForToken();

            return String.IsNullOrEmpty(AuthToken) ? AuthorisationResult.Denied : AuthorisationResult.Authorized;

        }

        private void ExchangeCodeForToken()
        {
            IList<QueryParameter> parameters = new List<QueryParameter>();
            parameters.Add(new QueryParameter("client_id", APIKey));
            parameters.Add(new QueryParameter("redirect_uri", HttpContext.Current.Server.UrlEncode(CallbackUri.ToString())));
            //DNN-6265 Support for OAuth V2 Secrets which are not URL Friendly
            parameters.Add(new QueryParameter("client_secret", HttpContext.Current.Server.UrlEncode(APISecret.ToString())));
            parameters.Add(new QueryParameter("grant_type", "authorization_code"));
            parameters.Add(new QueryParameter("code", VerificationCode));

            //DNN-6265 Support for OAuth V2 optional parameter
            if (!String.IsNullOrEmpty(APIResource))
            {
                parameters.Add(new QueryParameter("resource", APIResource));
            }

            string responseText = ExecuteWebRequest(TokenMethod, TokenEndpoint, parameters.ToNormalizedString(), String.Empty);

            AuthToken = GetToken(responseText);
            AuthTokenExpiry = GetExpiry(responseText);
        }


        // TODO The set on base class is readonly. This will require moving more base class code
        private string _authToken = string.Empty;
        private string AuthToken
        {
            get { return _authToken; }
            set { _authToken = value; }
        }

        private string ExecuteWebRequest(HttpMethod method, Uri uri, string parameters, string authHeader)
        {
            WebRequest request;

            if (method == HttpMethod.POST)
            {
                byte[] byteArray = Encoding.UTF8.GetBytes(parameters);

                request = WebRequest.CreateDefault(uri);
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                //request.ContentType = "text/xml";
                request.ContentLength = byteArray.Length;

                if (!String.IsNullOrEmpty(OAuthHeaderCode))
                {
                    byte[] API64 = Encoding.UTF8.GetBytes(APIKey + ":" + APISecret);
                    string Api64Encoded = System.Convert.ToBase64String(API64);
                    //Authentication providers needing an "Authorization: Basic/bearer base64(clientID:clientSecret)" header. OAuthHeaderCode might be: Basic/Bearer/empty.
                    request.Headers.Add("Authorization: " + OAuthHeaderCode + " " + Api64Encoded);
                }

                if (!String.IsNullOrEmpty(parameters))
                {
                    Stream dataStream = request.GetRequestStream();
                    dataStream.Write(byteArray, 0, byteArray.Length);
                    dataStream.Close();
                }
            }
            else
            {
                request = WebRequest.CreateDefault(GenerateRequestUri(uri.ToString(), parameters));
            }

            //Add Headers
            if (!String.IsNullOrEmpty(authHeader))
            {
                request.Headers.Add(HttpRequestHeader.Authorization, authHeader);
            }

            try
            {
                using (WebResponse response = request.GetResponse())
                {
                    using (Stream responseStream = response.GetResponseStream())
                    {
                        if (responseStream != null)
                        {
                            using (var responseReader = new StreamReader(responseStream))
                            {
                                return responseReader.ReadToEnd();
                            }
                        }
                    }
                }
            }
            catch (WebException ex)
            {
                using (Stream responseStream = ex.Response.GetResponseStream())
                {
                    if (responseStream != null)
                    {
                        using (var responseReader = new StreamReader(responseStream))
                        {
                            //Logger.ErrorFormat("WebResponse exception: {0}", responseReader.ReadToEnd());
                        }
                    }
                }
            }
            return null;
        }

        private Uri GenerateRequestUri(string url, string parameters)
        {
            if (string.IsNullOrEmpty(parameters))
            {
                return new Uri(url);
            }

            return new Uri(string.Format("{0}{1}{2}", url, url.Contains("?") ? "&" : "?", parameters));
        }



    }

    internal static class AuthExtensions
    {
        public static string ToAuthorizationString(this IList<QueryParameter> parameters)
        {
            var sb = new StringBuilder();
            sb.Append("OAuth ");

            for (int i = 0; i < parameters.Count; i++)
            {
                string format = "{0}=\"{1}\"";

                QueryParameter p = parameters[i];
                sb.AppendFormat(format, OAuthClientBase.UrlEncode(p.Name), OAuthClientBase.UrlEncode(p.Value));

                if (i < parameters.Count - 1)
                {
                    sb.Append(", ");
                }
            }

            return sb.ToString();
        }

        public static string ToNormalizedString(this IList<QueryParameter> parameters)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < parameters.Count; i++)
            {
                QueryParameter p = parameters[i];
                sb.AppendFormat("{0}={1}", p.Name, p.Value);

                if (i < parameters.Count - 1)
                {
                    sb.Append("&");
                }
            }

            return sb.ToString();
        }
    }



}