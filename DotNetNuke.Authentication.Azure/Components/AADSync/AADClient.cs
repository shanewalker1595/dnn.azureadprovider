using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Services.Exceptions;
using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.WindowsAzure.ServiceRuntime;

namespace DotNetNuke.Authentication.Azure.Components.AADSync
{
    public class AADClient
    {
       // Token constants
       private const string TokenResource = "https://graph.windows.net";

        private static int PortalID = 0;

        public AADClient(int portalID)
        {
            PortalID = portalID;
        }

        public static async Task<string> AcquireTokenAsyncForApp()
        {
            return GetTokenForApp();
        }

        public static string GetTokenForApp()
        {
            try
            {
                var authenticationContext = new AuthenticationContext(PortalController.GetPortalSetting("Azure_TokenEndpoint", PortalID, ""));

                return authenticationContext.AcquireToken(TokenResource
                                                        , new ClientCredential(PortalController.GetPortalSetting("Azure_APIKey", PortalID, "")
                                                        , PortalController.GetPortalSetting("Azure_APISecret", PortalID, ""))).AccessToken;
            }
            catch (Exception)
            {
                return "";
            }
        }

        private ActiveDirectoryClient _activeDirectoryClient;
        private ActiveDirectoryClient ActiveDirectoryClient
        {
            get
            {
                try
                {
                    if (_activeDirectoryClient == null)
                    {
                        var baseServiceUri = new Uri(Constants.ResourceId);
                        _activeDirectoryClient =
                            new ActiveDirectoryClient(new Uri(baseServiceUri, PortalController.GetPortalSetting("Azure_ADDTenant", PortalID, "")),
                                async () => await AcquireTokenAsyncForApp());
                    }
                    return _activeDirectoryClient;
                }
                catch (Exception ex)
                {
                    throw new SecurityException(string.Format("Error creating ActiveDirectoryClient for AAD access: {0}", ex.Message));
                }
            }
        }

        public IUser GetUser(string userName)
        {
            try
            {
                IUser retrievedUser = null;
                var users = ActiveDirectoryClient.Users.Where(user =>
                                user.UserPrincipalName.Equals(userName)).ExecuteAsync().Result.CurrentPage.ToList();

                if (users.Count > 0)
                {
                    retrievedUser = users.First();
                }

                return retrievedUser;
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("Error getting AAD user with name '{0}': {1}", userName, ex.Message));
            }
        }

        public List<IUser> GetUsersByGroup(IGroup group)
        {
            try
            {
                IGroupFetcher groupFetcher = (IGroupFetcher)group;
                var members = groupFetcher.Members.ExecuteAsync().Result;
                var retrievedUsers = members.CurrentPage.Where(member => member is User)
                                    .Select(member => member as IUser).ToList();

                return retrievedUsers;
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("Error getting AAD user for group '{0}': {1}", group.DisplayName, ex.Message));
            }
        }

        public List<IUser> GetUsersByGroup(string groupFilter)
        {
            try
            {
                List<IGroup> retrievedGroups = null;
                var retrievedUsers = new List<IUser>();

                retrievedGroups = ActiveDirectoryClient.Groups.Where(group => group.DisplayName.StartsWith(groupFilter)).ExecuteAsync().Result.CurrentPage.ToList();
                foreach (var group in retrievedGroups)
                {
                    retrievedUsers.AddRange(group.Members.CurrentPage.Where(member => member is User)
                                    .Select(member => member as IUser).ToList());
                }

                return retrievedUsers;
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("Error getting AAD user by group filter by '{0}': {1}", groupFilter, ex.Message));
            }
        }

        public List<IGroup> GetGroups(string groupFilter)
        {
            try
            {
                List<IGroup> retrievedGroups = null;

                retrievedGroups = ActiveDirectoryClient.Groups.Where(group => group.DisplayName.StartsWith(groupFilter)).ExecuteAsync().Result.CurrentPage.ToList();

                return retrievedGroups;
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("Error getting AAD groups filter by '{0}': {1}", groupFilter, ex.Message));
            }
        }
    }


}