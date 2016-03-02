using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Web;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Services.Authentication.OAuth;
using DotNetNuke.UI.WebControls;

namespace DotNetNuke.Authentication.Azure.Components
{
    public class AzureConfig : OAuthConfigBase
    {
        private const string _cacheKey = "Authentication";

        protected internal AzureConfig(string service, int portalId) : base(service, portalId)
        {
            AppIdUri = PortalController.GetPortalSetting(Service + "_AppIdUri", portalId, "");
            TokenEndpoint = PortalController.GetPortalSetting(Service + "_TokenEndpoint", portalId, "");
            AuthorizationEndpoint = PortalController.GetPortalSetting(Service + "_AuthorizationEndpoint", portalId, "");
            GraphEndpoint = PortalController.GetPortalSetting(Service + "_GraphEndpoint", portalId, "");

            AADSyncEnabled = bool.Parse(PortalController.GetPortalSetting(Service + "_AADSyncEnabled", portalId, "false"));
            ADDTenant = PortalController.GetPortalSetting(Service + "_ADDTenant", portalId, "");
            ADDSyncGroupsFilter = PortalController.GetPortalSetting(Service + "_ADDSyncGroupsFilter", portalId, "");
            ADDSyncUsersFilter = PortalController.GetPortalSetting(Service + "_ADDSyncUsersFilter", portalId, "");
        }

        [SortOrder(1)]
        public string TokenEndpoint { get; set; }
        [SortOrder(2)]
        public string AuthorizationEndpoint { get; set; }
        [SortOrder(3)]
        public string GraphEndpoint { get; set; }
        [SortOrder(4)]
        public string AppIdUri { get; set; }


        [SortOrder(5)]
        public bool AADSyncEnabled { get; set; }
        [SortOrder(6)]
        public string ADDTenant { get; set; }
        [SortOrder(7)]
        public string ADDSyncGroupsFilter { get; set; }
        [SortOrder(8)]
        public string ADDSyncUsersFilter { get; set; }

        private static string GetCacheKey(string service, int portalId)
        {
            return _cacheKey + "." + service + "_" + portalId;
        }

        public new static AzureConfig GetConfig(string service, int portalId)
        {
            string key = GetCacheKey(service, portalId);
            var config = (AzureConfig)DataCache.GetCache(key);
            if (config == null)
            {
                config = new AzureConfig(service, portalId);
                DataCache.SetCache(key, config);
            }
            return config;
        }

        public static void UpdateConfig(AzureConfig config)
        {
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_AppIdUri", config.AppIdUri);
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_TokenEndpoint", config.TokenEndpoint);
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_AuthorizationEndpoint", config.AuthorizationEndpoint);
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_GraphEndpoint", config.GraphEndpoint);

            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_AADSyncEnabled", config.AADSyncEnabled.ToString());
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_ADDTenant", config.ADDTenant);
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_ADDSyncGroupsFilter", config.ADDSyncGroupsFilter);
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_ADDSyncUsersFilter", config.ADDSyncUsersFilter);

            UpdateConfig((OAuthConfigBase)config);
        }
    }
}