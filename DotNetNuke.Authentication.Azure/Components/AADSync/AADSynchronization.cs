using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Entities.Users;
//using DotNetNuke.Modules.Dashboard.Components.Portals;
using DotNetNuke.Security.Roles;
using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Scheduling;
using Microsoft.Azure.ActiveDirectory.GraphClient;

namespace DotNetNuke.Authentication.Azure.Components.AADSync
{
    public class AADSynchronization : SchedulerClient
    {
        public AADSynchronization(ScheduleHistoryItem oItem)
            : base()
        {
            this.ScheduleHistoryItem = oItem;
        }


        public override void DoWork()
        {
            try
            {
                this.Progressing();
                
                this.ScheduleHistoryItem.AddLogNote("\nStarting the synchronization of Dnn user and AAD\n");

                foreach (PortalInfo portal in PortalController.Instance.GetPortals())
                {
                    var ADClient = new AADClient(portal.PortalID);

                    var AADSyncEnabled = bool.Parse(PortalController.GetPortalSetting("Azure_AADSyncEnabled", portal.PortalID, "false"));
                    var ADDSyncGroupsFilter = PortalController.GetPortalSetting("Azure_ADDSyncGroupsFilter", portal.PortalID, "");
                    var ADDSyncUsersFilter = PortalController.GetPortalSetting("Azure_ADDSyncUsersFilter", portal.PortalID, "");

                    if (AADSyncEnabled)
                    {
                        foreach (var group in ADClient.GetGroups(ADDSyncGroupsFilter))
                        {
                            foreach (var user in ADClient.GetUsersByGroup(group))
                            {
                                if (!string.IsNullOrEmpty(ADDSyncUsersFilter) && !user.UserPrincipalName.StartsWith(ADDSyncUsersFilter))
                                    continue;

                                this.ScheduleHistoryItem.AddLogNote(string.Format("\nUser '{0}':\n", user.UserPrincipalName));
                                var dnnUser = UserController.GetUserByName(portal.PortalID, "Azure-" + user.UserPrincipalName);
                                if (dnnUser != null)
                                {
                                    this.ScheduleHistoryItem.AddLogNote("already exists");
                                    if (!dnnUser.Membership.Approved)
                                    {
                                        this.ScheduleHistoryItem.AddLogNote(", adding Approved");
                                        dnnUser.Membership.Approved = true;
                                        UserController.UpdateUser(portal.PortalID, dnnUser);
                                    }
                                }
                                else
                                {
                                    dnnUser = new UserInfo()
                                    {
                                        FirstName = user.GivenName,
                                        LastName = user.Surname,
                                        Email = user.Mail,
                                        PortalID = portal.PortalID,
                                        IsDeleted = false,
                                        IsSuperUser = false,
                                        Username = "Azure-" + user.UserPrincipalName
                                    };

                                    // Generate a random password for the user
                                    dnnUser.Membership = new UserMembership(dnnUser);
                                    dnnUser.Membership.Password = UserController.GeneratePassword();
                                    dnnUser.Membership.PasswordConfirm = dnnUser.Membership.Password;

                                    // Authorize the user
                                    dnnUser.Membership.Approved = true;

                                    this.ScheduleHistoryItem.AddLogNote("creating user");
                                    UserController.CreateUser(ref dnnUser);
                                }
                                this.ScheduleHistoryItem.AddLogNote(", adding Azure Authentication");
                                AuthenticationController.AddUserAuthentication(dnnUser.UserID, "Azure", dnnUser.Username);
                                if (!RoleController.Instance.GetUserRoles(portal.PortalID, dnnUser.Username, group.DisplayName).Any())
                                {
                                    var role = RoleController.Instance.GetRoleByName(portal.PortalID, group.DisplayName);
                                    if (role != null)
                                    {
                                        this.ScheduleHistoryItem.AddLogNote(string.Format(", adding role {0}", role.RoleName));
                                        RoleController.AddUserRole(dnnUser, role, new PortalSettings(portal.PortalID), RoleStatus.Approved, DateTime.Now, DateTime.MaxValue, false, false);
                                    }                                        
                                }
                            }
                        }
                    }
                }
                this.ScheduleHistoryItem.AddLogNote("Synchronization of Dnn user and AAD completed\n");

                //Show success
                this.ScheduleHistoryItem.Succeeded = true;
            }
            catch (Exception ex)
            {
                this.ScheduleHistoryItem.Succeeded = false;

                this.Errored(ref ex);
                DotNetNuke.Services.Exceptions.Exceptions.LogException(ex);
            }
        }
    }
}