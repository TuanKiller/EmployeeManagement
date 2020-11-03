using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using WebApi.Helpers;
using WebApi.Models;

namespace WebApi.Data
{
    public class ApplicationDbContextSeed
    {
        public static async Task SeedEssentialsAsync(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            //Seed Roles
            await roleManager.CreateAsync(new IdentityRole(Roles.Administrator.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Roles.Moderator.ToString()));
            await roleManager.CreateAsync(new IdentityRole(Roles.User.ToString()));

            //Seed Default User
            var defaultUser = new ApplicationUser { UserName = ConfigHelpers.default_username, Email = ConfigHelpers.default_email, EmailConfirmed = true, PhoneNumberConfirmed = true };

            if (userManager.Users.All(u => u.Id != defaultUser.Id))
            {
                await userManager.CreateAsync(defaultUser, ConfigHelpers.default_password);
                await userManager.AddToRoleAsync(defaultUser, ConfigHelpers.default_role.ToString());
            }
        }
    }
}
