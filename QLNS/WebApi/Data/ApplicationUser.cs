using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;
using WebApi.Entities;

namespace WebApi.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; }
    }
}
