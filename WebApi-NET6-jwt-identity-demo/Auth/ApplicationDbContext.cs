
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApi_NET6_jwt_identity_demo.Infrastructure.Entities;

namespace WebApi_NET6_jwt_identity_demo.Auth
{
    public class ApplicationDbContext : IdentityDbContext<IdentityUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
            
        }
        public DbSet<RefreshToken> RefreshToken => Set<RefreshToken>();
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            
        }
    }
}