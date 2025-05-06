using Microsoft.EntityFrameworkCore;
using ModularERP.Modules.Auth.Entities;

namespace ModularERP.Modules.Auth
{
    public class AuthDbContext : DbContext
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) {}

        public DbSet<User> Users { get; set; }
    }
}