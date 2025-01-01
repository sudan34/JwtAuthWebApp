using JwtAuthWebApp.Model;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthWebApp.DbConnection
{
    public class AppDbContext: DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }
        public DbSet<User> Users { get; set; }
    }
}
