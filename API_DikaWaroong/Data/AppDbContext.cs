using API_DikaWaroong.Models;
using Microsoft.EntityFrameworkCore;

namespace API_DikaWaroong.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<Akun> Akuns { get; set; }
        public DbSet<Role> Roles { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Mapping tabel Role
            modelBuilder.Entity<Role>(entity =>
            {
                entity.ToTable("role");

                entity.HasKey(r => r.Id_Role);
                entity.Property(r => r.Id_Role).HasColumnName("id_role");
                entity.Property(r => r.Nama_Role).HasColumnName("nama_role");
            });

            // Mapping tabel Akun
            modelBuilder.Entity<Akun>(entity =>
            {
                entity.ToTable("akun");

                entity.HasKey(a => a.Id_Akun);
                entity.Property(a => a.Id_Akun).HasColumnName("id_akun");
                entity.Property(a => a.Email).HasColumnName("email");
                entity.Property(a => a.Username).HasColumnName("username");
                entity.Property(a => a.Password).HasColumnName("password");
                entity.Property(a => a.Role_Id_Role).HasColumnName("role_id_role"); // lowercase fix

                entity.HasOne(a => a.Role)
                      .WithMany(r => r.Akuns)
                      .HasForeignKey(a => a.Role_Id_Role)
                      .OnDelete(DeleteBehavior.Cascade)
                      .HasConstraintName("fk_role");
            });
        }
    }
}
