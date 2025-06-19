namespace API_DikaWaroong.Models
{
    public class Role
    {
        public int Id_Role { get; set; }
        public string? Nama_Role { get; set; }

        public ICollection<Akun>? Akuns { get; set; }
    }

}
