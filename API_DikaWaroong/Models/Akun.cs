namespace API_DikaWaroong.Models
{
    public class Akun
    {
        public int Id_Akun { get; set; }
        public string? Email { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }

        public int Role_Id_Role { get; set; }
        public Role? Role { get; set; }
    }
}
