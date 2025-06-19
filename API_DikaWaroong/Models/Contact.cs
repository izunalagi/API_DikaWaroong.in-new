namespace API_DikaWaroong.Models
{
    public class Contact
    {
        public int Id { get; set; }
        public string NomorTelepon { get; set; }
        public string Email { get; set; }
        public string Alamat { get; set; }
        public double? Latitude { get; set; }
        public double? Longitude { get; set; }
        public DateTime? CreatedAt { get; set; }
    }

}
