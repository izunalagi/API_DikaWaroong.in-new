namespace API_DikaWaroong.Models
{
    public class CreateTransaksiRequest
    {
        public int AkunIdAkun { get; set; }
        public bool StatusPesanan { get; set; }
        public DateTime Tanggal { get; set; }
    }

}
