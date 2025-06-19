namespace API_DikaWaroong.Models
{
    public class Transaksi
    {
        public int IdTransaksi { get; set; }
        public DateTime Tanggal { get; set; }
        public int AkunIdAkun { get; set; }
        public bool StatusPesanan { get; set; }
        public string BuktiTF { get; set; } = string.Empty;
    }
}
