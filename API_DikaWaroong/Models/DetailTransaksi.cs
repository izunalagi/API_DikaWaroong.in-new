namespace API_DikaWaroong.Models
{
    public class DetailTransaksi
    {
        public int IdDetailTransaksi { get; set; } // Auto-increment
        public int Quantity { get; set; }
        public int ProdukIdProduk { get; set; }
        public int TransaksiIdTransaksi { get; set; }
    }
}
