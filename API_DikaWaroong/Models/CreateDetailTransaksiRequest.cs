namespace API_DikaWaroong.Models
{
    public class CreateDetailTransaksiRequest
    {
        public int Quantity { get; set; }
        public int ProdukIdProduk { get; set; }
        public int TransaksiIdTransaksi { get; set; }
    }
}
