namespace API_DikaWaroong.Models
{
    public class Produk
    {
        public int IdProduk { get; set; }
        public string NamaProduk { get; set; } = string.Empty;
        public int Stock { get; set; }
        public decimal Harga { get; set; }
        public string? Gambar { get; set; }
        public string? Keterangan { get; set; }
        public int IdKategori { get; set; }
        public Kategori? Kategori { get; set; }

    }

}
