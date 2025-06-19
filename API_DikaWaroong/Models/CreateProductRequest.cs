namespace API_DikaWaroong.Models
{
    public class CreateProductRequest
    {
        public string NamaProduk { get; set; } = string.Empty;
        public int Stock { get; set; }
        public decimal Harga { get; set; }
        public string? Keterangan { get; set; }
        public int IdKategori { get; set; }
        public IFormFile? Gambar { get; set; }
    }
}
