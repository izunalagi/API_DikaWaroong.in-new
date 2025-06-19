using Microsoft.AspNetCore.Http;

namespace API_DikaWaroong.Models
{
    public class CreateGalleryRequest
    {
        public IFormFile? FotoGallery { get; set; }
    }
}
