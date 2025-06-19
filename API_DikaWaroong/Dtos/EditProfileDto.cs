using System.ComponentModel.DataAnnotations;

namespace API_DikaWaroong.Dtos
{
    public class EditProfileDto
    {
        [Required(ErrorMessage = "Username harus diisi")]
        [StringLength(50, ErrorMessage = "Username maksimal 50 karakter")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email harus diisi")]
        [EmailAddress(ErrorMessage = "Format email tidak valid")]
        [StringLength(100, ErrorMessage = "Email maksimal 100 karakter")]
        public string Email { get; set; } = string.Empty;
    }
}
