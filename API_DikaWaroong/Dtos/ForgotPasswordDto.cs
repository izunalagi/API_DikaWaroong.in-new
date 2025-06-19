namespace API_DikaWaroong.Dtos
{
    public class ForgotPasswordDto
    {
        public string Email { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
}
