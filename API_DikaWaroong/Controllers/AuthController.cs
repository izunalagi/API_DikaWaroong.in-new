namespace API_DikaWaroong.Controllers
{
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.IdentityModel.Tokens;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Text;
    using API_DikaWaroong.Data;
    using API_DikaWaroong.Models;
    using API_DikaWaroong.Dtos;
    using System;
    using BCrypt = BCrypt.Net.BCrypt;
    using Microsoft.AspNetCore.Authorization;

    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _config;

        public AuthController(AppDbContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto dto)
        {
            var akun = new Akun
            {
                Email = dto.Email,
                Username = dto.Username,
                Password = BCrypt.HashPassword(dto.Password),
                Role_Id_Role = dto.RoleId
            };

            _context.Akuns.Add(akun);
            await _context.SaveChangesAsync();

            return Ok(new { message = "Registrasi berhasil." });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var akun = await _context.Akuns
                .Include(a => a.Role)
                .FirstOrDefaultAsync(a => a.Email == dto.Email);

            if (akun == null || !BCrypt.Verify(dto.Password, akun.Password))
            {
                return Unauthorized(new { message = "Email atau password salah." });
            }

            var token = GenerateJwtToken(akun);

            return Ok(new
            {
                token,
                akun = new
                {
                    akun.Id_Akun,
                    akun.Username,
                    akun.Email,
                    Role = akun.Role?.Nama_Role
                }
            });
        }


        private string GenerateJwtToken(Akun akun)
        {
            var claims = new[]
            {
        new Claim(ClaimTypes.NameIdentifier, akun.Id_Akun.ToString()),
        new Claim(ClaimTypes.Email, akun.Email),
        new Claim(ClaimTypes.Role, akun.Role.Nama_Role)
    };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


        [Authorize]
        [HttpGet("me")]
        public async Task<IActionResult> GetMe()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
                return Unauthorized();

            var akun = await _context.Akuns
                .Include(a => a.Role)
                .FirstOrDefaultAsync(a => a.Id_Akun.ToString() == userId);

            if (akun == null)
                return NotFound();

            return Ok(new
            {
                akun.Id_Akun,
                akun.Username,
                akun.Email,
                Role = akun.Role.Nama_Role
            });
        }

        [Authorize]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            try
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (userId == null)
                    return Unauthorized(new { message = "Token tidak valid" });

                var akun = await _context.Akuns.FirstOrDefaultAsync(a => a.Id_Akun.ToString() == userId);
                if (akun == null)
                    return NotFound(new { message = "Akun tidak ditemukan" });

                if (!BCrypt.Verify(dto.OldPassword, akun.Password))
                {
                    return BadRequest(new { message = "Password lama salah" });
                }

                if (string.IsNullOrWhiteSpace(dto.NewPassword) || dto.NewPassword.Length < 6)
                {
                    return BadRequest(new { message = "Password baru minimal 6 karakter" });
                }

                akun.Password = BCrypt.HashPassword(dto.NewPassword);
                await _context.SaveChangesAsync();

                return Ok(new { message = "Password berhasil diubah" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Terjadi kesalahan server", error = ex.Message });
            }
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto dto)
        {
            try
            {
                var akun = await _context.Akuns
                    .FirstOrDefaultAsync(a => a.Email == dto.Email && a.Username == dto.Username);

                if (akun == null)
                {
                    return BadRequest(new { message = "Email atau Username tidak cocok" });
                }

                if (string.IsNullOrWhiteSpace(dto.NewPassword) || dto.NewPassword.Length < 6)
                {
                    return BadRequest(new { message = "Password baru minimal 6 karakter" });
                }

                akun.Password = BCrypt.HashPassword(dto.NewPassword);
                await _context.SaveChangesAsync();

                return Ok(new { message = "Password berhasil direset" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Terjadi kesalahan server", error = ex.Message });
            }
        }

        [Authorize]
        [HttpPut("edit-profile")]
        public async Task<IActionResult> EditProfile([FromBody] EditProfileDto dto)
        {
            try
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (userId == null)
                    return Unauthorized(new { message = "Token tidak valid" });

                var akun = await _context.Akuns.FirstOrDefaultAsync(a => a.Id_Akun.ToString() == userId);
                if (akun == null)
                    return NotFound(new { message = "Akun tidak ditemukan" });

                if (string.IsNullOrWhiteSpace(dto.Username) || string.IsNullOrWhiteSpace(dto.Email))
                {
                    return BadRequest(new { message = "Username dan Email tidak boleh kosong" });
                }

                var existingEmailAkun = await _context.Akuns
                    .FirstOrDefaultAsync(a => a.Email == dto.Email && a.Id_Akun != akun.Id_Akun);
                if (existingEmailAkun != null)
                {
                    return BadRequest(new { message = "Email sudah digunakan oleh akun lain" });
                }

                var existingUsernameAkun = await _context.Akuns
                    .FirstOrDefaultAsync(a => a.Username == dto.Username && a.Id_Akun != akun.Id_Akun);
                if (existingUsernameAkun != null)
                {
                    return BadRequest(new { message = "Username sudah digunakan oleh akun lain" });
                }

                akun.Username = dto.Username;
                akun.Email = dto.Email;
                await _context.SaveChangesAsync();

                return Ok(new
                {
                    message = "Profile berhasil diperbarui",
                    data = new
                    {
                        akun.Id_Akun,
                        akun.Username,
                        akun.Email
                    }
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Terjadi kesalahan server", error = ex.Message });
            }
        }

        [HttpGet("pelanggan")]
        public async Task<IActionResult> GetPelanggan()
        {
            try
            {
                var pelangganList = await _context.Akuns
                    .Where(a => a.Role_Id_Role == 2)
                    .Select(a => new
                    {
                        a.Username,
                        a.Email
                    })
                    .ToListAsync();

                return Ok(pelangganList);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "Terjadi kesalahan server", error = ex.Message });
            }
        }

    }

}
