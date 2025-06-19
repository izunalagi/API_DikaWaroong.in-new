using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using System.Data;
using API_DikaWaroong.Helpers;
using API_DikaWaroong.Models;

namespace API_DikaWaroong.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ContactController : ControllerBase
    {
        private readonly SqlDBHelper _dbHelper;

        public ContactController(IConfiguration config)
        {
            _dbHelper = new SqlDBHelper(config);
        }

        // GET: api/Contact
        [HttpGet]
        public IActionResult Get()
        {
            using var conn = _dbHelper.GetConnection();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM contact WHERE id = 1";

            try
            {
                conn.Open();
                using var reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    var contact = new Contact
                    {
                        Id = (int)reader["id"],
                        NomorTelepon = reader["nomortelepon"]?.ToString(),
                        Email = reader["email"]?.ToString(),
                        Alamat = reader["alamat"]?.ToString(),
                        Latitude = reader["latitude"] is DBNull ? null : (double?)reader["latitude"],
                        Longitude = reader["longitude"] is DBNull ? null : (double?)reader["longitude"],
                        CreatedAt = reader["createdat"] is DBNull ? null : (DateTime?)reader["createdat"]
                    };

                    return Ok(new List<Contact> { contact });
                }

                return NotFound("Kontak tidak ditemukan");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Gagal mengambil data: {ex.Message}");
            }
        }

        // PUT: api/Contact
        [HttpPut]
        public IActionResult Update([FromBody] Contact request)
        {
            const int id = 1;

            using var conn = _dbHelper.GetConnection();
            using var cmd = conn.CreateCommand();

            cmd.CommandText = @"
                UPDATE contact SET 
                    nomortelepon = @nomor,
                    email = @email,
                    alamat = @alamat,
                    latitude = @lat,
                    longitude = @lng
                WHERE id = @id";

            cmd.Parameters.Add(new NpgsqlParameter("@id", id));
            cmd.Parameters.Add(new NpgsqlParameter("@nomor", request.NomorTelepon ?? (object)DBNull.Value));
            cmd.Parameters.Add(new NpgsqlParameter("@email", request.Email ?? (object)DBNull.Value));
            cmd.Parameters.Add(new NpgsqlParameter("@alamat", request.Alamat ?? (object)DBNull.Value));
            cmd.Parameters.Add(new NpgsqlParameter("@lat", request.Latitude ?? (object)DBNull.Value));
            cmd.Parameters.Add(new NpgsqlParameter("@lng", request.Longitude ?? (object)DBNull.Value));

            try
            {
                conn.Open();
                int rows = cmd.ExecuteNonQuery();
                if (rows == 0) return NotFound("Kontak tidak ditemukan");

                return Ok(new { message = "Kontak berhasil diperbarui" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Gagal update data: {ex.Message}");
            }
        }
    }
}
