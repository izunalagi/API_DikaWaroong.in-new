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
    public class KategoriController : ControllerBase
    {
        private readonly SqlDBHelper _dbHelper;

        public KategoriController(IConfiguration config)
        {
            _dbHelper = new SqlDBHelper(config);
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM kategori";
            var list = new List<Kategori>();

            try
            {
                conn.Open();
                var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    list.Add(new Kategori
                    {
                        IdKategori = reader["id_kategori"] is DBNull ? 0 : (int)reader["id_kategori"],
                        NamaKategori = reader["nama_kategori"]?.ToString() ?? string.Empty
                    });
                }
                return Ok(list);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
            finally
            {
                conn.Close();
            }
        }

        [HttpPost]
        public IActionResult Create([FromBody] Kategori kategori)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT INTO kategori (nama_kategori) VALUES (@nama)";
            cmd.Parameters.Add(new NpgsqlParameter("@nama", kategori.NamaKategori));

            try
            {
                conn.Open();
                cmd.ExecuteNonQuery();
                return Ok(new { message = "Kategori berhasil ditambahkan" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
            finally
            {
                conn.Close();
            }
        }

        [HttpPut("{id}")]
        public IActionResult Update(int id, [FromBody] Kategori kategori)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();
            cmd.CommandText = "UPDATE kategori SET nama_kategori = @nama WHERE id_kategori = @id";
            cmd.Parameters.Add(new NpgsqlParameter("@nama", kategori.NamaKategori));
            cmd.Parameters.Add(new NpgsqlParameter("@id", id));

            try
            {
                conn.Open();
                int affected = cmd.ExecuteNonQuery();
                if (affected == 0) return NotFound("Kategori tidak ditemukan");
                return Ok(new { message = "Kategori berhasil diperbarui" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
            finally
            {
                conn.Close();
            }
        }

        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM kategori WHERE id_kategori = @id";
            cmd.Parameters.Add(new NpgsqlParameter("@id", id));

            try
            {
                conn.Open();
                int affected = cmd.ExecuteNonQuery();
                if (affected == 0) return NotFound("Kategori tidak ditemukan");
                return Ok(new { message = "Kategori berhasil dihapus" });
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
            finally
            {
                conn.Close();
            }
        }
    }
}
