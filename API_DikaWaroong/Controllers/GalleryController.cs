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
    public class GalleryController : ControllerBase
    {
        private readonly SqlDBHelper _dbHelper;

        public GalleryController(IConfiguration config)
        {
            _dbHelper = new SqlDBHelper(config);
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT id_gallery, foto_gallery FROM gallery";

            var galleryList = new List<Gallery>();

            try
            {
                conn.Open();
                var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    galleryList.Add(new Gallery
                    {
                        IdGallery = reader["id_gallery"] is DBNull ? 0 : (int)reader["id_gallery"],
                        FotoGallery = reader["foto_gallery"]?.ToString()
                    });
                }
                return Ok(galleryList);
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
        [RequestSizeLimit(10_000_000)]
        public async Task<IActionResult> Create([FromForm] CreateGalleryRequest request)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            string? fileName = null;

            if (request.FotoGallery != null && request.FotoGallery.Length > 0)
            {
                var folderPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "gallery");
                if (!Directory.Exists(folderPath))
                    Directory.CreateDirectory(folderPath);

                fileName = Guid.NewGuid().ToString() + Path.GetExtension(request.FotoGallery.FileName);
                var filePath = Path.Combine(folderPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await request.FotoGallery.CopyToAsync(stream);
                }
            }

            cmd.CommandText = @"INSERT INTO gallery (foto_gallery) VALUES (@foto)";
            cmd.Parameters.Add(new NpgsqlParameter("@foto", (object?)fileName ?? DBNull.Value));

            try
            {
                conn.Open();
                cmd.ExecuteNonQuery();
                return Ok(new { message = "Gambar berhasil ditambahkan" });
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
            cmd.CommandText = "DELETE FROM gallery WHERE id_gallery = @id";
            cmd.Parameters.Add(new NpgsqlParameter("@id", id));

            try
            {
                conn.Open();
                int affected = cmd.ExecuteNonQuery();
                if (affected == 0) return NotFound("Galeri tidak ditemukan");
                return Ok(new { message = "Galeri berhasil dihapus" });
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
