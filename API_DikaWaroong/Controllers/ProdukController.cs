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
    public class ProdukController : ControllerBase
    {
        private readonly SqlDBHelper _dbHelper;

        public ProdukController(IConfiguration config)
        {
            _dbHelper = new SqlDBHelper(config);
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();
            cmd.CommandText = @"
        SELECT 
            p.id_produk,
            p.nama_produk,
            p.stock,
            p.harga,
            p.gambar,
            p.keterangan,
            p.id_kategori,
            k.nama_kategori
        FROM produk p
        JOIN kategori k ON p.id_kategori = k.id_kategori";

            var produkList = new List<object>();


            try
            {
                conn.Open();
                var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    produkList.Add(new Produk
                    {
                        IdProduk = reader["id_produk"] is DBNull ? 0 : (int)reader["id_produk"],
                        NamaProduk = reader["nama_produk"]?.ToString() ?? string.Empty,
                        Stock = reader["stock"] is DBNull ? 0 : (int)reader["stock"],
                        Harga = reader["harga"] is DBNull ? 0 : (decimal)reader["harga"],
                        Gambar = reader["gambar"]?.ToString() ?? string.Empty,
                        Keterangan = reader["keterangan"]?.ToString() ?? string.Empty,
                        Kategori = new Kategori
                        {
                            IdKategori = reader["id_kategori"] is DBNull ? 0 : (int)reader["id_kategori"],
                            NamaKategori = reader["nama_kategori"]?.ToString() ?? string.Empty
                        }
                    });

                }
                return Ok(produkList);
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
        public async Task<IActionResult> Create([FromForm] CreateProductRequest request)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            string? fileName = null;
            if (request.Gambar != null && request.Gambar.Length > 0)
            {
                var folderPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images");
                if (!Directory.Exists(folderPath))
                    Directory.CreateDirectory(folderPath);

                fileName = Guid.NewGuid().ToString() + Path.GetExtension(request.Gambar.FileName);
                var filePath = Path.Combine(folderPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await request.Gambar.CopyToAsync(stream);
                }
            }

            cmd.CommandText = @"INSERT INTO produk 
        (nama_produk, stock, harga, gambar, keterangan, id_kategori)
        VALUES (@nama, @stock, @harga, @gambar, @keterangan, @id_kategori)";

            cmd.Parameters.Add(new NpgsqlParameter("@nama", request.NamaProduk));
            cmd.Parameters.Add(new NpgsqlParameter("@stock", request.Stock));
            cmd.Parameters.Add(new NpgsqlParameter("@harga", request.Harga));
            cmd.Parameters.Add(new NpgsqlParameter("@gambar", (object?)fileName ?? DBNull.Value));
            cmd.Parameters.Add(new NpgsqlParameter("@keterangan", (object?)request.Keterangan ?? DBNull.Value));
            cmd.Parameters.Add(new NpgsqlParameter("@id_kategori", request.IdKategori));

            try
            {
                conn.Open();
                cmd.ExecuteNonQuery();
                return Ok(new { message = "Produk berhasil ditambahkan" });
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
        [RequestSizeLimit(10_000_000)]
        public async Task<IActionResult> Update(int id, [FromForm] CreateProductRequest request)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            string? fileName = null;

            if (request.Gambar != null && request.Gambar.Length > 0)
            {
                var folderPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "images");
                if (!Directory.Exists(folderPath))
                    Directory.CreateDirectory(folderPath);

                fileName = Guid.NewGuid().ToString() + Path.GetExtension(request.Gambar.FileName);
                var filePath = Path.Combine(folderPath, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await request.Gambar.CopyToAsync(stream);
                }
            }
            else
            {
                // Ambil gambar lama dari database jika tidak ada upload baru
                var getGambarCmd = conn.CreateCommand();
                getGambarCmd.CommandText = "SELECT gambar FROM produk WHERE id_produk = @id";
                getGambarCmd.Parameters.Add(new NpgsqlParameter("@id", id));

                try
                {
                    conn.Open();
                    var result = getGambarCmd.ExecuteScalar();
                    fileName = result?.ToString();
                }
                finally
                {
                    conn.Close();
                }
            }

            // Update data
            cmd.CommandText = @"UPDATE produk SET 
        nama_produk = @nama,
        stock = @stock,
        harga = @harga,
        gambar = @gambar,
        keterangan = @keterangan,
        id_kategori = @id_kategori
        WHERE id_produk = @id";

            cmd.Parameters.Add(new NpgsqlParameter("@nama", request.NamaProduk));
            cmd.Parameters.Add(new NpgsqlParameter("@stock", request.Stock));
            cmd.Parameters.Add(new NpgsqlParameter("@harga", request.Harga));
            cmd.Parameters.Add(new NpgsqlParameter("@gambar", (object?)fileName ?? DBNull.Value));
            cmd.Parameters.Add(new NpgsqlParameter("@keterangan", (object?)request.Keterangan ?? DBNull.Value));
            cmd.Parameters.Add(new NpgsqlParameter("@id_kategori", request.IdKategori));
            cmd.Parameters.Add(new NpgsqlParameter("@id", id));

            try
            {
                conn.Open();
                int affected = cmd.ExecuteNonQuery();
                if (affected == 0) return NotFound("Produk tidak ditemukan");
                return Ok(new { message = "Produk berhasil diperbarui" });
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
            cmd.CommandText = "DELETE FROM produk WHERE id_produk = @id";
            cmd.Parameters.Add(new NpgsqlParameter("@id", id));

            try
            {
                conn.Open();
                int affected = cmd.ExecuteNonQuery();
                if (affected == 0) return NotFound("Produk tidak ditemukan");
                return Ok(new { message = "Produk berhasil dihapus" });
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
