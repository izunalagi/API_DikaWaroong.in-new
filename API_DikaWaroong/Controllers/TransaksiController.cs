using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using API_DikaWaroong.Helpers;
using API_DikaWaroong.Models;
using System;
using System.Collections.Generic;

namespace API_DikaWaroong.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TransaksiController : ControllerBase
    {
        private readonly SqlDBHelper _dbHelper;

        public TransaksiController(IConfiguration config)
        {
            _dbHelper = new SqlDBHelper(config);
        }

        [HttpGet]
        public IActionResult GetAll()
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT * FROM transaksi";

            var list = new List<Transaksi>();

            try
            {
                conn.Open();
                var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    list.Add(new Transaksi
                    {
                        IdTransaksi = Convert.ToInt32(reader["id_transaksi"]),
                        Tanggal = Convert.ToDateTime(reader["tanggal"]),
                        AkunIdAkun = Convert.ToInt32(reader["akun_id_akun"]),
                        StatusPesanan = Convert.ToBoolean(reader["status_pesanan"]),
                        BuktiTF = reader["bukti_tf"]?.ToString() ?? ""
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
        public IActionResult Create([FromBody] CreateTransaksiRequest request)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            cmd.CommandText = @"
                INSERT INTO transaksi (tanggal, akun_id_akun, status_pesanan, bukti_tf)
                VALUES (@tanggal, @akun, @status, '')
                RETURNING id_transaksi;
            ";

            cmd.Parameters.Add(new NpgsqlParameter("@tanggal", DateTime.Now));
            cmd.Parameters.Add(new NpgsqlParameter("@akun", request.AkunIdAkun));
            cmd.Parameters.Add(new NpgsqlParameter("@status", request.StatusPesanan));

            try
            {
                conn.Open();
                var id = (int)cmd.ExecuteScalar();
                return Ok(new { id_transaksi = id });
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
        public async Task<IActionResult> UpdateBuktiTF(int id, [FromForm] UpdateBuktiTFRequest request)
        {
            if (request.BuktiTF == null || request.BuktiTF.Length == 0)
            {
                return BadRequest("File bukti transfer tidak ditemukan.");
            }

            var conn = _dbHelper.GetConnection();

            string fileName = Guid.NewGuid().ToString() + Path.GetExtension(request.BuktiTF.FileName);
            var folderPath = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "BuktiTF");

            if (!Directory.Exists(folderPath))
                Directory.CreateDirectory(folderPath);

            var filePath = Path.Combine(folderPath, fileName);

            try
            {
                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await request.BuktiTF.CopyToAsync(stream);
                }

                var cmd = conn.CreateCommand();
                cmd.CommandText = @"
                    UPDATE transaksi 
                    SET bukti_tf = @bukti 
                    WHERE id_transaksi = @id";

                cmd.Parameters.Add(new NpgsqlParameter("@bukti", fileName));
                cmd.Parameters.Add(new NpgsqlParameter("@id", id));

                conn.Open();
                int rowsAffected = cmd.ExecuteNonQuery();

                if (rowsAffected == 0)
                {
                    return NotFound($"Transaksi dengan ID {id} tidak ditemukan.");
                }

                return Ok(new { message = "Bukti transfer berhasil diunggah.", file = fileName });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Terjadi kesalahan server: {ex.Message}");
            }
            finally
            {
                conn.Close();
            }
        }

        [HttpGet("with-akun")]
        public IActionResult GetAllWithAkun()
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            cmd.CommandText = @"
        SELECT t.id_transaksi, t.tanggal, t.status_pesanan, t.bukti_tf, 
               a.username
        FROM transaksi t
        JOIN akun a ON t.akun_id_akun = a.id_akun
        ORDER BY t.id_transaksi ASC;
    ";

            var list = new List<object>();

            try
            {
                conn.Open();
                var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    list.Add(new
                    {
                        IdTransaksi = Convert.ToInt32(reader["id_transaksi"]),
                        Tanggal = Convert.ToDateTime(reader["tanggal"]).ToString("yyyy-MM-dd"),
                        Username = reader["username"].ToString(),
                        Status = (bool)reader["status_pesanan"] ? "Selesai" : "Sedang Diproses",
                        Selesai = (bool)reader["status_pesanan"],
                        BuktiUploaded = !string.IsNullOrEmpty(reader["bukti_tf"].ToString())
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

        [HttpPut("{id}/selesaikan")]
        public IActionResult TandaiSelesai(int id)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            cmd.CommandText = @"
        UPDATE transaksi 
        SET status_pesanan = TRUE 
        WHERE id_transaksi = @id;
    ";

            cmd.Parameters.Add(new NpgsqlParameter("@id", id));

            try
            {
                conn.Open();
                int rows = cmd.ExecuteNonQuery();
                if (rows == 0)
                    return NotFound("Transaksi tidak ditemukan.");

                return Ok(new { message = "Transaksi berhasil ditandai sebagai selesai." });
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

        [HttpGet("{id}/bukti")]
        public IActionResult GetBuktiTransfer(int id)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            cmd.CommandText = @"
        SELECT bukti_tf 
        FROM transaksi 
        WHERE id_transaksi = @id
    ";

            cmd.Parameters.Add(new NpgsqlParameter("@id", id));

            try
            {
                conn.Open();
                var reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    string fileName = reader["bukti_tf"]?.ToString();
                    if (string.IsNullOrEmpty(fileName))
                    {
                        return NotFound(new { message = "Bukti transfer belum diunggah." });
                    }

                    var request = HttpContext.Request;
                    var baseUrl = $"{request.Scheme}://{request.Host}";
                    string imageUrl = $"{baseUrl}/BuktiTF/{fileName}";

                    return Ok(new { url = imageUrl });
                }
                else
                {
                    return NotFound(new { message = "Transaksi tidak ditemukan." });
                }
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
