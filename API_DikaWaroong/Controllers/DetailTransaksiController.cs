using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Npgsql;
using API_DikaWaroong.Helpers;
using API_DikaWaroong.Models;
using System;

namespace API_DikaWaroong.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class DetailTransaksiController : ControllerBase
    {
        private readonly SqlDBHelper _dbHelper;

        public DetailTransaksiController(IConfiguration config)
        {
            _dbHelper = new SqlDBHelper(config);
        }

        [HttpGet("total/{transaksiId}")]
        public IActionResult GetTotalHarga(int transaksiId)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            cmd.CommandText = @"
        SELECT SUM(p.harga * dt.quantity) AS total_harga
        FROM detail_transaksi dt
        JOIN produk p ON dt.produk_id_produk = p.id_produk
        WHERE dt.transaksi_id_transaksi = @id;
    ";

            cmd.Parameters.Add(new NpgsqlParameter("@id", transaksiId));

            try
            {
                conn.Open();
                var total = cmd.ExecuteScalar();
                return Ok(new { total_harga = total == DBNull.Value ? 0 : Convert.ToInt32(total) });
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


        [HttpGet]
        public IActionResult GetAll()
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            cmd.CommandText = @"
        SELECT p.nama_produk, p.harga
        FROM detail_transaksi dt
        JOIN produk p ON dt.produk_id_produk = p.id_produk;
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
                        namaProduk = reader["nama_produk"]?.ToString(),
                        harga = Convert.ToInt32(reader["harga"])
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
        public IActionResult Create([FromBody] CreateDetailTransaksiRequest request)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            cmd.CommandText = @"
                INSERT INTO detail_transaksi (quantity, produk_id_produk, transaksi_id_transaksi)
                VALUES (@qty, @produk, @transaksi);
            ";

            cmd.Parameters.Add(new NpgsqlParameter("@qty", request.Quantity));
            cmd.Parameters.Add(new NpgsqlParameter("@produk", request.ProdukIdProduk));
            cmd.Parameters.Add(new NpgsqlParameter("@transaksi", request.TransaksiIdTransaksi));

            try
            {
                conn.Open();
                cmd.ExecuteNonQuery();
                return Ok(new { message = "Detail transaksi berhasil ditambahkan" });
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

        [HttpGet("by-transaksi/{transaksiId}")]
        public IActionResult GetByTransaksiId(int transaksiId)
        {
            var conn = _dbHelper.GetConnection();
            var cmd = conn.CreateCommand();

            cmd.CommandText = @"
        SELECT p.nama_produk, p.harga, dt.quantity
        FROM detail_transaksi dt
        JOIN produk p ON dt.produk_id_produk = p.id_produk
        WHERE dt.transaksi_id_transaksi = @id;
    ";

            cmd.Parameters.Add(new NpgsqlParameter("@id", transaksiId));

            var list = new List<object>();

            try
            {
                conn.Open();
                var reader = cmd.ExecuteReader();
                while (reader.Read())
                {
                    list.Add(new
                    {
                        produk = reader["nama_produk"]?.ToString(),
                        harga = Convert.ToInt32(reader["harga"]),
                        quantity = Convert.ToInt32(reader["quantity"]),
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

    }
}
