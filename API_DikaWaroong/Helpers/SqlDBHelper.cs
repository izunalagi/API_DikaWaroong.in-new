using Microsoft.Extensions.Configuration;
using Npgsql;
using System.Data;

namespace API_DikaWaroong.Helpers
{
    public class SqlDBHelper
    {
        private readonly string _connectionString;

        public SqlDBHelper(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection")
                ?? throw new InvalidOperationException("Connection string not found.");
        }

        public IDbConnection GetConnection()
        {
            return new NpgsqlConnection(_connectionString);
        }
    }
}
