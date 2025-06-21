using API_DikaWaroong.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
// Hello world
// DB Context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// JWT Auth
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization(); // <-- WAJIB

// CORS - Updated untuk production
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFlutterWeb", policy =>
    {
        policy.WithOrigins(
                "http://localhost:57307", // Untuk development
                "https://yourdomain.com", // Ganti dengan domain Flutter web production Anda
                "*" // HATI-HATI: Hanya untuk testing, jangan untuk production
              )
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// SWAGGER - DIAKTIFKAN UNTUK SEMUA ENVIRONMENT
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "API DikaWaroong V1");
    c.RoutePrefix = "swagger"; // URL akan jadi /swagger
});

app.UseCors("AllowFlutterWeb");
app.UseHttpsRedirection();
app.UseAuthentication(); 
app.UseAuthorization();
app.UseStaticFiles();
app.MapControllers();

app.Run();