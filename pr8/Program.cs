using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using pr8.Models;
using pr8.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. Подключение контроллеров и Swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// 2. Подключение базы данных MS SQL Server через EF Core
builder.Services.AddDbContext<Pr8DbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// 3. Регистрация сервисов: хэшер паролей, генератор JWT и сервис Refresh-токенов
builder.Services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();
builder.Services.AddScoped<JwtService>();
builder.Services.AddScoped<RefreshTokenService>();

var key = builder.Configuration["Jwt:Key"]!;
var issuer = builder.Configuration["Jwt:Issuer"]!;
var audience = builder.Configuration["Jwt:Audience"]!;

// 4. Настройка аутентификации JWT с проверкой отозванных токенов (Черный список)
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
            // ЛОВУШКА МЕТОДИЧКИ: ClockSkew = TimeSpan.Zero гарантирует, что токен протухнет ровно через 60 сек
            ClockSkew = TimeSpan.Zero
        };

        // ПР9: Проверка токена по таблице отозванных (RevokedTokens) в БД при КАЖДОМ запросе
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                // Достаем уникальный идентификатор jti из утверждений JWT
                var jti = context.Principal?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
                if (string.IsNullOrEmpty(jti))
                {
                    context.Fail("В JWT отсутствует jti");
                    return;
                }

                // Получаем DbContext из текущего контекста запроса
                var db = context.HttpContext.RequestServices.GetRequiredService<Pr8DbContext>();

                // Если jti находится в таблице RevokedTokens — отклоняем запрос (вернется 401)
                if (await db.RevokedTokens.AnyAsync(r => r.Jti == jti))
                {
                    context.Fail("JWT отозван");
                }
            }
        };
    });

builder.Services.AddAuthorization();

// 5. Настройка Swagger с кнопкой авторизации Bearer токена
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Введите токен в формате: Bearer {ваш_токен}",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// 6. Инициализация базы данных и создание стандартного администратора
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<Pr8DbContext>();
    var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<User>>();
    try
    {
        db.Database.EnsureCreated();
        if (!db.Users.Any(u => u.Login == "admin123"))
        {
            var admin = new User { Login = "admin123", Role = "Admin" };
            admin.PasswordHash = hasher.HashPassword(admin, "P@s$w0rd");
            db.Users.Add(admin);
            db.SaveChanges();
        }
    }
    catch
    {
    }
}

// 7. Включение Swagger UI
app.UseSwagger();
app.UseSwaggerUI();

// Автоматический редирект с корня на Swagger UI
app.MapGet("/", () => Results.Redirect("/swagger"));

// Автоматическое открытие браузера при запуске приложения
app.Lifetime.ApplicationStarted.Register(() =>
{
    try
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "http://localhost:5100/swagger",
            UseShellExecute = true
        });
    }
    catch
    {
    }
});

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
