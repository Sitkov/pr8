using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using pr8.Models;
using pr8.Services;

namespace pr8.Controllers;

[Route("api/v1/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly Models.Pr8DbContext _db;
    private readonly JwtService _jwtService;
    private readonly IPasswordHasher<User> _hasher;

    public AuthController(Models.Pr8DbContext db, JwtService jwtService, IPasswordHasher<User> hasher)
    {
        _db = db;
        _jwtService = jwtService;
        _hasher = hasher;
    }

    [HttpPost("register")]
    public IActionResult Register([FromBody] RegisterRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Login) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest("Логин и пароль обязательны");

        if (_db.Users.Any(u => u.Login == request.Login))
            return Conflict("Пользователь уже существует");

        var user = new User
        {
            Login = request.Login.Trim(),
            Role = "User"
        };
        user.PasswordHash = _hasher.HashPassword(user, request.Password);

        _db.Users.Add(user);
        _db.SaveChanges();

        return Ok(new { message = "Успешная регистрация" });
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Login) || string.IsNullOrWhiteSpace(request.Password))
            return Unauthorized("Неверный логин или пароль");

        var user = _db.Users.FirstOrDefault(u => u.Login == request.Login.Trim());
        if (user == null || _hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            return Unauthorized("Неверный логин или пароль");

        string token = _jwtService.GenerateToken(user);

        return Ok(new AuthResponse { AccessToken = token });
    }
}

public class RegisterRequest
{
    public string Login { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class LoginRequest
{
    public string Login { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class AuthResponse
{
    [System.Text.Json.Serialization.JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;
}
