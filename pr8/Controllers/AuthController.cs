using System.IdentityModel.Tokens.Jwt;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using pr8.Models;
using pr8.Services;

namespace pr8.Controllers;

[Route("api/v1/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly Pr8DbContext _db;
    private readonly JwtService _jwtService;
    private readonly RefreshTokenService _refreshTokenService;
    private readonly IPasswordHasher<User> _hasher;

    public AuthController(
        Pr8DbContext db,
        JwtService jwtService,
        RefreshTokenService refreshTokenService,
        IPasswordHasher<User> hasher)
    {
        _db = db;
        _jwtService = jwtService;
        _refreshTokenService = refreshTokenService;
        _hasher = hasher;
    }

    
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Login) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest("Логин и пароль обязательны");

        if (await _db.Users.AnyAsync(u => u.Login == request.Login))
            return Conflict("Пользователь уже существует");

        var user = new User
        {
            Login = request.Login.Trim(),
            Role = "User" 
        };
        user.PasswordHash = _hasher.HashPassword(user, request.Password);

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        return Ok(new { message = "Успешная регистрация" });
    }

    // JWT и RT
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Login) || string.IsNullOrWhiteSpace(request.Password))
            return Unauthorized("Неверный логин или пароль");

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Login == request.Login.Trim());
        if (user == null || _hasher.VerifyHashedPassword(user, user.PasswordHash, request.Password) == PasswordVerificationResult.Failed)
            return Unauthorized("Неверный логин или пароль");

        string accessToken = _jwtService.GenerateToken(user);

        string refreshToken = await _refreshTokenService.GenerateRefreshToken(user.Id);

        // возвращаем оба токена
        return Ok(new AuthResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        });
    }

    // обновление токенов
    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return Unauthorized("Недействительный Refresh Token");

        var (user, newRefreshToken) = await _refreshTokenService.RotateRefreshToken(request.RefreshToken);

        if (user == null || newRefreshToken == null)
            return Unauthorized("Неизвестный, просроченный или отозванный Refresh Token");

        string newAccessToken = _jwtService.GenerateToken(user);

        return Ok(new AuthResponse
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken
        });
    }

    // завершение сессии
    [HttpPost("logout")]
    [Authorize] //действующий JWT
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
            return Unauthorized("Недействительный Refresh Token");

        var login = User.Identity?.Name;
        if (string.IsNullOrEmpty(login))
            return Unauthorized("Пользователь не авторизован");

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Login == login);
        if (user == null)
            return Unauthorized("Пользователь не найден");

        // jti токена 
        var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
        if (string.IsNullOrEmpty(jti))
            return Unauthorized("В JWT отсутствует jti");

        var result = await _refreshTokenService.RevokeSession(request.RefreshToken, user.Id, jti);

        return result switch
        {
            RevokeResult.Success => NoContent(), 
            RevokeResult.Forbidden => Forbid(),
            _ => Unauthorized("Неизвестный или просроченный Refresh Token")
        };
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
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;
}

public class RefreshRequest
{
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;
}

public class LogoutRequest
{
    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; } = string.Empty;
}
