using Microsoft.EntityFrameworkCore;
using pr8.Models;
using System.Security.Cryptography;
using System.Text;

namespace pr8.Services;

public class RefreshTokenService
{
    private readonly Pr8DbContext _context;

    public RefreshTokenService(Pr8DbContext context)
    {
        _context = context;
    }

    // сша256 вычисление
    public string HashToken(string token)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes).ToLower();
    }

    public async Task<string> GenerateRefreshToken(int userId)
    {

        var rndBytes = RandomNumberGenerator.GetBytes(32);
        string rawToken = Convert.ToBase64String(rndBytes);

        string tokenHash = HashToken(rawToken);

        var expiresAt = DateTime.UtcNow.AddDays(7);

        var newRefToken = new RefreshToken
        {
            UserId = userId,
            TokenHash = tokenHash,
            ExpiresAt = expiresAt
        };

        _context.RefreshTokens.Add(newRefToken);
        await _context.SaveChangesAsync();

        return rawToken;
    }

    public async Task<(User? user, string? newRefreshToken)> RotateRefreshToken(string rawRefreshToken)
    {
        string tokenHash = HashToken(rawRefreshToken);

        var existingToken = await _context.RefreshTokens
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.TokenHash == tokenHash);

        if (existingToken == null || existingToken.ExpiresAt < DateTime.UtcNow || existingToken.User == null)
        {
            return (null, null);
        }

        // ротация атомарно 
        using var transaction = await _context.Database.BeginTransactionAsync();
        try
        {
            var user = existingToken.User;

            _context.RefreshTokens.Remove(existingToken);

            var rndBytes = RandomNumberGenerator.GetBytes(32);
            string newRawToken = Convert.ToBase64String(rndBytes);
            string newTokenHash = HashToken(newRawToken);

            var newTokenEntity = new RefreshToken
            {
                UserId = user.Id,
                TokenHash = newTokenHash,
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            };

            _context.RefreshTokens.Add(newTokenEntity);
            await _context.SaveChangesAsync();

            await transaction.CommitAsync();

            return (user, newRawToken);
        }
        catch
        {
            await transaction.RollbackAsync();
            return (null, null);
        }
    }

    public async Task<RevokeResult> RevokeSession(string rawRefreshToken, int currentUserId, string currentJti)
    {
        string tokenHash = HashToken(rawRefreshToken);

        var existingToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(r => r.TokenHash == tokenHash);

        if (existingToken == null || existingToken.ExpiresAt < DateTime.UtcNow)
        {
            return RevokeResult.InvalidToken;
        }

        if (existingToken.UserId != currentUserId)
        {
            return RevokeResult.Forbidden;
        }

        using var transaction = await _context.Database.BeginTransactionAsync();
        try
        {
            _context.RefreshTokens.Remove(existingToken);
            if (!await _context.RevokedTokens.AnyAsync(r => r.Jti == currentJti))
            {
                _context.RevokedTokens.Add(new RevokedToken
                {
                    Jti = currentJti,
                    ExpiresAt = DateTime.UtcNow.AddMinutes(5) 
                });
            }

            await _context.SaveChangesAsync();
            await transaction.CommitAsync();

            return RevokeResult.Success;
        }
        catch
        {
            await transaction.RollbackAsync();
            return RevokeResult.InvalidToken;
        }
    }
}

public enum RevokeResult
{
    Success,      // 204 No Content
    InvalidToken, // 401 Unauthorized
    Forbidden     // 403 Forbidden
}
