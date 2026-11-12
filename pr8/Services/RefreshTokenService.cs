using pr8.Models;
using System.Security.Cryptography;
using System.Text;

namespace pr8.Services
{
    public class RefreshTokenService
    {
        private readonly Pr8DbContext _context;

        public RefreshTokenService (Pr8DbContext context)
        {
            _context = context;
        }

        public async Task<string> GenerateRefreshToken (int userId)
        {
            var rndBytes = RandomNumberGenerator.GetBytes(32);
            
            var srokDeystvia = DateTime.UtcNow.AddDays(7);
            var bytesToken = SHA256.HashData(Encoding.UTF8.GetBytes(rndBytes.ToString()));

            var newRefToken = new RefreshToken
            {
                UserId = userId,
                ExpiresAt = srokDeystvia,
                TokenHash = bytesToken.ToString()
            };

            _context.RefreshTokens.Add(newRefToken);
            await _context.SaveChangesAsync();

            return rndBytes.ToString();
        }
    }
}
