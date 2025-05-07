using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using ModularERP.Modules.Auth.Entities;
using Microsoft.Extensions.Logging;

namespace ModularERP.Modules.Auth.Services
{
    public class JwtService
    {
        private readonly IConfiguration _config;
        private readonly ILogger<JwtService> _logger;

        public JwtService(IConfiguration config, ILogger<JwtService> logger)
        {
            _config = config;
            _logger = logger;
        }

        public string GenerateToken(User user) {
            _logger.LogInformation("Generating JWT token for user: {UserId}, {Email}", user.Id, user.Email);
            
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim("isActive", user.IsActive.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if (user.LastLoginAt.HasValue)
            {
                claims.Add(new Claim("lastLogin", user.LastLoginAt.Value.ToString("o")));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var tokenExpiration = DateTime.UtcNow.AddHours(3);
            _logger.LogDebug("Token will expire at: {ExpirationTime}", tokenExpiration);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: tokenExpiration,
                signingCredentials: creds);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
            _logger.LogDebug("JWT token generated successfully");
            
            return tokenString;
        }
    }
}