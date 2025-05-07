using ModularERP.Modules.Auth.Entities;
using ModularERP.Common.DTOs.Auth;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Extensions.Logging;
using ModularERP.Common.Logging;

namespace ModularERP.Modules.Auth.Services
{
    public class AuthService
    {
        private readonly AuthDbContext _db;
        private readonly JwtService _jwt;
        private readonly ILogger<AuthService> _logger;

        public AuthService(AuthDbContext db, JwtService jwt, ILogger<AuthService> logger)
        {
            _db = db;
            _jwt = jwt;
            _logger = logger;
        }

        public async Task<string> RegisterAsync(RegisterDto dto)
        {
            _logger.LogInformation("Attempting to register user with email: {Email}", dto.Email);
            
            using var timer = _logger.BeginTimedOperation("UserRegistration");
            
            var exists = await _db.Users.AnyAsync(u => u.Email == dto.Email);
            if (exists)
            {
                _logger.LogAuthenticationFailure(dto.Email, "Email already exists");
                throw new Exception("Email already exists");
            }

            var user = new User
            {
                FullName = dto.FullName,
                Email = dto.Email,
                PasswordHash = HashPassword(dto.Password),
                IsActive = true,
                Role = dto.Role ?? "User" // If no role specified, default to "User"
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();
            
            _logger.LogSecurityEvent("UserCreated", user.Id.ToString(), $"User created: {user.Email}, Role: {user.Role}");
            _logger.LogDataAccess("Create", "User", user.Id.ToString(), $"New user registered: {user.Email}");
            
            return _jwt.GenerateToken(user);
        }

        public async Task<string> LoginAsync(LoginDto dto)
        {
            _logger.LogInformation("Login attempt for user: {Email}", dto.Email);
            
            using var timer = _logger.BeginTimedOperation("UserLogin");
            
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null)
            {
                _logger.LogAuthenticationFailure(dto.Email, "User not found");
                throw new Exception("Invalid credentials");
            }
            
            if (!user.IsActive)
            {
                _logger.LogAuthenticationFailure(dto.Email, "Account is inactive");
                throw new Exception("This account has been deactivated");
            }
            
            if (!VerifyPassword(dto.Password, user.PasswordHash))
            {
                _logger.LogAuthenticationFailure(dto.Email, "Invalid password");
                throw new Exception("Invalid credentials");
            }

            user.LastLoginAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();

            _logger.LogAuthenticationSuccess(user.Id.ToString(), user.Email);
            _logger.LogSecurityEvent("UserLoggedIn", user.Id.ToString(), $"User logged in: {user.Email}, Role: {user.Role}");
            
            return _jwt.GenerateToken(user);
        }

        private string HashPassword(string password)
        {
            _logger.LogDebug("Hashing password");
            
            byte[] salt = new byte[128 / 8];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(salt);

            var hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password, salt, KeyDerivationPrf.HMACSHA256, 10000, 32));

            return $"{Convert.ToBase64String(salt)}.{hashed}";
        }

        private bool VerifyPassword(string password, string storedHash)
        {
            _logger.LogDebug("Verifying password");
            
            var parts = storedHash.Split('.');
            if (parts.Length != 2) return false;

            var salt = Convert.FromBase64String(parts[0]);
            var hash = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password, salt, KeyDerivationPrf.HMACSHA256, 10000, 32));

            return parts[1] == hash;
        }
    }
}