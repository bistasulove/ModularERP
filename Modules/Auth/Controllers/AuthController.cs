using Microsoft.AspNetCore.Mvc;
using ModularERP.Common.DTOs.Auth;
using ModularERP.Modules.Auth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace ModularERP.Modules.Auth.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _auth;
        private readonly ILogger<AuthController> _logger;

        public AuthController(AuthService auth, ILogger<AuthController> logger)
        {
            _auth = auth;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            try
            {
                _logger.LogInformation("Registration request received for {Email}", dto.Email);
                var token = await _auth.RegisterAsync(dto);
                _logger.LogInformation("Registration successful for {Email}", dto.Email);
                return Ok(new { token });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Registration failed for {Email}", dto.Email);
                return BadRequest(new { message = ex.Message });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            try
            {
                _logger.LogInformation("Login request received for {Email}", dto.Email);
                var token = await _auth.LoginAsync(dto);
                _logger.LogInformation("Login successful for {Email}", dto.Email);
                return Ok(new { token });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Login failed for {Email}", dto.Email);
                return Unauthorized(new { message = ex.Message });
            }
        }

        [HttpGet("profile")]
        [Authorize]
        public IActionResult GetProfile()
        {
            try
            {
                // Get the authenticated user's claims
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? User.FindFirst("sub")?.Value;
                var email = User.FindFirst(ClaimTypes.Email)?.Value ?? User.FindFirst("email")?.Value;
                var name = User.FindFirst(ClaimTypes.Name)?.Value ?? User.FindFirst("name")?.Value;
                var role = User.FindFirst(ClaimTypes.Role)?.Value;
                var isActive = User.FindFirst("isActive")?.Value;
                var lastLoginStr = User.FindFirst("lastLogin")?.Value;
                
                DateTime? lastLogin = null;
                if (!string.IsNullOrEmpty(lastLoginStr))
                {
                    if (DateTime.TryParse(lastLoginStr, out var parsedDate))
                    {
                        lastLogin = parsedDate;
                    }
                }

                _logger.LogInformation("Profile request for user {UserId}, {Email}, Role: {Role}", userId, email, role);

                return Ok(new 
                { 
                    userId, 
                    email, 
                    name,
                    role,
                    isActive = isActive == "True",
                    lastLogin,
                    message = "This is a protected endpoint that requires authentication"
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving profile for user");
                return StatusCode(500, new { message = "An error occurred while retrieving profile" });
            }
        }

        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminOnly()
        {
            return Ok(new { message = "You have access to admin area" });
        }
    }
}