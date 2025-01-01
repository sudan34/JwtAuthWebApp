using JwtAuthWebApp.DbConnection;
using JwtAuthWebApp.Services;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthWebApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly JwtTokenProvider _tokenProvider;
        private readonly AppDbContext _dbContext;
        private readonly IConfiguration _configuration;
        public AuthController(JwtTokenProvider tokenProvider, AppDbContext context, AppDbContext dbContext, IConfiguration configuration)
        {
            _tokenProvider = tokenProvider;
            _dbContext = context;
            _dbContext = dbContext;
            _configuration = configuration;
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Model.LoginRequest loginRequest)
        {
            var user = await _dbContext.Users.SingleOrDefaultAsync(u => u.Username == loginRequest.Username);

            if (user == null || !BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.PasswordHash))
            {
                return Unauthorized("Invalid credentials.");
            }

            var jwtToken = _tokenProvider.GenerateJwtToken(user);
            var refreshToken = _tokenProvider.GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(int.Parse(_configuration["JwtSettings:RefreshTokenExpiryDays"]));

            await _dbContext.SaveChangesAsync();

            return Ok(new { Token = jwtToken, RefreshToken = refreshToken });
        }
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshRequest refreshRequest)
        {
            var user = await _dbContext.Users.SingleOrDefaultAsync(u => u.RefreshToken == refreshRequest.RefreshToken);

            if (user == null || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            {
                return Unauthorized("Invalid or expired refresh token.");
            }

            var jwtToken = _tokenProvider.GenerateJwtToken(user);
            var newRefreshToken = _tokenProvider.GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(int.Parse(_configuration["JwtSettings:RefreshTokenExpiryDays"]));

            await _dbContext.SaveChangesAsync();

            return Ok(new { Token = jwtToken, RefreshToken = newRefreshToken });
        }
    }
}
