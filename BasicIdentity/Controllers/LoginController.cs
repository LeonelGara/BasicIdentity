using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace SoporteTicketBE.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IConfiguration _configuration;

        public LoginController(IConfiguration config,
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = config;
        }

        public class User
        {
            public string email { get; set; }
            public string password { get; set; }
        }
        
        [AllowAnonymous]
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] User model)
        {
            //Find user by email
            var user = await _userManager.FindByNameAsync(model.email);

            if (user != null)
            {
                //Check user validity
                var signInResult = await _signInManager.CheckPasswordSignInAsync(user, model.password, false);

                if (signInResult.Succeeded)
                {
                    var roles = await _userManager.GetRolesAsync(user);
                    //Generate jwt
                    var token = GenerateJSONToken(user, roles);
                    return Ok(new { token = token });
                }
            }

            return Unauthorized();
        }

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpPost("LogOut")]
        public async Task<IActionResult> LogOut()
        {
            return Ok();
        }

        private string GenerateJSONToken(IdentityUser user, IList<string> roles)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
            var issuer = _configuration["Jwt:Issuer"];
            var audience = _configuration["Jwt:Audience"];
            var expireTimeInSeconds = Convert.ToInt32(_configuration["Jwt:ExpiryTimeInSeconds"]);

            var claimList = new List<Claim>
                {
                    new Claim(ClaimTypes.Email, user.Email)
                };

            foreach (var role in roles)
                claimList.Add(new Claim(ClaimTypes.Role, role));

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claimList),
                Expires = DateTime.UtcNow.AddSeconds(expireTimeInSeconds),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = issuer,
                Audience = audience
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}