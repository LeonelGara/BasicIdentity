using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BasicIdentity.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace SoporteTicketBE.Controllers
{
    [Authorize(AuthenticationSchemes = "Bearer")]
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly BasicIdentityContext _context;

        public AccountController(BasicIdentityContext context,
            UserManager<IdentityUser> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(string email, string password)
        {
            var user = new IdentityUser()
            {
                Email = email,
                UserName = email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, password);

            if (result.Succeeded)
            {
                return Ok();
            }
            return BadRequest();
        }
    }
}