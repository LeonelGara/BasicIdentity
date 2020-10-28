using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace SoporteTicketBE.Controllers
{
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin", AuthenticationSchemes = "Bearer")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleController(RoleManager<IdentityRole> roleManager, UserManager<IdentityUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [HttpPost]
        public async Task<IActionResult> Create(string name)
        {
            if (ModelState.IsValid)
            {
                IdentityResult result = await _roleManager.CreateAsync(new IdentityRole(name));
                if (result.Succeeded)
                    return Ok();
                else
                    return BadRequest();
            }
            return BadRequest();
        }

        [HttpDelete]
        public async Task<IActionResult> Delete(string id)
        {
            IdentityRole role = await _roleManager.FindByIdAsync(id);
            if (role != null)
            {
                IdentityResult result = await _roleManager.DeleteAsync(role);
                if (result.Succeeded)
                    return Ok();
                else
                    return BadRequest();
            }
            else
                return BadRequest();
        }

        [HttpPut]
        public async Task<IActionResult> Update(string id)
        {
            IdentityRole role = await _roleManager.FindByIdAsync(id);
            if (role != null)
            {
                IdentityResult result = await _roleManager.UpdateAsync(role);
                if (result.Succeeded)
                    return Ok();
                else
                    return BadRequest();
            }
            else
                return BadRequest();
        }

        [HttpPost("Add/User")]
        public async Task<IActionResult> AddUserToRole(string roleName, string userId)
        {
            IdentityResult result;
            if (ModelState.IsValid)
            {
                IdentityUser user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    result = await _userManager.AddToRoleAsync(user, roleName);
                    if (result.Succeeded)
                        return Ok();
                }
            }
            return BadRequest();
        }

        [HttpPost("Remove/User")]
        public async Task<IActionResult> RemoveUserToRole(string roleName, string userId)
        {
            IdentityResult result;
            if (ModelState.IsValid)
            {
                IdentityUser user = await _userManager.FindByIdAsync(userId);
                if (user != null)
                {
                    result = await _userManager.RemoveFromRoleAsync(user, roleName);
                    if (result.Succeeded)
                        return Ok();
                }
            }
            return BadRequest();
        }
    }
}
