using WebApi_NET6_jwt_identity_demo.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using WebApi_NET6_jwt_identity_demo.Infrastructure.Model;
using WebApi_NET6_jwt_identity_demo.Infrastructure.Repository.IServices;
using WebApi_NET6_jwt_identity_demo.Infrastructure.Entities;

namespace WebApi_NET6_jwt_identity_demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IUserServices _userServices;
        public AuthenticateController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            IUserServices userServices
            )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _userServices = userServices;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = GetToken(authClaims);
                var refreshToken = GenerateRefreshToken();
                refreshToken.UserName = user.UserName;
                SetRefreshToken(refreshToken);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }
        [HttpPost("refresh-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if(refreshToken != null)
            {
                var res = _userServices.GetRefreshToken(refreshToken);

                if (res != null && res.Token != null)
                {
                    if (!res.Token.Equals(refreshToken))
                    {
                        return Unauthorized("Invalid Refresh Token.");
                    }
                    else if (res.Expires < DateTime.Now)
                    {
                        return Unauthorized("Token expired.");
                    }

                    var user = await _userManager.FindByNameAsync(res.UserName);
                    if (user != null)
                    {
                        var userRoles = await _userManager.GetRolesAsync(user);

                        var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    };

                        foreach (var userRole in userRoles)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                        }

                        var token = GetToken(authClaims);

                        return Ok(new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(token),
                            expiration = token.ValidTo
                        });
                    }
                }
            }
            
            return Unauthorized("Token expired.");

        }

        private RefreshTokenModel GenerateRefreshToken()
        {
            var refreshToken = new RefreshTokenModel
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(7),
                Created = DateTime.Now
            };

            return refreshToken;
        }

        private void SetRefreshToken(RefreshTokenModel newRefreshToken)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = newRefreshToken.Expires
            };
            if(newRefreshToken.Token != null)
            {
                Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

                var res = new RefreshToken
                {
                    Token = newRefreshToken.Token,
                    Expires = DateTime.Now.AddDays(7),
                    Created = DateTime.Now,
                    UserName = newRefreshToken.UserName,
                };
                var result = _userServices.CreateRefreshToken(res);
            }
        }
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            IdentityUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            IdentityUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.User);
            }
            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddDays(1),
                notBefore: DateTime.Now,
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );


            return token;
        }
    }
}
