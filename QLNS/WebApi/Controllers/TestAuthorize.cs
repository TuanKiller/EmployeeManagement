using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace WebApi.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    public class TestAuthorize : Controller
    {
        [HttpGet]
        public async Task<IActionResult> TestAuth()
        {
            return Ok("Da dang nhap");
        }
    }
}
