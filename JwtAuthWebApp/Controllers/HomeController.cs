using Microsoft.AspNetCore.Mvc;

namespace JwtAuthWebApp.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }
    }
}
