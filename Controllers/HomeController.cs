using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using mvc.Models;

namespace mvc.Controllers
{
    public class HomeController : Controller
    {
        public async Task<IActionResult> Index(string url = "")
        {
            if (!string.IsNullOrEmpty(url))
            {
                System.Console.WriteLine($"Getting {url}");
                try
                {
                    using (var client = new HttpClient())
                    {
                        await client.GetAsync(url);
                    }
                    System.Console.WriteLine("Get finished succesfully");
                }
                catch (Exception e)
                {
                    System.Console.WriteLine($"Get threw {e.Message}");
                }
            }
            return View();
        }

        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public IActionResult HttpGet(string url)
        {
            return View();
        }
    }
}
