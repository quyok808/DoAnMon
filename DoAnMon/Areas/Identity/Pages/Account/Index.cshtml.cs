using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;
using System.Text;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using System.Net.Mail;
using System.Net;
using DoAnMon.IdentityCudtomUser;
using DoAnMon.SendMail;

namespace DoAnMon.Areas.Identity.Pages.Account
{
    public class IndexModel : PageModel
    {
        private readonly SignInManager<CustomUser> _signInManager;
        private readonly UserManager<CustomUser> _userManager;
        private readonly IUserStore<CustomUser> _userStore;
        private readonly IUserEmailStore<CustomUser> _emailStore;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;
        private Mail mail = new Mail();

        public IndexModel(
            UserManager<CustomUser> userManager,
            IUserStore<CustomUser> userStore,
            SignInManager<CustomUser> signInManager,
            ILogger<RegisterModel> logger,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = (IUserEmailStore<CustomUser>?)GetEmailStore();
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
        }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [BindProperty]
        public InputModel Input { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public class InputModel
        {
            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [EmailAddress]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Required]
            [Display(Name = "Mssv")]
            public string Mssv { get; set; }

            [Required]
            [Display(Name = "Name")]
            public string Name { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }

            [Required]
            [Display(Name = "Mssv")]
            public string Username { get; set; }
        }


        public async Task OnGetAsync(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            ModelState.Remove("Input.Username");
            if (ModelState.IsValid)
            {
                var user = CreateUser();
                user.Mssv = Input.Mssv;
                user.Name = Input.Name;
                await _userStore.SetUserNameAsync((CustomUser)user, Input.Mssv, CancellationToken.None);
                await _emailStore.SetEmailAsync((CustomUser)user, Input.Email, CancellationToken.None);
                var result = await _userManager.CreateAsync((CustomUser)user, Input.Password);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User created a new account with password.");

                    var userId = await _userManager.GetUserIdAsync((CustomUser)user);
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync((CustomUser)user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var callbackUrl = Url.Page(
                        "/Account/ConfirmEmail",
                        pageHandler: null,
                        values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
                        protocol: Request.Scheme);
                    await mail.SendEmailAsync(Input.Email, "Confirm your email",
                        $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>." +
                        $"<br> You can login with Username: {Input.Mssv} or {Input.Email}." +
                        $"<br>Password: {Input.Password}");


					if (_userManager.Options.SignIn.RequireConfirmedAccount)
                    {
                        return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                    }
                    else
                    {
                        await _signInManager.SignInAsync((CustomUser)user, isPersistent: false);
                        return LocalRedirect(returnUrl);
                    }
                }
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }

		//private async Task<bool> SendEmailAsync(string email, string subject, string confirmLink)
		//{
		//	try
		//	{
		//		MailMessage message = new MailMessage("ONLYA@gmail.com", email, subject, confirmLink);
		//		message.IsBodyHtml = true;
		//		SmtpClient smtpClient = new SmtpClient();
		//		message.Body = confirmLink;

		//		smtpClient.Port = 587;
		//		smtpClient.Host = "smtp.gmail.com";


		//		smtpClient.EnableSsl = true;
		//		smtpClient.UseDefaultCredentials = false;
		//		smtpClient.Credentials = new NetworkCredential("quyok8080@gmail.com", "uaab ylsf uikl mnnd"/*password của phần bảo mật khác*/);
		//		smtpClient.Send(message);
		//		return true;
		//	}
		//	catch (Exception)
		//	{
		//		return false;
		//	}
		//}

		private CustomUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<CustomUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(IdentityUser)}'. " +
                    $"Ensure that '{nameof(CustomUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml");
            }
        }

        private IUserEmailStore<CustomUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<CustomUser>)_userStore;
        }

     //   //login

     //   public async Task OnGetLoginAsync(string returnUrl = null)
     //   {
     //       if (!string.IsNullOrEmpty(ErrorMessage))
     //       {
     //           ModelState.AddModelError(string.Empty, ErrorMessage);
     //       }

     //       returnUrl ??= Url.Content("~/");

     //       // Clear the existing external cookie to ensure a clean login process
     //       await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

     //       ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

     //       ReturnUrl = returnUrl;
     //   }

     //   public async Task<IActionResult> OnPostLoginAsync(string returnUrl = null)
     //   {
     //       returnUrl ??= Url.Content("~/");

     //       ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

     //       if (ModelState.IsValid)
     //       {
     //           // This doesn't count login failures towards account lockout
     //           // To enable password failures to trigger account lockout, set lockoutOnFailure: true
     //           var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
     //           if (result.Succeeded)
     //           {
     //               var mdUser = await _userManager.FindByEmailAsync(Input.Email);
     //               if (!mdUser.EmailConfirmed)
     //               {
     //                   await _signInManager.SignOutAsync();
					//	return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
					//}
     //               else
     //               {
     //                   _logger.LogInformation("User logged in.");
     //                   return LocalRedirect(returnUrl);
     //               }
     //           }
     //           if (result.RequiresTwoFactor)
     //           {
     //               return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
     //           }
     //           if (result.IsLockedOut)
     //           {
     //               _logger.LogWarning("User account locked out.");
     //               return RedirectToPage("./Lockout");
     //           }
     //           else
     //           {
     //               ModelState.AddModelError(string.Empty, "Invalid login attempt.");
     //               return RedirectToPage("/Index");
     //           }
     //       }

     //       // If we got this far, something failed, redisplay form
     //       return Page();
     //   }
    }
}
