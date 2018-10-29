using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
 
using System.DirectoryServices.AccountManagement;
using System.Security.Claims;
using Microsoft.Owin.Security;
using System.Configuration;

namespace WebApisTokenAuth
{
 
    public class AdAuthenticationService
    {
        public class AuthenticationResult
        {
            public AuthenticationResult(string errorMessage = null)
            {
                ErrorMessage = errorMessage;
            }

            public string ErrorMessage { get; private set; }
            public bool IsSuccess => string.IsNullOrEmpty(ErrorMessage);
        }

        private readonly IAuthenticationManager _authenticationManager;

        public AdAuthenticationService(IAuthenticationManager authenticationManager)
        {
            _authenticationManager = authenticationManager;
        }

        public AuthenticationResult SignIn(String username, String password)
        {
            // Use ContextType authenticationType = ContextType.Machine; if you need for local development
            ContextType authenticationType = ContextType.Domain;

            string _ADDomain, _userName, _password;

            _ADDomain = ConfigurationManager.AppSettings["ADDomain"].ToString();
            _userName = ConfigurationManager.AppSettings["ADUser"].ToString();
            _password = ConfigurationManager.AppSettings["ADPassword"].ToString();

            PrincipalContext principalContext = new PrincipalContext(authenticationType, _ADDomain, _userName, _password);
            bool isAuthenticated = false;
            UserPrincipal userPrincipal = null;
            try
            {
                userPrincipal = UserPrincipal.FindByIdentity(principalContext, username);
                if (userPrincipal != null)
                {
                    isAuthenticated = principalContext.ValidateCredentials(username, password, ContextOptions.Negotiate);
                }
            }
            catch (Exception exception)
            {
                return new AuthenticationResult("Username or Password is not correct");
            }

            if (!isAuthenticated)
            {
                return new AuthenticationResult("Username or Password is not correct");
            }

            if (userPrincipal.IsAccountLockedOut())
            {
                // here can be a security related discussion weather it is worth revealing this information
                return new AuthenticationResult("Your account is locked.");
            }

            if (userPrincipal.Enabled.HasValue && userPrincipal.Enabled.Value == false)
            {
                // here can be a security related discussion weather it is worth revealing this information
                return new AuthenticationResult("Your account is disabled");
            }

            var identity = CreateIdentity(userPrincipal);

            _authenticationManager.SignOut("MyProjectAuthenticationType");
            _authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = false }, identity);

            return new AuthenticationResult();
        }

        private ClaimsIdentity CreateIdentity(UserPrincipal userPrincipal)
        {
            var identity = new ClaimsIdentity("MyProjectAuthenticationType", ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
            identity.AddClaim(new Claim("http://schemas.microsoft.com/accesscontrolservice/2010/07/claims/identityprovider", "Active Directory"));
            identity.AddClaim(new Claim(ClaimTypes.Name, userPrincipal.SamAccountName));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, userPrincipal.SamAccountName));
            if (!string.IsNullOrEmpty(userPrincipal.EmailAddress))
            {
                identity.AddClaim(new Claim(ClaimTypes.Email, userPrincipal.EmailAddress));
            }

            //var groups = userPrincipal.GetAuthorizationGroups();
            //foreach (var @group in groups)
            //{
            //    identity.AddClaim(new Claim(ClaimTypes.Role, @group.Name));
            //}

            // add your own claims if you need to add more information stored on the cookie

            return identity;
        }
    }
}