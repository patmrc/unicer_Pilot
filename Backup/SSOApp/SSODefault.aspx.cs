using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Configuration;
using System.Text;

namespace SSO
{
    public partial class SSODefault : System.Web.UI.Page
    {
        public bool Error { get; set; }
        public string ErrorDescription { get; set; }

        protected void Page_Load(object sender, EventArgs e)
        {
           Response.Clear();
           Response.Write(GenerateForm("$User ID$")); //replace $User ID$ part with Login User ID. 
        }

        public string GenerateForm(string userId)
        {
            StringBuilder sbForm = new StringBuilder();
            //get base url and all other URLs
            string acct = ConfigurationManager.AppSettings.Get("acct");
            string ssoURL = ConfigurationManager.AppSettings.Get("baseURL");
            string ouId = ConfigurationManager.AppSettings.Get("ouId");
            string logoutURL = ConfigurationManager.AppSettings.Get("logoutURL");
            string timeoutURL = ConfigurationManager.AppSettings.Get("timeoutURL");
            string errorURL = ConfigurationManager.AppSettings.Get("errorURL");
            string destURL = ConfigurationManager.AppSettings.Get("destURL");//To enable DEEPLINKING, uncomment the following two lines

            if (Request.QueryString["link"] != null)
            {
                destURL = HttpUtility.UrlEncode(Request.QueryString["link"]);
            }

            //get the encrypted token
           
            string encryptedToken = WCyberu.GetSecurityToken(acct, userId, string.Empty, logoutURL, timeoutURL, errorURL, destURL);
            if (Error)
            {
                if (!string.IsNullOrEmpty(errorURL))
                {

                    sbForm.AppendLine("<html>").AppendFormat("<body onload=\"window.location.href='{0}';\">", errorURL);
                    sbForm.AppendLine("</body>").AppendLine("</html>");
                }
                else
                {
                    sbForm.AppendFormat("<html><body><p>{0}</p></body></html>", ErrorDescription);
                }
            }
            else
            {
                sbForm.AppendLine("<html>").AppendLine("<body onload=\"document.forms[0].submit();\">");
                sbForm.AppendFormat("<form method=\"POST\" action=\"{0}\">", ssoURL).AppendLine();
                sbForm.AppendFormat("<input type=\"hidden\" name=\"key\" value=\"{0}\"/>", encryptedToken).AppendLine();
                sbForm.AppendFormat("<input type=\"hidden\" name=\"ouid\" value=\"{0}\"/>", ouId);
                sbForm.AppendLine("</form>").AppendLine("</body>").AppendLine("</html>");
            }

            return sbForm.ToString();

        }
    }
}