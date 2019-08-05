package ca.redtoad.sp;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Secure
    extends HttpServlet
{
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    UserPrincipal userPrincipal =
        (UserPrincipal) request.getSession().getAttribute(WebSecurityConfig.AUTHENTICATED_USER);
    response.setContentType("text/html");
    response.setStatus(HttpServletResponse.SC_OK);
    response.getWriter()
        .printf("<html><p>Hello %s from secure! <a href='/logout'>Logout</a></p><p>Your attributes are %s</p></html>",
            userPrincipal.getName(), userPrincipal.getAttributes());
  }
}
