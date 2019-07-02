package ca.redtoad.sp;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Metadata
    extends HttpServlet
{
  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    response.setContentType("text/xml");
    response.setStatus(HttpServletResponse.SC_OK);
    response.getWriter().print(SAMLUtil.toString(SAMLUtil.buildServiceProviderMetdata()));
  }
}
