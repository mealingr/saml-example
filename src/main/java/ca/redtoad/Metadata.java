package ca.redtoad;

import java.io.IOException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Metadata
    extends HttpServlet
{
  private final SAML2ClientBuilder saml2ClientBuilder = new SAML2ClientBuilder();

  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    response.setContentType("text/xml");
    response.setStatus(HttpServletResponse.SC_OK);
    response.getWriter().print(saml2ClientBuilder.build().getServiceProviderMetadataResolver().getMetadata());
  }
}
