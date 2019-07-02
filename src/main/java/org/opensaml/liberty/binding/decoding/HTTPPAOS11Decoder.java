package org.opensaml.liberty.binding.decoding;

import javax.servlet.http.HttpServletRequest;

import ca.redtoad.sp.SAMLUtil;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;

public class HTTPPAOS11Decoder
    extends HTTPSOAP11Decoder
{
  @Override
  protected void validateHttpRequest(HttpServletRequest request) throws MessageDecodingException {
    try {
      super.validateHttpRequest(request);
    }
    catch (MessageDecodingException e) {
      if (!request.getContentType().equals(SAMLUtil.ECP_ACCEPT_HEADER_VALUE) || !e.getMessage()
          .equals(String.format("Content-Type '%s' was not a supported media type", request.getContentType()))) {
        throw e;
      }
    }
  }
}
