package org.exoplatform.security.session;

import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Created by eXo Platform MEA on 23/10/14.
 *
 * @author <a href="mailto:mtrabelsi@exoplatform.com">Marwen Trabelsi</a>
 */
public class SessionTimeoutFilter extends AbstractFilter {

  private final Log LOG = ExoLogger.getLogger("org.exoplatform.security.session.SessionTimeoutFilter");

  private static final String AJAX_TIMEOUT_FLAG = "ajax-timeout-flag";
  public static final String PORTAL_SESSION_TIMEOUT = "portal.session.timeout";

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {

    HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;

    HttpSession session = httpRequest.getSession(true);
    String sessionTimeout = System.getProperty(PORTAL_SESSION_TIMEOUT);

    if ((session != null)) {

      LOG.info(String.format("Setting \"%s\" to track session timeout.", AJAX_TIMEOUT_FLAG));
      session.setAttribute(AJAX_TIMEOUT_FLAG, AJAX_TIMEOUT_FLAG);

      int sessionTimeoutValue = Integer.parseInt(sessionTimeout);
      if ((sessionTimeout != null) && (session.getMaxInactiveInterval() != sessionTimeoutValue)) {
        LOG.info(String.format("Session timeout will be changed from : '%d' to '%d' (seconds)", session.getMaxInactiveInterval(), sessionTimeoutValue));
        session.setMaxInactiveInterval(Integer.parseInt(sessionTimeout));
      }
    }
    filterChain.doFilter(httpRequest, servletResponse);
  }

  @Override
  public void destroy() {}
}
