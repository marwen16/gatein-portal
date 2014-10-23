package org.exoplatform.security.session;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.RootContainer;
import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Created by eXo Platform MEA on 20/10/14.
 *
 * @author <a href="mailto:mtrabelsi@exoplatform.com">Marwen Trabelsi</a>
 */
public class CustomSessionFilter extends AbstractFilter {

  private final Log LOG = ExoLogger.getLogger("org.exoplatform.security.session.CustomSessionFilter");

  private static final int TIMEOUT_STATUS_CODE = 440;

  public static final String PORTAL_SESSION_TIMEOUT = "portal.session.timeout";

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
      throws IOException, ServletException {

    HttpServletRequest httpRequest = (HttpServletRequest) servletRequest;
    HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

    if (isAJAXRequest(httpRequest) && !httpRequest.isRequestedSessionIdValid()) {
      if (LOG.isDebugEnabled())
        LOG.info(">> The session is no more valid, we will return an error since this is an AJAX request.");
      httpResponse.sendError(TIMEOUT_STATUS_CODE);
      return;
    } else {
      filterChain.doFilter(httpRequest, servletResponse);
    }

    HttpSession session = httpRequest.getSession();
    String sessionTimeout = System.getProperty(PORTAL_SESSION_TIMEOUT);
    if (sessionTimeout != null) {
      int sessionTimeoutValue = Integer.parseInt(sessionTimeout);
      if (session.getMaxInactiveInterval() != sessionTimeoutValue) {
        LOG.info(String.format("Session timeout will be changed from : '%d' to '%d' (seconds)", session.getMaxInactiveInterval(), sessionTimeoutValue));
        session.setMaxInactiveInterval(Integer.parseInt(sessionTimeout));
      }
    }
  }

  private boolean isAJAXRequest(HttpServletRequest request) {
    return "XMLHttpRequest".equals(request.getHeader("X-Requested-With"));
  }

  @Override
  public void destroy() {

  }

  private void completeLoginPhase(HttpServletRequest req, HttpServletResponse resp, String azione, boolean includeJSP) throws IOException, ServletException {
    LOG.debug("Add AZIONE: " + azione);
    req.setAttribute("azione", azione);

    if (includeJSP) {
      LOG.debug(">>completeLoginPhase");
      String loginUri = "/login/jsp/login.jsp";
      getRequestDispatcher(req, loginUri).include(req, resp);
      LOG.debug("<<completeLoginPhase");
    }
  }

  private RequestDispatcher getRequestDispatcher(HttpServletRequest req, String path) {
    ExoContainer container = ExoContainerContext.getCurrentContainer();
    if ((container instanceof RootContainer)) {
      container = ((RootContainer)container).getPortalContainer(req.getContextPath().replaceAll("/", ""));
      if (container == null) {
        container = PortalContainer.getInstance();
      }
    }
    if (container != null) {
      return ((PortalContainer)container).getPortalContext().getRequestDispatcher(path);
    }
    return req.getRequestDispatcher(path);
  }
}
