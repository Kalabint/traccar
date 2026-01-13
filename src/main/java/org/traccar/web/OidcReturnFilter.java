/*
 * Copyright 2026 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.web;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class OidcReturnFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(OidcReturnFilter.class);
    private static final String RETURN_URL_KEY = "oidc.return.url";
    private static final int MAX_SESSION_AGE = 600; // 10 minutes

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpRequest = (HttpServletRequest) request;
            String returnUrl = httpRequest.getParameter("return");
            
            // Store return URL in session if present and valid
            if (returnUrl != null && !returnUrl.isEmpty()) {
                // Validate return URL for security
                if (OidcSecurityValidator.isValidRelativeReturnUrl(returnUrl)) {
                    HttpSession session = httpRequest.getSession(true);
                    
                    // Set session timeout for security
                    session.setMaxInactiveInterval(MAX_SESSION_AGE);
                    
                    // Store validated return URL
                    session.setAttribute(RETURN_URL_KEY, returnUrl);
                    
                    // Store timestamp to prevent replay attacks
                    session.setAttribute(RETURN_URL_KEY + ".timestamp", System.currentTimeMillis());
                    
                    LOGGER.debug("Stored validated return URL in session: {}", returnUrl);
                } else {
                    LOGGER.warn("Invalid return URL rejected: {}", returnUrl);
                    // Don't store invalid URLs - potential attack attempt
                }
            }
        }
        
        chain.doFilter(request, response);
    }
}
