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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Security validator for OIDC return URLs and redirect URIs
 * Implements protection against:
 * - Open redirects
 * - XSS attacks
 * - Path traversal
 * - Protocol injection
 */
public class OidcSecurityValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(OidcSecurityValidator.class);

    // Allowed URL schemes
    private static final List<String> ALLOWED_SCHEMES = Arrays.asList("http", "https");
    
    // Dangerous patterns to block
    private static final Pattern JAVASCRIPT_PATTERN = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);
    private static final Pattern DATA_PATTERN = Pattern.compile("data:", Pattern.CASE_INSENSITIVE);
    private static final Pattern VBSCRIPT_PATTERN = Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE);
    private static final Pattern PATH_TRAVERSAL_PATTERN = Pattern.compile("\\.\\./");
    private static final Pattern XSS_PATTERN = Pattern.compile("<script|javascript:|onerror=|onload=", Pattern.CASE_INSENSITIVE);
    
    // Maximum URL length to prevent DoS
    private static final int MAX_URL_LENGTH = 2048;

    /**
     * Validates a return URL for security issues
     * @param returnUrl The URL to validate
     * @param allowedHosts List of allowed hostnames (null = only allow relative paths)
     * @return true if URL is safe, false otherwise
     */
    public static boolean isValidReturnUrl(String returnUrl, List<String> allowedHosts) {
        if (returnUrl == null || returnUrl.trim().isEmpty()) {
            return false;
        }

        // Check length
        if (returnUrl.length() > MAX_URL_LENGTH) {
            LOGGER.warn("Return URL exceeds maximum length: {}", returnUrl.length());
            return false;
        }

        // Check for dangerous patterns
        if (JAVASCRIPT_PATTERN.matcher(returnUrl).find()) {
            LOGGER.warn("JavaScript protocol detected in return URL");
            return false;
        }
        
        if (DATA_PATTERN.matcher(returnUrl).find()) {
            LOGGER.warn("Data protocol detected in return URL");
            return false;
        }
        
        if (VBSCRIPT_PATTERN.matcher(returnUrl).find()) {
            LOGGER.warn("VBScript protocol detected in return URL");
            return false;
        }

        if (PATH_TRAVERSAL_PATTERN.matcher(returnUrl).find()) {
            LOGGER.warn("Path traversal detected in return URL");
            return false;
        }

        if (XSS_PATTERN.matcher(returnUrl).find()) {
            LOGGER.warn("Potential XSS pattern detected in return URL");
            return false;
        }

        // If it starts with /, it's a relative path - validate it
        if (returnUrl.startsWith("/")) {
            // Ensure it doesn't try to escape with //
            if (returnUrl.startsWith("//")) {
                LOGGER.warn("Protocol-relative URL not allowed: {}", returnUrl);
                return false;
            }
            return true;
        }

        // If it's an absolute URL, validate against whitelist
        try {
            URI uri = new URI(returnUrl);
            
            // Check scheme
            String scheme = uri.getScheme();
            if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
                LOGGER.warn("Invalid scheme in return URL: {}", scheme);
                return false;
            }

            // Check host against whitelist
            String host = uri.getHost();
            if (host == null) {
                LOGGER.warn("No host in return URL");
                return false;
            }

            if (allowedHosts == null || allowedHosts.isEmpty()) {
                LOGGER.warn("Absolute URL not allowed (no whitelist): {}", host);
                return false;
            }

            // Check if host is in whitelist (exact match or subdomain)
            boolean hostAllowed = false;
            for (String allowedHost : allowedHosts) {
                if (host.equals(allowedHost) || host.endsWith("." + allowedHost)) {
                    hostAllowed = true;
                    break;
                }
            }

            if (!hostAllowed) {
                LOGGER.warn("Host not in whitelist: {}", host);
                return false;
            }

            return true;

        } catch (URISyntaxException e) {
            LOGGER.warn("Invalid URI syntax in return URL: {}", returnUrl, e);
            return false;
        }
    }

    /**
     * Validates a return URL allowing only relative paths
     * @param returnUrl The URL to validate
     * @return true if URL is a safe relative path, false otherwise
     */
    public static boolean isValidRelativeReturnUrl(String returnUrl) {
        return isValidReturnUrl(returnUrl, null);
    }

    /**
     * Sanitizes a return URL by removing dangerous characters
     * This is a fallback - validation should be preferred
     * @param returnUrl The URL to sanitize
     * @return Sanitized URL or null if cannot be sanitized safely
     */
    public static String sanitizeReturnUrl(String returnUrl) {
        if (returnUrl == null) {
            return null;
        }

        // Remove any null bytes
        returnUrl = returnUrl.replace("\0", "");
        
        // Remove any control characters
        returnUrl = returnUrl.replaceAll("[\\p{Cntrl}]", "");
        
        // Trim whitespace
        returnUrl = returnUrl.trim();

        // If it's now empty or invalid, return null
        if (returnUrl.isEmpty() || !isValidRelativeReturnUrl(returnUrl)) {
            return null;
        }

        return returnUrl;
    }

    /**
     * Validates an OIDC redirect URI against registered client URIs
     * @param redirectUri The redirect URI to validate
     * @param registeredUris List of registered redirect URIs for the client
     * @return true if redirect URI matches a registered URI, false otherwise
     */
    public static boolean isValidRedirectUri(String redirectUri, List<String> registeredUris) {
        if (redirectUri == null || registeredUris == null || registeredUris.isEmpty()) {
            return false;
        }

        // Exact match required for security
        return registeredUris.contains(redirectUri);
    }
}
