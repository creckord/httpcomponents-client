/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */
package org.apache.http.impl.auth.win;

import com.sun.jna.platform.win32.Secur32;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.CredHandle;
import com.sun.jna.platform.win32.Sspi.CtxtHandle;
import com.sun.jna.platform.win32.Sspi.SecBufferDesc;
import com.sun.jna.platform.win32.Sspi.TimeStamp;
import com.sun.jna.platform.win32.Win32Exception;
import com.sun.jna.platform.win32.WinError;
import com.sun.jna.ptr.IntByReference;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AUTH;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.MalformedChallengeException;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.conn.routing.RouteInfo;
import org.apache.http.impl.auth.AuthSchemeBase;
import org.apache.http.message.BufferedHeader;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.CharArrayBuffer;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * Auth scheme that makes use of JNA to implement Negotiate and NTLM on Windows Platforms.
 * <p>
 * This will delegate negotiation to the windows machine.
 * </p>
 * <p>
 * EXPERIMENTAL
 * </p>
 *
 * @since 4.4
 */
public class WindowsNegotiateScheme extends AuthSchemeBase {

    private final Log log = LogFactory.getLog(getClass());

    private static final TokenAccess TOKEN_ACCESS;

    static {
        TokenAccess ta = null;
        try {
            ta = new TokenAccessJna5();
        } catch (final Exception ex) {
            //ignore
        }
        if (ta == null) {
            try {
                ta = new TokenAccessJna4();
            } catch (final Exception ex) {
                throw new UnsupportedOperationException("Failed to initialize JNA API", ex);
            }
        }
        TOKEN_ACCESS = ta;
    }

    // NTLM or Negotiate
    private final String schemeName;
    private final String servicePrincipalName;

    private String challenge;
    private CredHandle clientCred;
    private CtxtHandle sspiContext;
    private boolean continueNeeded;

    public WindowsNegotiateScheme(final String schemeName, final String servicePrincipalName) {
        super();

        this.schemeName = (schemeName == null) ? AuthSchemes.SPNEGO : schemeName;
        this.continueNeeded = true;
        this.servicePrincipalName = servicePrincipalName;

        if (this.log.isDebugEnabled()) {
            this.log.debug("Created WindowsNegotiateScheme5 using " + this.schemeName);
        }
    }

    public void dispose() {
        if (clientCred != null && !clientCred.isNull()) {
            final int rc = Secur32.INSTANCE.FreeCredentialsHandle(clientCred);
            if (WinError.SEC_E_OK != rc) {
                throw new Win32Exception(rc);
            }
        }
        if (sspiContext != null && !sspiContext.isNull()) {
            final int rc = Secur32.INSTANCE.DeleteSecurityContext(sspiContext);
            if (WinError.SEC_E_OK != rc) {
                throw new Win32Exception(rc);
            }
        }
        continueNeeded = true; // waiting
        clientCred = null;
        sspiContext = null;
    }

    @Override
    public void finalize() throws Throwable {
        dispose();
        super.finalize();
    }

    @Override
    public String getSchemeName() {
        return schemeName;
    }

    @Override
    public boolean isConnectionBased() {
        return true;
    }

    // String parameters not supported
    @Override
    public String getParameter(final String name) {
        return null;
    }

    @Override
    public String getRealm() {
        return null;
    }

    @Override
    protected void parseChallenge(
            final CharArrayBuffer buffer,
            final int beginIndex,
            final int endIndex) throws MalformedChallengeException {
        this.challenge = buffer.substringTrimmed(beginIndex, endIndex);

        if (this.challenge.isEmpty()) {
            if (clientCred != null) {
                dispose(); // run cleanup first before throwing an exception otherwise can leak OS resources
                if (continueNeeded) {
                    throw new RuntimeException("Unexpected token");
                }
            }
        }
    }

    /**
     * Get the SAM-compatible username of the currently logged-on user.
     *
     * @return String.
     */
    public static String getCurrentUsername() {
        return CurrentWindowsCredentials.getCurrentUsername();
    }

    @Override
    public Header authenticate(
            final Credentials credentials,
            final HttpRequest request,
            final HttpContext context) throws AuthenticationException {

        final HttpClientContext clientContext = HttpClientContext.adapt(context);
        final String response;
        if (clientCred == null) {
            // client credentials handle
            try {
                final String username = getCurrentUsername();
                final TimeStamp lifetime = new TimeStamp();

                clientCred = new CredHandle();
                final int rc = Secur32.INSTANCE.AcquireCredentialsHandle(username,
                        schemeName, Sspi.SECPKG_CRED_OUTBOUND, null, null, null, null,
                        clientCred, lifetime);

                if (WinError.SEC_E_OK != rc) {
                    throw new Win32Exception(rc);
                }

                final String targetName = getServicePrincipalName(request, clientContext);
                response = getToken(null, null, targetName);
            } catch (final RuntimeException ex) {
                failAuthCleanup();
                if (ex instanceof Win32Exception) {
                    throw new AuthenticationException("Authentication Failed", ex);
                }
                throw ex;
            }
        } else if (challenge == null || challenge.isEmpty()) {
            failAuthCleanup();
            throw new AuthenticationException("Authentication Failed");
        } else {
            try {
                final byte[] continueTokenBytes = Base64.decodeBase64(challenge);
                final SecBufferDesc continueTokenBuffer = TOKEN_ACCESS.create(
                                Sspi.SECBUFFER_TOKEN, continueTokenBytes);
                final String targetName = getServicePrincipalName(request, clientContext);
                response = getToken(this.sspiContext, continueTokenBuffer, targetName);
            } catch (final RuntimeException ex) {
                failAuthCleanup();
                if (ex instanceof Win32Exception) {
                    throw new AuthenticationException("Authentication Failed", ex);
                }
                throw ex;
            }
        }

        final CharArrayBuffer buffer = new CharArrayBuffer(schemeName.length() + 30);
        if (isProxy()) {
            buffer.append(AUTH.PROXY_AUTH_RESP);
        } else {
            buffer.append(AUTH.WWW_AUTH_RESP);
        }
        buffer.append(": ");
        buffer.append(schemeName); // NTLM or Negotiate
        buffer.append(" ");
        buffer.append(response);
        return new BufferedHeader(buffer);
    }

    private void failAuthCleanup() {
        dispose();
        this.continueNeeded = false;
    }

    // Per RFC4559, the Service Principal Name should HTTP/<hostname>. However, <hostname>
    // can just be the host or the fully qualified name (e.g., see "Kerberos SPN generation"
    // at http://www.chromium.org/developers/design-documents/http-authentication). Here,
    // I've chosen to use the host that has been provided in HttpHost so that I don't incur
    // any additional DNS lookup cost.
    private String getServicePrincipalName(final HttpRequest request, final HttpClientContext clientContext) {
        String spn = null;
        if (this.servicePrincipalName != null) {
            spn = this.servicePrincipalName;
        } else if (isProxy()) {
            final RouteInfo route = clientContext.getHttpRoute();
            if (route != null) {
                spn = "HTTP/" + route.getProxyHost().getHostName();
            } else {
                // Should not happen
                spn = null;
            }
        } else {
            final HttpHost target = clientContext.getTargetHost();
            if (target != null) {
                spn = "HTTP/" + target.getHostName();
            } else {
                final RouteInfo route = clientContext.getHttpRoute();
                if (route != null) {
                    spn = "HTTP/" + route.getTargetHost().getHostName();
                } else {
                    // Should not happen
                    spn = null;
                }
            }
        }
        if (this.log.isDebugEnabled()) {
            this.log.debug("Using SPN: " + spn);
        }
        return spn;
    }

    // See http://msdn.microsoft.com/en-us/library/windows/desktop/aa375506(v=vs.85).aspx
    String getToken(
            final CtxtHandle continueCtx,
            final SecBufferDesc continueToken,
            final String targetName) {
        final IntByReference attr = new IntByReference();
        final SecBufferDesc token = TOKEN_ACCESS.create(
                Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE);

        sspiContext = new CtxtHandle();
        final int rc = Secur32.INSTANCE.InitializeSecurityContext(clientCred,
                continueCtx, targetName, Sspi.ISC_REQ_DELEGATE | Sspi.ISC_REQ_MUTUAL_AUTH, 0,
                Sspi.SECURITY_NATIVE_DREP, continueToken, 0, sspiContext, token,
                attr, null);
        switch (rc) {
            case WinError.SEC_I_CONTINUE_NEEDED:
                continueNeeded = true;
                break;
            case WinError.SEC_E_OK:
                dispose(); // Don't keep the context
                continueNeeded = false;
                break;
            default:
                dispose();
                throw new Win32Exception(rc);
        }
        return Base64.encodeBase64String(TOKEN_ACCESS.getBytes(token));
    }

    @Override
    public boolean isComplete() {
        return !continueNeeded;
    }

    /**
     * @deprecated Use {@link #authenticate(Credentials, HttpRequest, HttpContext)}
     */
    @Override
    @Deprecated
    public Header authenticate(
            final Credentials credentials,
            final HttpRequest request) throws AuthenticationException {
        return authenticate(credentials, request, null);
    }

    private static abstract class TokenAccess {

        abstract SecBufferDesc create(int type, int size);
        abstract SecBufferDesc create(int type, byte[] token);
        abstract byte[] getBytes(SecBufferDesc token);

        <T> T safeCreateInstance(final Constructor<T> ctor, final Object... args) {
            try {
                return ctor.newInstance(args);
            } catch (final InstantiationException e) {
                throw new UnsupportedOperationException(e);
            } catch (final IllegalAccessException e) {
                throw new UnsupportedOperationException(e);
            } catch (final InvocationTargetException e) {
                final Throwable cause = e.getCause();
                if (cause instanceof RuntimeException) {
                    throw (RuntimeException) cause;
                }
                throw new IllegalArgumentException(cause);
            }
        }

        Object safeInvoke(final Method m, final Object target, final Object... args) {
            try {
                return m.invoke(target, args);
            } catch (final IllegalAccessException e) {
                throw new UnsupportedOperationException(e);
            } catch (final InvocationTargetException e) {
                final Throwable cause = e.getCause();
                if (cause instanceof RuntimeException) {
                    throw (RuntimeException) cause;
                }
                throw new IllegalArgumentException(cause);
            }
        }
    }

    private static final class TokenAccessJna4 extends TokenAccess {

        private final Constructor<SecBufferDesc> sizeCtor;
        private final Constructor<SecBufferDesc> tokenCtor;
        private final Method getBytes;

        TokenAccessJna4() {
            try {
                sizeCtor = SecBufferDesc.class.getConstructor(int.class, int.class);
                tokenCtor = SecBufferDesc.class.getConstructor(int.class, byte[].class);
                getBytes = SecBufferDesc.class.getMethod("getBytes");
            } catch (final NoSuchMethodException e) {
                throw new UnsupportedOperationException("JNA 4 API not available", e);
            }
        }

        @Override
        SecBufferDesc create(final int type, final int size) {
            return safeCreateInstance(sizeCtor, type, size);
        }

        @Override
        SecBufferDesc create(final int type, final byte[] token) {
            return safeCreateInstance(tokenCtor, type, token);
        }

        @Override
        byte[] getBytes(final SecBufferDesc token) {
            return (byte[]) safeInvoke(getBytes, token);
        }
    }

    private static final class TokenAccessJna5 extends TokenAccess {

        private final Constructor<?> sizeCtor;
        private final Constructor<?> tokenCtor;
        private final Method getBuffer;

        TokenAccessJna5() {
            try {
                final Class<?> managedSecBufferDescClass = Class.forName("com.sun.jna.platform.win32.SspiUtil$ManagedSecBufferDesc");
                sizeCtor = managedSecBufferDescClass.getConstructor(int.class, int.class);
                tokenCtor = managedSecBufferDescClass.getConstructor(int.class, byte[].class);
                getBuffer = managedSecBufferDescClass.getMethod("getBuffer", int.class);
            } catch (final ClassNotFoundException e) {
                throw new UnsupportedOperationException("JNA 5 API not available", e);
            } catch (final NoSuchMethodException e) {
                throw new UnsupportedOperationException("JNA 5 API not available", e);
            }
        }

        @Override
        SecBufferDesc create(final int type, final int size) {
            return (SecBufferDesc) safeCreateInstance(sizeCtor, type, size);
        }

        @Override
        SecBufferDesc create(final int type, final byte[] token) {
            return (SecBufferDesc) safeCreateInstance(tokenCtor, type, token);
        }

        @Override
        byte[] getBytes(final SecBufferDesc token) {
            final Sspi.SecBuffer buffer = (Sspi.SecBuffer) safeInvoke(getBuffer, token, 0);
            return buffer.getBytes();
        }
    }
}
