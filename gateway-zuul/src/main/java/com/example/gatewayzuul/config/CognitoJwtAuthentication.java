package com.example.gatewayzuul.config;

import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class CognitoJwtAuthentication extends AbstractAuthenticationToken {

    /**Generated SerialVersionUID*/
    private static final long serialVersionUID = 4780644483172376731L;
    private final transient Object principal;
    private JWTClaimsSet jwtClaimsSet;

    /** Constructor with parameters
     * @param principal
     * @param jwtClaimsSet
     * @param authorities
     */
    public CognitoJwtAuthentication(Object principal, JWTClaimsSet jwtClaimsSet, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.jwtClaimsSet = jwtClaimsSet;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public JWTClaimsSet getJwtClaimsSet() {
        return jwtClaimsSet;
    }
}
