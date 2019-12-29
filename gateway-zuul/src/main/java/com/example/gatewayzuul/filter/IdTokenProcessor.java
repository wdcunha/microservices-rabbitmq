package com.example.gatewayzuul.filter;

import com.example.gatewayzuul.config.CognitoJwtAuthentication;
import com.example.gatewayzuul.exception.CognitoException;
import com.example.gatewayzuul.util.AWSConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public class IdTokenProcessor {
    private static final String INVALID_TOKEN = "Invalid Token";
    private static final String NO_TOKEN_FOUND = "Invalid Action, no token found";

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String EMPTY_STRING = "";



    @SuppressWarnings("rawtypes")
    @Autowired
    private ConfigurableJWTProcessor configurableJWTProcessor;

    @Autowired
    private AWSConfig jwtConfiguration;


    /**
     * Method that verifies if the token has the Bearer string key and if it does it removes it.
     *@param token
     *@return token - without the Bearer string
     *@throws ParseException
     * @user ihuaylupo
     * @since 2018-06-26
     */
    private String extractAndDecodeJwt(String token) {
        String tokenResult = token;

        if (token != null && token.startsWith("Bearer ")) {
            tokenResult = token.substring("Bearer ".length());
        }
        return tokenResult;
    }

    /**
     * Method that obtains the authentication and validates the JWT ClaimsSet defined previously in the CognitoJwtAutoConfiguration class .
     *@param request
     *@return org.springframework.security.core.Authentication
     * @throws ParseException
     * @throws JOSEException
     * @throws BadJOSEException
     *@throws Exception
     * @user ihuaylupo
     * @since 2018-06-26
     */
    @SuppressWarnings("unchecked")
    public Authentication getAuthentication(HttpServletRequest request) throws ParseException, BadJOSEException, JOSEException {
        String idToken = request.getHeader(jwtConfiguration.getHttpHeader());
        if(null == idToken) {
            throw new CognitoException(NO_TOKEN_FOUND,CognitoException.NO_TOKEN_PROVIDED_EXCEPTION, "No token found in Http Authorization Header");
        }else {

            idToken = extractAndDecodeJwt(idToken);
            JWTClaimsSet claimsSet = null;

            /**To verify JWT claims:
             1.Verify that the token is not expired.
             2.The audience (aud) claim should match the app client ID created in the Amazon Cognito user pool.
             3.The issuer (iss) claim should match your user pool. For example, a user pool created in the us-east-1 region will have an iss value of: https://cognito-idp.us-east-1.amazonaws.com/<userpoolID>.
             4.Check the token_use claim.
             5.If you are only accepting the access token in your web APIs, its value must be access.
             6.If you are only using the ID token, its value must be id.
             7.If you are using both ID and access tokens, the token_use claim must be either id or access.
             8.You can now trust the claims inside the token.
             */
            claimsSet = configurableJWTProcessor.process(idToken, null);

            if (!isIssuedCorrectly(claimsSet)) {
                throw new CognitoException(INVALID_TOKEN, CognitoException.INVALID_TOKEN_EXCEPTION_CODE, String.format("Issuer %s in JWT token doesn't match cognito idp %s", claimsSet.getIssuer(), jwtConfiguration.getCognitoIdentityPoolUrl()));
            }

            if (!isIdToken(claimsSet)) {
                throw new CognitoException(INVALID_TOKEN, CognitoException.NOT_A_TOKEN_EXCEPTION, "JWT Token doesn't seem to be an ID Token");
            }

            String username = claimsSet.getClaims().get(jwtConfiguration.getUserNameField()).toString();

            List<String> groups = (List<String>) claimsSet.getClaims().get(jwtConfiguration.getGroupsField());
            List<GrantedAuthority> grantedAuthorities = convertList(groups, group -> new SimpleGrantedAuthority(ROLE_PREFIX + group.toUpperCase()));
            User user = new User(username, EMPTY_STRING, grantedAuthorities);


            return new CognitoJwtAuthentication(user, claimsSet, grantedAuthorities);


        }


    }

    /**
     * Method that validates if the tokenId is issued correctly.
     *@param claimsSet
     *@return boolean
     * @user ihuaylupo
     * @since 2018-06-26
     */
    private boolean isIssuedCorrectly(JWTClaimsSet claimsSet) {
        return claimsSet.getIssuer().equals(jwtConfiguration.getCognitoIdentityPoolUrl());
    }


    /**
     * Method that validates if the ID token is valid.
     *@param claimsSet
     *@return
     * @user ihuaylupo
     * @since 2018-06-26
     */
    private boolean isIdToken(JWTClaimsSet claimsSet) {
        return claimsSet.getClaim("token_use").equals("id");
    }


    /**
     * Method generics.
     *@param from
     *@param func
     *@return
     * @user ihuaylupo
     * @since 2018-06-26
     */
    private static <T, U> List<U> convertList(List<T> from, Function<T, U> func) {
        return from.stream().map(func).collect(Collectors.toList());
    }
}
