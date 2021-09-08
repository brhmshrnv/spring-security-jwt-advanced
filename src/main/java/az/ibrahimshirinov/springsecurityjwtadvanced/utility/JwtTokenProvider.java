package az.ibrahimshirinov.springsecurityjwtadvanced.utility;

import az.ibrahimshirinov.springsecurityjwtadvanced.domain.UserPrincipal;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static az.ibrahimshirinov.springsecurityjwtadvanced.constant.SecurityConstant.*;
import static com.auth0.jwt.algorithms.Algorithm.HMAC512;
import static java.util.Arrays.stream;

/**
 * @author IbrahimShirinov
 * @since 07.09.2021
 */
@Component
public class JwtTokenProvider {

    @Value("jwt.secret")
    private String secret;

    private String generateJwtToken(UserPrincipal userPrincipal){
        String[] claims = getClaimsFromUser(userPrincipal);
        return JWT.create()
                .withIssuer(TOKEN_ISSUE)
                .withAudience(ABOUT_PROJECT)
                .withIssuedAt(new Date())
                .withSubject(userPrincipal.getUsername())
                .withArrayClaim(AUTHORITIES,claims)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .sign(HMAC512(secret.getBytes()));
    }

    /**
     *
     * @param token jwt token
     * @return authority list
     * @implNote retrieving authorities from jwt token
     */
    public List<GrantedAuthority> getAuthorities(String token) {
        String[] claims = getClaimsFromToken(token);
        return stream(claims).map(SimpleGrantedAuthority::new).collect(Collectors.toList());

    }

    /**
     *
     * @param username username of current user
     * @param authorities authorities of current user
     * @param request http request
     * @return UsernamePasswordAuthenticationToken Object
     * @implNote So the reason i did this method is that if i can verify that a token is correct. I have to tell spring security to get me authentication of the user and then set that authentication in the spring security context
     */
    public Authentication getAuthentication(String username, List<GrantedAuthority> authorities, HttpServletRequest request) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,null,authorities);
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return authenticationToken;
    }

    /**
     *
     * @param username username of current user
     * @param token jwt token of current user
     * @return true or false
     * @implNote this method checks token is valid
     */
    public boolean isTokenValid(String username,String token) {
        JWTVerifier verifier = getVerifier(token);
        return StringUtils.isNotEmpty(username) && isTokenExpired(verifier, token);

    }

    /**
     *
     * @param verifier  object for verify jwt token
     * @param token  jwt token
     * @return true or false
     * @implNote this method checks token is expired or not
     */
    private boolean isTokenExpired(JWTVerifier verifier, String token) {
        Date expiration = verifier.verify(token).getExpiresAt();
        return expiration.before(new Date());
    }

    /**
     *
     * @param token
     * @return subject of jwt token
     * @implNote getting subject of token , using jwt verifier
     */
    private String getSubject(String token) {
        JWTVerifier verifier = getVerifier(token);
        return verifier.verify(token).getSubject();
    }

    /**
     *
     * @param token jwt token
     * @return claims
     * @implNote  extract claims(jwt payload) from jwt token
     */
    public String[] getClaimsFromToken(String token) {
        JWTVerifier verifier = getVerifier(token);
        return verifier.verify(token).getClaim(AUTHORITIES).asArray(String.class);
    }

    /**
     *
     * @param token jwt token
     * @return jwt verifier
     * @implNote  verify token using HMAC512 and issuer
     */
    public JWTVerifier getVerifier(String token){
        JWTVerifier verifier;
        try {
            Algorithm algorithm = HMAC512(secret);
            verifier = JWT.require(algorithm).withIssuer(TOKEN_ISSUE).build();
        }catch (JWTVerificationException exception) {
            throw new JWTVerificationException(TOKEN_CANNOT_BE_VERIFIED);
        }

        return verifier;
    }

    /**
     *
     * @param userPrincipal is credentials of current logged in user
     * @return claims
     * @implNote retrieve claims(only roles) from jwt token
     */
    private String[] getClaimsFromUser(UserPrincipal userPrincipal) {
        List<String> authorities = new ArrayList<>();
        userPrincipal.getAuthorities().forEach(grantedAuthority -> authorities.add(grantedAuthority.getAuthority()));
        return authorities.toArray(String[]::new);
    }
}
