package az.ibrahimshirinov.springsecurityjwtadvanced.filter;

import az.ibrahimshirinov.springsecurityjwtadvanced.constant.SecurityConstant;
import az.ibrahimshirinov.springsecurityjwtadvanced.domain.HttpResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author IbrahimShirinov
 * @since 09.09.2021
 */
public class JwtAuthenticationEntryPoint extends Http403ForbiddenEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        HttpResponse httpResponse = new HttpResponse(HttpStatus.FORBIDDEN.value(),HttpStatus.FORBIDDEN,HttpStatus.FORBIDDEN.getReasonPhrase(), SecurityConstant.FORBIDDEN_MESSAGE);
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.FORBIDDEN.value());

        OutputStream outputStream = response.getOutputStream();
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.writeValue(outputStream,httpResponse);
        outputStream.flush();
    }
}
