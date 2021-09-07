package az.ibrahimshirinov.springsecurityjwtadvanced.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

/**
 * @author IbrahimShirinov
 * @since 07.09.2021
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
public class HttpResponse {

    private int httpStatusCode; // 200, 201, 500. 404
    private HttpStatus httpStatus; // INTERNAL_SERVER_ERROR
    private String reason; // Internal Server Error
    private String message; // Your Reason
}
