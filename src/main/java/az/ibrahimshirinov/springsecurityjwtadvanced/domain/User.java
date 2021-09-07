package az.ibrahimshirinov.springsecurityjwtadvanced.domain;

import lombok.*;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Date;

/**
 * @author IbrahimShirinov
 * @since 07.09.2021
 */

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class User implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(nullable = false,updatable = false)
    private Long id;
    private String userId;
    private String firstName;
    private String lastName;
    private String username;
    private String password;
    private String email;
    private String profileImageUrl;
    private Date lastLoginDate;
    private Date lastLoginDateDisplay;
    private Date joinDate;
    private String[] roles; //ROLE_USER, ROLE_ADMIN
    private String[] authorities; //ROLE_USER{delete,read,write}
    private boolean isActive;
    private boolean isNotLocked;

}
