package az.ibrahimshirinov.springsecurityjwtadvanced.repository;

import az.ibrahimshirinov.springsecurityjwtadvanced.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author IbrahimShirinov
 * @since 09.09.2021
 */
public interface UserRepository extends JpaRepository<User,Long> {

    User findByUsername(String username);
    User findByEmail(String email);

}
