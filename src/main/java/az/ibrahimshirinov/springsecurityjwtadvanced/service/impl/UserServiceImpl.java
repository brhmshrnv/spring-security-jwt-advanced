package az.ibrahimshirinov.springsecurityjwtadvanced.service.impl;

import az.ibrahimshirinov.springsecurityjwtadvanced.domain.User;
import az.ibrahimshirinov.springsecurityjwtadvanced.domain.UserPrincipal;
import az.ibrahimshirinov.springsecurityjwtadvanced.repository.UserRepository;
import az.ibrahimshirinov.springsecurityjwtadvanced.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;

/**
 * @author IbrahimShirinov
 * @since 09.09.2021
 */

@Slf4j
@Service
@Qualifier("UserDetailsService")
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            log.error("User not found by username: " + username);
            throw new UsernameNotFoundException("User not found by username: " + username);
        }else {
            log.info("Returning found user by username: " + username);
            user.setLastLoginDate(new Date());
            user.setLastLoginDateDisplay(user.getLastLoginDate());
            userRepository.save(user);
            return new UserPrincipal(user);

        }

    }
}
