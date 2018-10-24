package com.zc.service.impl;

import com.zc.bean.IntegrationUser;
import com.zc.service.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service("userService")
public class UserServiceImpl implements UserService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        IntegrationUser integrationUser = new IntegrationUser("admin", "$2a$10$BOmMzLDaoiIQ4Q1pCw6Z4u0gzL01B8bNL.0WUecJ2YxTtHVRIA8Zm", new ArrayList<GrantedAuthority>());

        return integrationUser;
    }
}
