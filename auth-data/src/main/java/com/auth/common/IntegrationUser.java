package com.auth.common;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * @Auther: vicykie
 * @Date: 2018/8/16 20:33
 * @Description:
 */
@Getter
@Setter
public class IntegrationUser extends User implements Serializable {
    private static final long serialVersionUID = 600L;
    private Long id;
    private String wxOpenId;
    private String email;
    private String telephone;
    private String token;

    private boolean deleted;
    private List<Long> roleIds = Collections.emptyList();
    private String appType;

    public IntegrationUser(String username, String password, Collection<? extends GrantedAuthority> authorities) {
        super(username, password, authorities);
    }

    public IntegrationUser(String username, String password, Boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired,
                           boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities, Long id,
                           String wxOpenId, String email, String telephone, String token,
                           String appType, boolean deleted, List<Long> roleIds) {
        super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
        this.id = id;
        this.wxOpenId = wxOpenId;
        this.email = email;
        this.telephone = telephone;
        this.token = token;
        this.appType = appType;
        this.deleted = deleted;
        this.roleIds = roleIds;
    }

    @Override
    public String toString() {
        return "IntegrationUser{" +
                "id=" + id +
                ", wxOpenId='" + wxOpenId + '\'' +
                ", email='" + email + '\'' +
                ", telephone='" + telephone + '\'' +
                ", token='" + token + '\'' +
                ", deleted=" + deleted +
                ", roleIds=" + roleIds +
                ", appType='" + appType + '\'' +
                ", super='" + super.toString() + '\'' +
                '}';
    }
}
