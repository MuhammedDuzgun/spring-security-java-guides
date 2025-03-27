package com.demo.springsecurityjavaguides.repository;

import com.demo.springsecurityjavaguides.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByName(String name);

}
