package com.codewithprojects.springsecurity;

import com.codewithprojects.springsecurity.entities.Role;
import com.codewithprojects.springsecurity.entities.User;
import com.codewithprojects.springsecurity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootApplication
public class SpringsecurityApplication implements CommandLineRunner {

	@Autowired
	UserRepository userRepository;

	public static void main(String[] args) {
		SpringApplication.run(SpringsecurityApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {

		if(userRepository.findByRole(Role.ADMIN) == null)
		{
			User user = new User();
			user.setFirstName("Admin");
			user.setSecondName("Ladmin");
			user.setEmail("admin@gamil.com");
			user.setRole(Role.ADMIN);
			user.setPasword(new BCryptPasswordEncoder().encode("admin"));
			userRepository.save(user);
		}
	}
}
