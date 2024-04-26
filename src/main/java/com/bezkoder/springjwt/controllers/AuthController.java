package com.bezkoder.springjwt.controllers;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.bezkoder.springjwt.models.*;
import com.bezkoder.springjwt.security.services.EmailService;
import com.bezkoder.springjwt.security.services.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.*;

import com.bezkoder.springjwt.payload.request.LoginRequest;
import com.bezkoder.springjwt.payload.request.SignupRequest;
import com.bezkoder.springjwt.payload.response.JwtResponse;
import com.bezkoder.springjwt.payload.response.MessageResponse;
import com.bezkoder.springjwt.repository.RoleRepository;
import com.bezkoder.springjwt.repository.UserRepository;
import com.bezkoder.springjwt.security.jwt.JwtUtils;
import com.bezkoder.springjwt.security.services.UserDetailsImpl;
import org.springframework.web.multipart.MultipartFile;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;
	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;

	@Autowired
	private EmailService emailService;

	@Autowired
	private UserDetailsServiceImpl userService;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());

		return ResponseEntity.ok(new JwtResponse(jwt,
				userDetails.getId(),
				userDetails.getUsername(),
				userDetails.getEmail(),
				roles));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}

		// Create new user's account
		User user = new User(signUpRequest.getUsername(),
				signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));

		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
					case "admin":
						Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(adminRole);

						break;
					case "mod":
						Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(modRole);

						break;
					default:
						Role userRole = roleRepository.findByName(ERole.ROLE_USER)
								.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
						roles.add(userRole);
				}
			});
		}

		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}

	public Set<ImageModel> uploadImage(MultipartFile[] multipartFiles) throws IOException {
		Set<ImageModel> imageModels = new HashSet<ImageModel>();

		for (MultipartFile file : multipartFiles) {
			if (file.isEmpty()) {
				continue;
			}
			try {
				ImageModel imageModel = new ImageModel(file.getOriginalFilename(), file.getContentType(), file.getBytes());
				imageModels.add(imageModel);
			} catch (IOException e) {
				// Log the error or handle it as needed
				System.err.println("Failed to read bytes from file: " + file.getOriginalFilename());
			}
		}

		return imageModels;
	}

	@PutMapping("/updateProfilePicture/{userId}")
	public ResponseEntity<?> updateProfilePicture(@PathVariable Long userId,
												  @RequestParam("file") MultipartFile file) {
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + userId));

		if (!file.isEmpty()) {
			try {
				ImageModel imageModel = new ImageModel(file.getOriginalFilename(), file.getContentType(), file.getBytes());
				// Gérer l'ancienne image si nécessaire...
				user.setProfileImage(imageModel); // Mise à jour avec la nouvelle image
				userRepository.save(user);
				// Envisager de retourner l'URL de l'image si stockée en externe
				return ResponseEntity.ok(new MessageResponse("Profile picture updated successfully!"));
			} catch (IOException e) {
				// Log et gestion des erreurs spécifiques
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
						.body(new MessageResponse("Could not update profile picture."));
			}
		} else {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new MessageResponse("Empty file cannot be uploaded."));
		}
	}


	@PutMapping("/updateProfile/{userId}")
	public ResponseEntity<?> updateProfile(@PathVariable Long userId,
										   @Valid @RequestBody UpdateProfileRequest updateProfileRequest) {
		User user = userRepository.findById(userId)
				.orElseThrow(() -> new UsernameNotFoundException("User Not Found with id: " + userId));

		// Confirmer que le mot de passe actuel est correct
		if (!encoder.matches(updateProfileRequest.getCurrentPassword(), user.getPassword())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Current password is incorrect!"));
		}

		// Vérifier si le nouveau nom d'utilisateur est déjà pris
		if (!user.getUsername().equals(updateProfileRequest.getUsername()) &&
				userRepository.existsByUsername(updateProfileRequest.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
		}

		// Mise à jour du nom d'utilisateur, du mot de passe, de la ville et de la position si fournis
		user.setUsername(updateProfileRequest.getUsername());
		user.setPassword(encoder.encode(updateProfileRequest.getNewPassword()));
		user.setCity(updateProfileRequest.getCity()); // Assurez-vous que le modèle User a un champ pour la ville
		user.setPosition(updateProfileRequest.getPosition()); // Assurez-vous que le modèle User a un champ pour la position

		userRepository.save(user);
		return ResponseEntity.ok(new MessageResponse("User profile updated successfully!"));
	}
	@PostMapping("/forgot-password")
	public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> payload) {
		String email = payload.get("email");
		User user = userRepository.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with email " + email));

		String token = UUID.randomUUID().toString();
		System.out.println("Generated token: " + token);  // Log pour vérifier le token généré
		user.setResetPasswordToken(token);
		user.setResetPasswordExpire(new Date(System.currentTimeMillis() + 3600000)); // Token expire in 1 hour
		userRepository.save(user);

		emailService.sendResetPasswordEmail(email, token);

		return ResponseEntity.ok(new MessageResponse("Reset password email sent."));
	}

	@PutMapping("/reset-password")
	public ResponseEntity<?> resetPassword(@RequestParam String token, @RequestParam String newPassword) {
		System.out.println("Received token: " + token); // Log received token

		User user = userRepository.findByResetPasswordToken(token)
				.orElseThrow(() -> new IllegalStateException("Invalid token"));

		System.out.println("User found: " + user.getUsername() + " with token: " + user.getResetPasswordToken()); // Log user and token from DB

		if (user.getResetPasswordExpire().before(new Date())) {
			System.out.println("Token expired for user: " + user.getUsername()); // Log expired token
			return ResponseEntity.badRequest().body(new MessageResponse("Token expired"));
		}

		user.setPassword(encoder.encode(newPassword));
		user.setResetPasswordToken(null);
		user.setResetPasswordExpire(null);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("Mot de passe mis à jour avec succès."));
	}

	@GetMapping("/reset-password")
	public ResponseEntity<String> validateToken(@RequestParam("token") String token) throws IOException {
		System.out.println("Received token: " + token);
		Optional<User> userOptional = userRepository.findByResetPasswordToken(token);
		System.out.println("Is token present in DB? " + userOptional.isPresent());

		if (!userOptional.isPresent()) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Invalid token");
		}

		User user = userOptional.get();
		if (user.getResetPasswordExpire().before(new Date())) {
			return ResponseEntity.badRequest().body("Token expired");
		}

		// Load the HTML form from file
		String htmlContent = loadResetPasswordForm();

		// Return the HTML form as response
		return ResponseEntity.ok(htmlContent);
	}

	// Utility method to load HTML form from file
	private String loadResetPasswordForm() throws IOException {
		try (InputStream inputStream = new ClassPathResource("reset-password-form.html").getInputStream()) {
			return StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
		}
	}
	/*@PutMapping("/set-password")
	public ResponseEntity<String> setPassword(@RequestParam String email, @RequestHeader String newPassword){
		return  new ResponseEntity<>(userService.setPassword(email, newPassword), HttpStatus.OK);
	}*/

}