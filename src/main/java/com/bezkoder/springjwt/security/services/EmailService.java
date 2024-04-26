package com.bezkoder.springjwt.security.services;
import com.bezkoder.springjwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private UserRepository userRepository;

    public void sendResetPasswordEmail(String to, String token) {
        String subject = "Réinitialisation de votre mot de passe";
        String resetUrl = "http://localhost:8080/api/auth/reset-password?token=" + token;
        String content = "Pour réinitialiser votre mot de passe, cliquez sur ce lien : " + resetUrl;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(content);

        mailSender.send(message);
    }


}