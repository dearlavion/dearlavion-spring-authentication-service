package com.dearlavion.authservice.auth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

/** Emails a superadmin their reset link over SMTP. The token is never logged. */
@Slf4j
@Component
public class ResetMailer {

    private final ObjectProvider<JavaMailSender> sender;
    private final String smtpHost;
    private final String from;
    private final String resetUrl;
    private final long ttlMinutes;

    public ResetMailer(ObjectProvider<JavaMailSender> sender,
                       @Value("${spring.mail.host:}") String smtpHost,
                       @Value("${app.mail-from}") String from,
                       @Value("${spring.mail.username:}") String smtpUsername,
                       @Value("${app.security-reset-url}") String resetUrl,
                       @Value("${app.jwt-reset-expires-in-seconds}") long ttlSeconds) {
        this.sender = sender;
        this.smtpHost = smtpHost;
        this.from = from.isBlank() ? smtpUsername : from;
        this.resetUrl = resetUrl;
        this.ttlMinutes = Math.max(1, ttlSeconds / 60);
    }

    /** Sends in the background, so the response takes the same time whether or not the account exists. */
    public void send(String to, String username, String token) {
        JavaMailSender mail = sender.getIfAvailable();
        if (smtpHost.isBlank() || from.isBlank() || mail == null) {
            log.warn("Password reset email not sent: set SMTP_HOST and MAIL_FROM (or SMTP_USERNAME)");
            return;
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(to);
        message.setSubject("Reset your Dear Lavion Security password");
        // The token goes in the URL fragment, which browsers don't send to servers (so it stays out of access logs).
        message.setText("Hi " + username + ",\n\n"
                + "Open this link to choose a new password:\n" + resetUrl + "#token=" + token + "\n\n"
                + "It works once and expires in " + ttlMinutes + " minutes. "
                + "If you didn't ask for this, you can ignore this email.\n");
        CompletableFuture.runAsync(() -> {
            try {
                mail.send(message);
                log.info("Password reset email accepted by the mail server");
            } catch (Exception e) {
                log.error("Password reset email failed: {}", e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        });
    }
}
