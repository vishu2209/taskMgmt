package com.vishal.taskMgmt.common.services;

import com.vishal.taskMgmt.sharedLib.user.entities.User;
import com.vishal.taskMgmt.sharedLib.user.entities.UserOTP;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository userOTPRepository;

    public String saveOtp(User user, String otpSentFor) {
        if (user == null) {
            throw new IllegalArgumentException("User cannot be null");
        }
        UserOTP userOtp = userOTPRepository.findByUserIdAndOtpFor(user.getId(), otpSentFor);
        LocalDateTime otpCreatedAt = LocalDateTime.now();
        String otp = RandomOTPGenerator.generateOTP(6);
        if (userOtp != null) {
            userOtp.setOtp(otp);
            userOtp.setCreatedDate(otpCreatedAt);
            userOtp.setExpiredAt(otpCreatedAt.plusMinutes(2));
        } else {
            userOtp = UserOTP.builder()
                    .createdDate(otpCreatedAt)
                    .expiredAt(otpCreatedAt.plusMinutes(2))
                    .otp(otp)
                    .otpFor(otpSentFor)
                    .user(user)
                    .build();
        }
        userOTPRepository.save(userOtp);
        return otp;
    }

    public UserOTP getUserOTP(String userId, String otp, String otpFor) {
        return userOTPRepository.findByUserIdAndOtpAndOtpFor(userId, otp, otpFor);
    }

    public void deleteOTPAfterUse(String id) {
        userOTPRepository.deleteById(id);
    }
}