package com.vishal.taskMgmt.common.services;

import java.time.LocalDateTime;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.vishal.taskMgmt.sharedLib.user.entities.User;
import com.vishal.taskMgmt.sharedLib.user.entities.UserOTP;

@Service
public class OtpService {

	@Autowired
	private OtpRepository userOTPRepository;
	
	public String saveOtp(User user, String otpSentFor) {
		String otp = null;
		if (user != null) {
			UserOTP userOtp = this.userOTPRepository.findByUserIdAndOtpFor(user.getId(), otpSentFor);
			LocalDateTime otpCreatedAt = LocalDateTime.now();
			otp = RandomOTPGenerator.generateOTP(6);
			if (userOtp != null) {
				userOtp.setOtp(otp);
				userOtp.setCreatedDate(otpCreatedAt);
				userOtp.setExpiredAt(otpCreatedAt.plusSeconds(123));
			} else {
				userOtp = UserOTP.builder().createdDate(otpCreatedAt).expiredAt(otpCreatedAt.plusMinutes(2)).otp(otp)
						.otpFor(otpSentFor).user(user).build();
			}
			userOTPRepository.save(userOtp);
		}
		return otp;
	}

	public UserOTP getUserOTP(String userId, String otp, String otpFor) {
		return this.userOTPRepository.findByUserIdAndOtpAndOtpFor(userId, otp, otpFor);

	}

	public void deleteOTPAfterUse(String id) {
		this.userOTPRepository.deleteById(id);
	}
}
