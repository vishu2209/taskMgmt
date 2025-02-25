package com.vishal.taskMgmt.common.services;

import org.springframework.data.jpa.repository.JpaRepository;

import com.vishal.taskMgmt.sharedLib.user.entities.UserOTP;

public interface OtpRepository extends JpaRepository<UserOTP, String>{

	UserOTP findByUserIdAndOtpFor(String id, String otpSentFor);

	UserOTP findByUserIdAndOtpAndOtpFor(String userId, String otp, String otpFor);

}
