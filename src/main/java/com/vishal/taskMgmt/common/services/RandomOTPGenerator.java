package com.vishal.taskMgmt.common.services;

import java.security.SecureRandom;

public class RandomOTPGenerator {

	private static final SecureRandom random = new SecureRandom();

    public static String generateOTP(int otpLength) {
        StringBuilder otp = new StringBuilder(otpLength);
        for (int i = 0; i < otpLength; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }
}
