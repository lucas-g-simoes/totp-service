package com.simoes.totpservice;

import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrDataFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@Configuration
public class TotpConfiguration {

	@Bean
	public QrDataFactory qrDataFactory() {
		return new QrDataFactory(HashingAlgorithm.SHA1, 6, 120);
	}

}
