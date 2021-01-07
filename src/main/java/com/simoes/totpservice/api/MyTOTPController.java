package com.simoes.totpservice.api;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import org.apache.commons.codec.binary.Base32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@RestController
@RequestMapping("/totp")
public class MyTOTPController {

	private final SecretGenerator secretGenerator;

	private final QrDataFactory qrDataFactory;

	private final QrGenerator qrGenerator;

	private final CodeVerifier verifier;

	private final ApplicationContext context;

	private static final Logger LOG = LoggerFactory.getLogger(MyTOTPController.class);

	public MyTOTPController(SecretGenerator secretGenerator,
		QrDataFactory qrDataFactory, QrGenerator qrGenerator,
		CodeVerifier verifier, ApplicationContext context
	) {
		this.secretGenerator = secretGenerator;
		this.qrDataFactory = qrDataFactory;
		this.qrGenerator = qrGenerator;
		this.verifier = verifier;
		this.context = context;
	}

	@GetMapping("/codes")
	public ResponseEntity<String> generateCode(@RequestParam("secret") String secret) {
		LOG.info("--Generate Code--");
		LOG.info("Secret: {}", secret);

		try {
			final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

			Base32 b32 = new Base32();
			byte[] decodedKey = b32.decode(secret);
			SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "SHA1");

			int code = totp.generateOneTimePassword(originalKey, Instant.now());
			LOG.info("Generated code: {}", String.format("%06d", code));

			return ResponseEntity.ok(String.format("%06d", code));
		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			e.printStackTrace();
		}

		return ResponseEntity.badRequest().body("GENERATE CODE ERROR");
	}

	@GetMapping("/setup")
	public ResponseEntity<TotpDTO> generate(@RequestParam("mail") String mail) throws QrGenerationException {
		LOG.info("--Setup--");

		String secret = secretGenerator.generate();

		QrData data = this.qrDataFactory.newBuilder()
			.label(mail)
			.secret(secret)
			.issuer("Personal")
			.build();

		String qrCodeImage = getDataUriForImage(
			qrGenerator.generate(data),
			qrGenerator.getImageMimeType()
		);

		LOG.info("User: {}", mail);
		LOG.info("Secret: {}", secret);

		return ResponseEntity.ok(TotpDTO
			.builder()
			.secret(secret)
			.qrCode(qrCodeImage)
			.build()
		);
	}

	@GetMapping("/verify")
	public ResponseEntity<String> verify(@RequestParam("code") String code, @RequestParam("secret") String secret) {
		LOG.info("--Validate--");
		LOG.info("Code: {}", code);
		LOG.info("Secret: {}", secret);

		String result = verifier.isValidCode(secret, code) ? "CORRECT" : "INCORRECT";
		return ResponseEntity.ok(result);
	}

}
