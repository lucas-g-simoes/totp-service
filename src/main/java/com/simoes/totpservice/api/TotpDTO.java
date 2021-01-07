package com.simoes.totpservice.api;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TotpDTO {

	private final String secret;

	private final String qrCode;

}
