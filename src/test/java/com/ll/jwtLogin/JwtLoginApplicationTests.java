package com.ll.jwtLogin;

import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JwtLoginApplicationTests {
	@Value("${custom.jwt.secretKey}")
	private String secretKeyPlain; // 원래 시크릿키 원문

	@Test
	@DisplayName("secretKey 키가 존재해야한다.")
	void t1() {
		assertThat(secretKeyPlain).isNotNull();
	}

	@Test
	@DisplayName("sercretKey 원문으로 hmac 암호화 알고리즘에 맞는 SecretKey 객체를 만들 수 있다.")
	void t2() {
		// 키를 Base64 인코딩 한다.
		String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKeyPlain.getBytes()); // 원문을 Base64로 인코딩
		// Base64 인코딩된 키를 이용하여 SecretKey 객체를 만든다.
		SecretKey secretKey = Keys.hmacShaKeyFor(keyBase64Encoded.getBytes()); // 인코딩 한 결과를 암호화

		assertThat(secretKey).isNotNull();
	}

}
