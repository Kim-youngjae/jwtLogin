package com.ll.jwtLogin;

import com.ll.jwtLogin.util.Ut;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JwtLoginApplicationTests {
	@Autowired
	private JwtProvider jwtProvider;

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

	@Test
	@DisplayName("JwtProvider 객체로 SecretKey 객체를 생성할 수 있다.")
	void t3() {
		SecretKey secretKey = jwtProvider.getSecretKey();

		System.out.println("secretKey = " + secretKey);

		assertThat(secretKey).isNotNull();
	}

	@Test
	@DisplayName("SecretKey 객체는 단 한번만 생성되어야 한다.") //
	void t4() {
		SecretKey secretKey1 = jwtProvider.getSecretKey();
		SecretKey secretKey2 = jwtProvider.getSecretKey();

		assertThat(secretKey1 == secretKey2).isTrue();
	}

	@Test
	@DisplayName("toStr()의 ObjectMapper().writeValueAsString(map)를 통해 json 형태의 문자열로 반환 받음")
	void t5() {
		Map<String, Object> claims = new HashMap<>();
		claims.put("id", 1L);
		claims.put("username", "admin");

		String json = (String) Ut.json.toStr(claims);
		System.out.println(json);
	}

	@Test
	@DisplayName("accessToken 을 얻는다.")
	void t6() {
		Map<String, Object> claims = new HashMap<>();
		claims.put("id", 1L);
		claims.put("username", "admin");

		// 지금으로부터 5시간의 유효기간을 가지는 토큰을 생성
		String accessToken = jwtProvider.genToken(claims, 60 * 60 * 5);

		System.out.println("accessToken : " + accessToken);

		assertThat(accessToken).isNotNull();
	}

	@Test
	@DisplayName("accessToken 을 통해서 claims 를 얻을 수 있다.")
	void t7() {
		Map<String, Object> claims = new HashMap<>();
		claims.put("id", 1L);
		claims.put("username", "admin");

		// 지금으로부터 5시간의 유효기간을 가지는 토큰을 생성
		String accessToken = jwtProvider.genToken(claims, 60 * 60 * 5);

		System.out.println("accessToken : " + accessToken);

		assertThat(jwtProvider.verify(accessToken)).isTrue();

		Map<String, Object> claimsFromToken = jwtProvider.getClaims(accessToken);
		System.out.println("claimsFromToken : " + claimsFromToken);
	}

	@Test
	@DisplayName("만료된 토큰을 유효하지 않다.")
	void t8() {
		Map<String, Object> claims = new HashMap<>();
		claims.put("id", 1L);
		claims.put("username", "admin");

		// 지금으로부터 5시간의 유효기간을 가지는 토큰을 생성
		String accessToken = jwtProvider.genToken(claims, -1);

		System.out.println("accessToken : " + accessToken);

		assertThat(jwtProvider.verify(accessToken)).isFalse();
	}
}
