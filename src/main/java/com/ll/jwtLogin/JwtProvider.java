package com.ll.jwtLogin;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;

@Component
public class JwtProvider { // 토큰을 생성해주는 클래스
    private SecretKey cachedSecretKey;

    @Value("${custom.jwt.secretKey}")
    private String secretKeyPlain; // 시크릿 키 원문을 가져다 쓴다

    private SecretKey _getSecretKey() { // 시크릿 키를 가져온다
        String keyBase64Encoded = Base64.getEncoder().encodeToString(secretKeyPlain.getBytes());
        return Keys.hmacShaKeyFor(keyBase64Encoded.getBytes());
    }

    public SecretKey getSecretKey() { // 시크릿키를 가져오는 메서드
        if (cachedSecretKey == null) cachedSecretKey = _getSecretKey(); // 시크릿 키가 존재하지 않으면 가지고 있는 시크릿 키를 base64인코딩 후 암호화

        return cachedSecretKey;
    }
}
