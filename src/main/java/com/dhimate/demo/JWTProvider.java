package com.dhimate.demo;

import io.jsonwebtoken.Jwts;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Enumeration;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class JWTProvider {
	private static final String PRIVATE_KEY_FILE_RSA = "Anypoint_Keystore.p12";
	private static final String PRIVATE_KEY_PASSWORD = "";
	private static final String EPIC_CLIENT_ID = "093ac323-dbb1-410f-b015-b3ea18304467";
	private static final String EPIC_FHIR_URL = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token";

	private static final Logger logger = LogManager.getLogger("JWTProvider");

	public static void main(String args[]) {

		try {
			System.out.println(getToken(PRIVATE_KEY_FILE_RSA, PRIVATE_KEY_PASSWORD, EPIC_CLIENT_ID, EPIC_FHIR_URL));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static String getToken(String PRIVATE_KEY_FILE_RSA, String PRIVATE_KEY_PASSWORD, String EPIC_CLIENT_ID,
			String EPIC_FHIR_URL) throws Exception {

		logger.info("Generating JWS token");

		String jws = Jwts.builder().setHeaderParam("alg", "RS384").setHeaderParam("typ", "JWT")
				.setIssuer(EPIC_CLIENT_ID).setSubject(EPIC_CLIENT_ID).setAudience(EPIC_FHIR_URL)
				.setId(UUID.randomUUID().toString())
				.setExpiration(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(5)))
				.signWith(getKey(PRIVATE_KEY_FILE_RSA, PRIVATE_KEY_PASSWORD)).compact();

		return (jws);
	}

	private static PrivateKey getKey(String PRIVATE_KEY_FILE_RSA, String PRIVATE_KEY_PASSWORD) throws Exception {

		KeyStore keystore = KeyStore.getInstance("PKCS12");
		URL resource = JWTProvider.class.getClassLoader().getResource(PRIVATE_KEY_FILE_RSA);
		FileInputStream is = new FileInputStream(new File(resource.toURI()));

		keystore.load(is, PRIVATE_KEY_PASSWORD.toCharArray());
		Enumeration<String> aliases = keystore.aliases();
		String keyAlias = "";

		while (aliases.hasMoreElements()) {
			keyAlias = (String) aliases.nextElement();
		}

		PrivateKey key = (PrivateKey) keystore.getKey(keyAlias, PRIVATE_KEY_PASSWORD.toCharArray());
		return (key);
	}
}