/**
 * 
 */
package com.metcash.cleproxy.azure;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * @author virade@metcash.com
 *
 */
public class Signature {
	public static String getHMAC254(String input, String dateString, String key) throws InvalidKeyException, NoSuchAlgorithmException {
	    String hash;
	    String httpMethod = "POST";
	    String contentType = "application/json";
	    String xmsDate = "x-ms-date:" + dateString;
	    String resource = "/api/logs";
	    String stringToHash = String.join("\n", httpMethod, String.valueOf(input.getBytes(StandardCharsets.UTF_8).length), contentType,
	                xmsDate , resource);
	    Mac sha254HMAC = Mac.getInstance("HmacSHA256");
	    Base64.Decoder decoder = Base64.getDecoder();
	    SecretKeySpec secretKey = new SecretKeySpec(decoder.decode(key.getBytes(StandardCharsets.UTF_8)), "HmacSHA256");
	    sha254HMAC.init(secretKey);
	    Base64.Encoder encoder = Base64.getEncoder();
	    hash = new String(encoder.encode(sha254HMAC.doFinal(stringToHash.getBytes(StandardCharsets.UTF_8))));
	    return hash;
	  }
	
	public static String getBytesJson(String json)
	{
		return String.valueOf(json.getBytes(StandardCharsets.UTF_8).length);
	}
}
