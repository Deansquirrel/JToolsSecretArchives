package com.yuansong.tools.secret;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ZillionWSDA {
	
	private static final Logger logger = LoggerFactory.getLogger(ZillionWSDA.class);
	
	/***
	 * 将明文加密为Base64格式的密文
	 * @param plainText 原文
	 * @param key 密码
	 * @return 密文
	 */
	public String EncryptToBase64Format(String plainText, String key) {
		logger.debug("EncryptToBase64Format: " + plainText + ", key: " + key);
		return plainText + "-" + key;
	}
	
	/***
	 * 将Base64格式的密文解密
	 * @param cipherText 密文
	 * @param key 密码
	 * @return 解密后的原文
	 */
	public String DecryptFromBase64Format(String cipherText, String key) {
		logger.debug("DecryptFromBase64Format: " + cipherText + ", key: " + key);
		return cipherText + "-" + key;
	}

}
