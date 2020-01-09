package com.yuansong.tools.secret;

import java.util.Arrays;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yuansong.tools.common.CommonTool;
import com.yuansong.tools.common.MathTool;

public class ZillionWSDA {
	
private static final Logger logger = LoggerFactory.getLogger(ZillionWSDA.class);
	
	private final Base64.Encoder encoder = Base64.getEncoder();
	private final Base64.Decoder decoder = Base64.getDecoder();
	
	/***
	 * 将明文加密为Base64格式的密文
	 * @param plainText 原文
	 * @param key 密码
	 * @return 密文
	 */
	public String EncryptToBase64Format(String plainText, String key) throws Exception{
		logger.debug("plainText: " + plainText + ", key: " + key);
		
		if(plainText == null || key == null) {
			throw new Exception("原文或密码不可为空");
		}
		if(plainText.length() < 1 || key.length() < 1) {
			throw new Exception("原文或密码不可为空");
		}
		
		byte[] sPlain =(key + plainText).getBytes("GBK"); 
		
		CommonTool ct = new CommonTool();
		MathTool mt = new MathTool();
		
		String sMd5 = ct.Md5Encode(sPlain);
		
		byte[] hexMd5 = this.hexStr2Bytes(sMd5) ;	
		
		byte[] resultByte = this.byteMerger(hexMd5,sPlain);
		byte[] keyByte = key.getBytes();
		
		for(int i=0;i<resultByte.length;i++) {
			resultByte[i] = this.getXor(resultByte[i], keyByte[i % keyByte.length]);
		}
		
		byte[] rndKey = new byte[4];
		for(int i = 0; i < rndKey.length; i++) {
			rndKey[i] = (byte)(mt.RandInt(0, 64) & 0xFF);
		}
		
		for(int i = 0; i < resultByte.length; i++) {
			resultByte[i] = (byte) (resultByte[i] ^ (rndKey[i%rndKey.length]));
		}

		resultByte = this.byteMerger(rndKey, resultByte);
		logger.debug(this.encoder.encodeToString(resultByte));
		return this.encoder.encodeToString(resultByte);
	}
	
	/***
	 * 将Base64格式的密文解密
	 * @param cipherText 密文
	 * @param key 密码
	 * @return 解密后的原文
	 */
	public String DecryptFromBase64Format(String cipherText, String key) throws Exception {
		
		logger.debug("cipherText: " + cipherText + ", key: " + key);
		byte[] byteCipherText = this.decoder.decode(cipherText);
		
		byte[] resultByte = new byte[byteCipherText.length - 4];
		System.arraycopy(byteCipherText, 4, resultByte, 0, resultByte.length);		
		byte[] rndKey = new byte[4];
		System.arraycopy(byteCipherText, 0, rndKey, 0, 4);
		
		for(int i = 0; i < resultByte.length; i++) {
			resultByte[i] = this.getXor(resultByte[i], rndKey[i % rndKey.length]);
		}
		
		byte[] keyByte = key.getBytes("UTF-8");
		for(int i = 0; i < resultByte.length; i++) {
			resultByte[i] = this.getXor(resultByte[i], keyByte[i % keyByte.length]);
		}
		
		byte[] checkKeyByte = new byte[keyByte.length];
		System.arraycopy(resultByte, 16, checkKeyByte, 0, checkKeyByte.length);
		
		if(!Arrays.equals(checkKeyByte, keyByte)) {
			throw new Exception("解密失败。（密码非法）");
		}
		
		byte[] sMd5Check = new byte[16];
		System.arraycopy(resultByte, 0, sMd5Check, 0, sMd5Check.length);
		byte[] plainByte = new byte[resultByte.length - (16 + keyByte.length)];
		System.arraycopy(resultByte, 16 + keyByte.length, plainByte, 0, plainByte.length);
		
		CommonTool ct = new CommonTool();
		byte[] byteTemp = this.byteMerger(keyByte, plainByte);
		
		byte[] sMd5 = this.hexStr2Bytes(ct.Md5Encode(byteTemp)) ;
		
		if(!Arrays.equals(sMd5Check, sMd5)) {
			throw new Exception("解密失败。（校验错误）");
		}
		
		logger.debug(new String(plainByte, "GBK"));
		return new String(plainByte, "GBK");
	}
	
	/**
	 * 字节数组合并
	 * @param bt1
	 * @param bt2
	 * @return
	 */
	private byte[] byteMerger(byte[] bt1, byte[] bt2) {
		byte[] btResult = new byte[bt1.length + bt2.length];
		System.arraycopy(bt1, 0, btResult, 0, bt1.length);
		System.arraycopy(bt2, 0, btResult, bt1.length, bt2.length);
		return btResult;
	}
	
	/**
	 * 16进制字符串转字节数组
	 * @param s
	 * @return
	 */
	private byte[] hexStr2Bytes(String s) {
        int l = s.length() / 2;        
        byte[] ret = new byte[l];
        for (int i = 0; i < l; i++) {
        	ret[i] = (byte)Integer.parseInt(s.substring(i * 2, (i + 1) * 2), 16);
        }
        return ret;
	}
	
	/**
	 * 字节求异或
	 * @param a
	 * @param b
	 * @return
	 */
	private byte getXor(byte a, byte b) {
		return (byte)(Integer.valueOf(a) ^ Integer.valueOf(b));
	}

}
