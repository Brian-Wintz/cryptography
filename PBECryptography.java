package com.bkw.crypto;

import javax.crypto.*;
import javax.crypto.spec.*;

public class PBECryptography {

    private static SecretKey pbeKey = null;
    private static Cipher pbeCipher = null; 
    private static PBEParameterSpec pbeParamSpec = null;

	public static void main(String[] args) {
		byte[] encryptedValue = encrypt("Testing");
		for(int i=0; i<encryptedValue.length; ++i)
		{
			System.out.println(i+":"+(char)encryptedValue[i]+":"+(int)encryptedValue[i]);
		}
		byte[] decryptedValue = decrypt(encryptedValue);
		for(int i=0; i<decryptedValue.length; ++i)
		{
			System.out.println(i+":"+(char)decryptedValue[i]);
		}
	}
	
	public static void init()
	{
	    char[] encryptPassword = "DKS@#34".toCharArray();
	    byte[] salt = {
		        (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
		        (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
		    };
	    int count = 20;
	    
	    if(pbeCipher == null) {
		    pbeParamSpec = new PBEParameterSpec(salt, count);
		    PBEKeySpec pbeKeySpec = new PBEKeySpec(encryptPassword);
		    try {
		    	SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
			    pbeKey = keyFac.generateSecret(pbeKeySpec);
		
			    // Create PBE Cipher
			    pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
		    } catch(Exception e) {
		    	e.printStackTrace();
		    }
	    }

	}
	
	public static byte[] encrypt(String data)
	{
		init();
	    byte[] result = null;

	    // Create PBE parameter set

	    try {
		    // Initialize PBE Cipher with key and parameters
		    pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);
	
		    // Encrypt the cleartext
		    result = pbeCipher.doFinal(data.getBytes());
	    } catch(Exception e)
	    {
	    	e.printStackTrace();
	    }
		return result;
	}

	public static byte[] decrypt(byte[] data)
	{
		init();
	    byte[] result = null;

	    // Create PBE parameter set

	    try {
		    // Initialize PBE Cipher with key and parameters
		    pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
	
		    // Encrypt the clear text
		    result = pbeCipher.doFinal(data);
	    } catch(Exception e)
	    {
	    	e.printStackTrace();
	    }
		return result;
	}

}
