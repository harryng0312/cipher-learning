package org.hikarikyou.demo.main;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class TestHashFunc {
    static Logger logger = LoggerFactory.getLogger(TestHashFunc.class);

    String secretKey = "123456";
    String data = "0123456789abcdefghijklmnopqrsxtuvxyz";
    byte[] dataBin = null;
    byte[] iv = null;
    byte[] secretKeyBin = null;

    protected void init() throws UnsupportedEncodingException {
        Provider provider = new BouncyCastleProvider();
        Security.insertProviderAt(provider, 1);

        dataBin = data.getBytes("utf-8");
        secretKeyBin = secretKey.getBytes("utf-8");
    }

    protected void testSha3() throws NoSuchAlgorithmException {
        MessageDigest sha3md = MessageDigest.getInstance("SHA3-256");
        MessageDigest sha2md = MessageDigest.getInstance("SHA-256");
        logger.info("SHA-256 hash:\t" + Hex.toHexString(sha2md.digest(dataBin)));
        logger.info("SHA3-256 hash:\t" + Hex.toHexString(sha3md.digest(dataBin)));
    }

    protected void testHMac() throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchProviderException {
        final int blockSize = 256 / 8;
        iv = new byte[blockSize];
        for (int i = 0; i < blockSize; i++) {
            iv[i] = (byte) 0xaa;
        }
        KeySpec ksHmacSha256 = new SecretKeySpec(secretKeyBin, "HmacSHA256");
        KeySpec ksHmacSha512 = new SecretKeySpec(secretKeyBin, "HmacSHA512");
        SecretKey secretKeyHmacSha256 = (SecretKey) ksHmacSha256;
        SecretKey secretKeyHmacSha512 = (SecretKey) ksHmacSha512;

        Mac hmacSha256 = Mac.getInstance("HmacSHA256");
        Mac hmacSha512 = Mac.getInstance("HmacSHA512");
        hmacSha256.init(secretKeyHmacSha256);
        hmacSha512.init(secretKeyHmacSha512);
        logger.info("HMAC SHA-256 hash:\t" + Hex.toHexString(hmacSha256.doFinal(dataBin)));
        logger.info("HMAC SHA-512 hash:\t" + Hex.toHexString(hmacSha512.doFinal(dataBin)));
    }

    protected void testLengthExtensionAttack() {
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, InvalidKeySpecException, NoSuchProviderException {
        TestHashFunc testHashFunc = new TestHashFunc();
        testHashFunc.init();
        logger.info("==========");
        testHashFunc.testSha3();
        logger.info("==========");
        testHashFunc.testHMac();
        logger.info("==========");
        testHashFunc.testLengthExtensionAttack();
    }
}