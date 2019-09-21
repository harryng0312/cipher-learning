package org.hikarikyou.demo.main;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Calendar;
import java.util.Enumeration;

public class TestHashFunc {

    static Logger logger = LoggerFactory.getLogger(TestHashFunc.class);

    KeyStore keyStoreECDSA = null;
    KeyStore keyStoreRSA = null;
    char[] passwd = "123456".toCharArray();

    PrivateKey ecdsaPrivateKey = null;
    Certificate ecdsaCertificate = null;
    PrivateKey rsaPrivateKey = null;
    Certificate rsaCertificate = null;

    static final String sampleData = "1234567890";

    protected KeyStore getKeyStoreECDSA() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (keyStoreECDSA == null) {
            Provider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
//            Security.insertProviderAt(provider, 1);
            keyStoreECDSA = KeyStore.getInstance("PKCS12", "BC");
            keyStoreECDSA.load(new FileInputStream("key/ks.pfx"), passwd);
        }
        return keyStoreECDSA;
    }

    protected KeyStore getKeyStoreRSA() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (keyStoreRSA == null) {
            Provider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
//            Security.insertProviderAt(provider, 1);
            keyStoreRSA = KeyStore.getInstance("PKCS12", "BC");
            keyStoreRSA.load(new FileInputStream("key/ks-rsa.pfx"), passwd);
        }
        return keyStoreRSA;
    }

    protected void init() throws NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        KeyStore ks = getKeyStoreECDSA();
        Enumeration<String> alias = ks.aliases();
        while (alias.hasMoreElements()) {
            String ali = alias.nextElement();
            ecdsaPrivateKey = (PrivateKey) getKeyStoreECDSA().getKey(ali, passwd);
            ecdsaCertificate = getKeyStoreECDSA().getCertificate(ali);
        }
        ks = getKeyStoreRSA();
        alias = ks.aliases();
        while (alias.hasMoreElements()) {
            String ali = alias.nextElement();
            rsaPrivateKey = (PrivateKey) getKeyStoreRSA().getKey(ali, passwd);
            rsaCertificate = getKeyStoreRSA().getCertificate(ali);
        }
    }

    protected byte[] getSha256(byte[] data) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
        messageDigest.update(data);
        byte[] digest = messageDigest.digest();
        return digest;
    }

    protected void signRsa() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] outputDigest = getSha256(sampleData.getBytes("utf-8"));
        AlgorithmIdentifier sha256Aid = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE);
        DigestInfo di = new DigestInfo(sha256Aid, outputDigest);
        //sing by cipher
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, rsaPrivateKey);
        byte[] encodedDigestInfo = di.toASN1Primitive().getEncoded();
        cipher.update(encodedDigestInfo);
        byte[] signed0 = cipher.doFinal();

        //sign SHA256 with RSA
        Signature rsaSignature = Signature.getInstance("NoneWithRSA", "BC");
        rsaSignature.initSign(rsaPrivateKey);
        encodedDigestInfo = di.toASN1Primitive().getEncoded();
        rsaSignature.update(encodedDigestInfo);
        byte[] signed = rsaSignature.sign();
        //compute SHA256withRSA as a single step
        Signature rsaSha256Signature = Signature.getInstance("SHA256withRSA", "BC");
        rsaSha256Signature.initSign(rsaPrivateKey);
        rsaSha256Signature.update(sampleData.getBytes());
        byte[] signed2 = rsaSha256Signature.sign();

        logger.info("RSA Cipher:\t\t\t\t" + Base64.getEncoder().encodeToString(signed0));
        logger.info("RSA Signature:\t\t\t\t" + Base64.getEncoder().encodeToString(signed));
        logger.info("SHA256WithRSA Signature:\t" + Base64.getEncoder().encodeToString(signed2));
    }

    protected void signSha256WithRsa() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(rsaPrivateKey);
        byte[] dataToSign = sampleData.getBytes("utf-8");
        long startTime = Calendar.getInstance().getTime().getTime();
        signature.update(dataToSign);
        byte[] signedData = signature.sign();
        long endTime = Calendar.getInstance().getTime().getTime();
        logger.info("SHA256WithRSA Signature:" + Base64.getEncoder().encodeToString(signedData) + "\nTime:" + (endTime - startTime));
    }

    public static void main(String[] args) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, SignatureException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        TestHashFunc testHashFunc = new TestHashFunc();
        testHashFunc.init();
        logger.info("==========");
        testHashFunc.signSha256WithRsa();
        logger.info("==========");
        testHashFunc.signRsa();
    }
}
