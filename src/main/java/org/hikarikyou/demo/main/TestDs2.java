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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.Enumeration;

public class TestDs2 {

    static Logger logger = LoggerFactory.getLogger(TestDs2.class);

    KeyStore keyStoreECDSA = null;
    KeyStore keyStoreRSA = null;
    KeyStore keyStoreRSAPSS = null;
    char[] passwd = "123456".toCharArray();

    PrivateKey ecdsaPrivateKey = null;
    Certificate ecdsaCertificate = null;
    PrivateKey rsaPrivateKey = null;
    Certificate rsaCertificate = null;
    PrivateKey rsaPssPrivateKey = null;
    Certificate rsaPssCertificate = null;

    static final String sampleData = "1234567890";

    protected KeyStore getKeyStoreECDSA() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (keyStoreECDSA == null) {
            Provider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
//            Security.insertProviderAt(provider, 1);
            keyStoreECDSA = KeyStore.getInstance("PKCS12", "BC");
            keyStoreECDSA.load(new FileInputStream("key/ks-ecdsa.pfx"), passwd);
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

    protected KeyStore getKeyStoreRSAPSS() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (keyStoreRSAPSS == null) {
            Provider provider = new BouncyCastleProvider();
            Security.addProvider(provider);
//            Security.insertProviderAt(provider, 1);
            keyStoreRSAPSS = KeyStore.getInstance("PKCS12", "BC");
            keyStoreRSAPSS.load(new FileInputStream("key/ks-rsa-pss.pfx"), passwd);
        }
        return keyStoreRSAPSS;
    }

    protected void init() throws NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        Enumeration<String> alias = null;
        KeyStore ks = null;
        ks = getKeyStoreECDSA();
        alias = ks.aliases();
        while (alias.hasMoreElements()) {
            String ali = alias.nextElement();
            ecdsaPrivateKey = (PrivateKey) getKeyStoreECDSA().getKey(ali, passwd);
            ecdsaCertificate = getKeyStoreECDSA().getCertificate(ali);
        }
        ks = getKeyStoreRSAPSS();
        alias = ks.aliases();
        while (alias.hasMoreElements()) {
            String ali = alias.nextElement();
            rsaPssPrivateKey = (PrivateKey) getKeyStoreRSAPSS().getKey(ali, passwd);
            rsaPssCertificate = getKeyStoreRSAPSS().getCertificate(ali);
        }
        ks = getKeyStoreRSA();
        alias = ks.aliases();
        while (alias.hasMoreElements()) {
            String ali = alias.nextElement();
            rsaPrivateKey = (PrivateKey) getKeyStoreRSA().getKey(ali, passwd);
            rsaCertificate = getKeyStoreRSA().getCertificate(ali);
        }
    }

    protected byte[] getSha256(byte[] data) throws NoSuchAlgorithmException {
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

        logger.info("RSA Cipher:\t\t\t\t\t" + Base64.getEncoder().encodeToString(signed0));
        logger.info("RSA Signature:\t\t\t\t" + Base64.getEncoder().encodeToString(signed));
        logger.info("SHA256WithRSA Signature:\t" + Base64.getEncoder().encodeToString(signed2));
    }

    protected void signVerifySha256WithRsa() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(rsaPrivateKey);
        byte[] dataToSign = sampleData.getBytes("utf-8");
        signature.update(dataToSign);
        byte[] signedData = signature.sign();
        signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(rsaCertificate);
        signature.update(dataToSign);
        boolean verifyResult = signature.verify(signedData);

        logger.info("SHA256WithRSA Len:\t\t\t" + signedData.length);
        logger.info("SHA256WithRSA Signature:\t" + Base64.getEncoder().encodeToString(signedData));
        logger.info("SHA256WithRSA Verify:\t\t" + verifyResult);
    }

    protected void signVerifyRsaPss() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, UnsupportedEncodingException, SignatureException {
        final String alg = "RSASSA-PSS";// "SHA256WithRSA/PSS";
        final MGF1ParameterSpec mgf1ParameterSpec = MGF1ParameterSpec.SHA256;
        final String mgfName = "MGF1";
        final int saltLen = 32;
        final int trailerField = 1;
        Signature signature = null;
        PSSParameterSpec pssParameterSpec = null;

        signature = Signature.getInstance(alg);
        pssParameterSpec = new PSSParameterSpec(mgf1ParameterSpec.getDigestAlgorithm(), mgfName, mgf1ParameterSpec, saltLen, trailerField);
        signature.setParameter(pssParameterSpec);
        signature.initSign(rsaPssPrivateKey);
        byte[] dataToSign = sampleData.getBytes("utf-8");
        signature.update(dataToSign);
        byte[] signedData = signature.sign();

        signature = Signature.getInstance(alg);
        pssParameterSpec = new PSSParameterSpec(mgf1ParameterSpec.getDigestAlgorithm(), mgfName, mgf1ParameterSpec, saltLen, trailerField);
        signature.setParameter(pssParameterSpec);
        signature.initVerify(rsaPssCertificate);
        signature.update(dataToSign);
        boolean verifyResult = signature.verify(signedData);

        logger.info("SHA256WithRSA/PSS Len:\t\t" + signedData.length);
        logger.info("SHA256WithRSA/PSS Signature:" + Base64.getEncoder().encodeToString(signedData));
        logger.info("SHA256WithRSA/PSS Verify:\t" + verifyResult);
    }

    public static void main(String[] args) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, SignatureException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        TestDs2 testDs2 = new TestDs2();
        testDs2.init();
//        logger.info("==========");
//        testDs2.signRsa();
        logger.info("==========");
        testDs2.signVerifySha256WithRsa();
        logger.info("==========");
        testDs2.signVerifyRsaPss();
        logger.info("==========");
    }
}
