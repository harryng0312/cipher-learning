package org.hikarikyou.demo.main;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.Enumeration;

public class TestKeyAgreement2 {

    static Logger logger = LoggerFactory.getLogger(TestKeyAgreement2.class);

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

    protected void testECDH() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
        keyPairGenerator.initialize(ecGenParameterSpec);

        KeyPair kpU = keyPairGenerator.genKeyPair();
        PrivateKey privKeyU = kpU.getPrivate();
        PublicKey pubKeyU = kpU.getPublic();
        logger.info("User U: " + privKeyU.toString());
        logger.info("User U: " + pubKeyU.toString());

        KeyPair kpV = keyPairGenerator.genKeyPair();
        PrivateKey privKeyV = kpV.getPrivate();
        PublicKey pubKeyV = kpV.getPublic();
        logger.info("User V: " + privKeyV.toString());
        logger.info("User V: " + pubKeyV.toString());

        KeyAgreement ecdhU = KeyAgreement.getInstance("ECDH");
        ecdhU.init(privKeyU);
        ecdhU.doPhase(pubKeyV, true);

        KeyAgreement ecdhV = KeyAgreement.getInstance("ECDH");
        ecdhV.init(privKeyV);
        ecdhV.doPhase(pubKeyU, true);

        logger.info("Secret computed by U: 0x" +
                (new BigInteger(1, ecdhU.generateSecret()).toString(16)).toUpperCase());
        logger.info("Secret computed by V: 0x" +
                (new BigInteger(1, ecdhV.generateSecret()).toString(16)).toUpperCase());
    }

    public static void main(String[] args) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, SignatureException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        TestKeyAgreement2 testKeyAgreement = new TestKeyAgreement2();
        testKeyAgreement.init();
        logger.info("==========");
        testKeyAgreement.testECDH();
        logger.info("==========");
        logger.info("==========");
        logger.info("==========");
    }
}
