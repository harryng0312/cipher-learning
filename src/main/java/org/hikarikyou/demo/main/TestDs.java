package org.hikarikyou.demo.main;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Enumeration;

public class TestDs {

    static Logger logger = LoggerFactory.getLogger(TestDs.class);

    KeyStore keyStoreECDSA = null;
    KeyStore keyStoreRSA = null;
    char[] passwd = "123456".toCharArray();

    PrivateKey ecdsaPrivateKey = null;
    Certificate ecdsaCertificate = null;
    PrivateKey rsaPrivateKey = null;
    Certificate rsaCertificate = null;

    protected KeyStore getKeyStoreECDSA() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (keyStoreECDSA == null) {
            Security.addProvider(new BouncyCastleProvider());
            keyStoreECDSA = KeyStore.getInstance("PKCS12", "BC");
            keyStoreECDSA.load(new FileInputStream("key/ks-ecdsa.pfx"), passwd);
        }
        return keyStoreECDSA;
    }

    protected KeyStore getKeyStoreRSA() throws NoSuchProviderException, KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        if (keyStoreRSA == null) {
            Security.addProvider(new BouncyCastleProvider());
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

    protected void signECDSA() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        logger.info("==========");
        String fileToSign = "E:\\downloads\\film\\Bumblebee.2018.ViE.1080p.10bit.BluRay.8CH.x265.HEVC-PSA.mkv";
        String fileSignature = "ds/ecdsa.txt";
        int cap = 1024 * 1024;

        Signature signature = Signature.getInstance("SHA256WithECDSA");
        SecureRandom secureRandom = new SecureRandom();
        signature.initSign(ecdsaPrivateKey, secureRandom);

        RandomAccessFile aFile = new RandomAccessFile(fileToSign, "r");
        FileChannel fileChannel = aFile.getChannel();
        ByteBuffer buffer = ByteBuffer.allocate(cap);
        long startTime = Calendar.getInstance().getTime().getTime();
        while (fileChannel.read(buffer) > 0) {
            buffer.flip();
            signature.update(buffer);
            buffer.clear();
        }
        long endTime = Calendar.getInstance().getTime().getTime();
        fileChannel.close();
        aFile.close();
        byte[] signedData = signature.sign();
        String base64Data = java.util.Base64.getEncoder().encodeToString(signedData);
        Files.write(Paths.get(fileSignature), base64Data.getBytes("utf-8"), StandardOpenOption.CREATE);
        logger.info("ECDSA Signature:" + Base64.toBase64String(signedData) + "\nTime:" + (endTime - startTime));
    }

    protected void signRSA() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        logger.info("==========");
        String fileToSign = "E:\\downloads\\film\\Bumblebee.2018.ViE.1080p.10bit.BluRay.8CH.x265.HEVC-PSA.mkv";
        String fileSignature = "ds/rsa.txt";
        int cap = 1024 * 1024;

        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(rsaPrivateKey);
        RandomAccessFile aFile = new RandomAccessFile(fileToSign, "r");
        FileChannel fileChannel = aFile.getChannel();
        ByteBuffer buffer = ByteBuffer.allocate(cap);
        long startTime = Calendar.getInstance().getTime().getTime();
        while (fileChannel.read(buffer) > 0) {
            buffer.flip();
            signature.update(buffer);
            buffer.clear();
        }
        long endTime = Calendar.getInstance().getTime().getTime();
        fileChannel.close();
        aFile.close();
        byte[] signedData = signature.sign();
        String base64Data = java.util.Base64.getEncoder().encodeToString(signedData);
        Files.write(Paths.get(fileSignature), base64Data.getBytes("utf-8"), StandardOpenOption.CREATE);
        logger.info("RSA Signature:" + Base64.toBase64String(signedData) + "\nTime:" + (endTime - startTime));
    }

    protected void verifyECDSA() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        logger.info("==========");
        String fileToSign = "E:\\downloads\\film\\Bumblebee.2018.ViE.1080p.10bit.BluRay.8CH.x265.HEVC-PSA.mkv";
        String fileSignature = "ds/ecdsa.txt";
        int cap = 1024 * 1024;

        Signature signature = Signature.getInstance("SHA256WithECDSA");
        signature.initVerify(ecdsaCertificate.getPublicKey());

        RandomAccessFile aFile = new RandomAccessFile(fileToSign, "r");
        FileChannel fileChannel = aFile.getChannel();
        ByteBuffer buffer = ByteBuffer.allocate(cap);
        long startTime = Calendar.getInstance().getTime().getTime();
        while (fileChannel.read(buffer) > 0) {
            buffer.flip();
            signature.update(buffer);
            buffer.clear();
        }
        long endTime = Calendar.getInstance().getTime().getTime();
        fileChannel.close();
        aFile.close();
        String signatureData = new String(Files.readAllBytes(Paths.get(fileSignature)), "utf-8");
        byte[] base64Data = java.util.Base64.getDecoder().decode(signatureData);
        boolean result = signature.verify(base64Data);
        logger.info("ECDSA Verify:" + result + "\nTime:" + (endTime - startTime));
    }

    protected void verifyRSA() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        logger.info("==========");
        String fileToSign = "E:\\downloads\\film\\Bumblebee.2018.ViE.1080p.10bit.BluRay.8CH.x265.HEVC-PSA.mkv";
        String fileSignature = "ds/rsa.txt";
        int cap = 1024 * 1024;

        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(rsaCertificate.getPublicKey());

        RandomAccessFile aFile = new RandomAccessFile(fileToSign, "r");
        FileChannel fileChannel = aFile.getChannel();
        ByteBuffer buffer = ByteBuffer.allocate(cap);
        long startTime = Calendar.getInstance().getTime().getTime();
        while (fileChannel.read(buffer) > 0) {
            buffer.flip();
            signature.update(buffer);
            buffer.clear();
        }
        long endTime = Calendar.getInstance().getTime().getTime();
        fileChannel.close();
        aFile.close();
        String signatureData = new String(Files.readAllBytes(Paths.get(fileSignature)), "utf-8");
        byte[] base64Data = java.util.Base64.getDecoder().decode(signatureData);
        boolean result = signature.verify(base64Data);
        logger.info("RSA Verify:" + result + "\nTime:" + (endTime - startTime));
    }

    public static void main(String[] args) throws NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, SignatureException, InvalidKeyException {
        TestDs testDs = new TestDs();
        testDs.init();
        testDs.signECDSA();
        testDs.signRSA();
        testDs.verifyECDSA();
        testDs.verifyRSA();
    }
}
