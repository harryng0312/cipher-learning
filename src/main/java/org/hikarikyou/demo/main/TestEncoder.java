package org.hikarikyou.demo.main;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.cert.CertificateException;

public class TestEncoder {
    static Logger logger = LoggerFactory.getLogger(TestEncoder.class);

    String filePath = "data/testImg.JPG";

    protected void init() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        Provider provider = new BouncyCastleProvider();
        Security.insertProviderAt(provider, 1);
    }

//    protected void encodeImageToBase64() throws IOException {
//        URL url = new URL(doc.getContentUrl());
//        URLConnection uc = url.openConnection();
//        String userpass = "userr:pass;
//        String basicAuth = "Basic " + new String(Base64.getEncoder().encode(userpass.getBytes()));
//        uc.setRequestProperty("Authorization", basicAuth);
//        // cach 1
//        InputStream initialStream = uc.getInputStream();
//
//        byte[] buffer = new byte[1024*100];
//        ByteArrayOutputStream resultOutputStream = new ByteArrayOutputStream(1024*1024); // 1MB
//        int eff = 0;
//        while((eff = initialStream.read(buffer)) > 0){
//            resultOutputStream.write(buffer, 0, eff);
//            resultOutputStream.flush();
//        }
//        // cach 2
//        ReadableByteChannel byteChannel = Channels.newChannel(uc.getInputStream());
//        ByteBuffer byteBuffer = ByteBuffer.allocate(1024 * 100);
//        while(byteChannel.read(byteBuffer) > 0){
//            resultOutputStream.write(byteBuffer.array());
//            byteBuffer.clear();
//        }
//        // finally
//        // close
//        byte[] data = resultOutputStream.toByteArray();
//    }

    public static void main(String[] args) throws CertificateException, UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, IOException, SignatureException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        TestEncoder testEncoder = new TestEncoder();
        testEncoder.init();
        logger.info("==========");
//        testEncoder.encodeImageToBase64();
        logger.info("==========");
    }
}
