package org.hikarikyou.demo.main;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class TestCipher {
    static Logger logger = LoggerFactory.getLogger(TestCipher.class);

    SecretKey secretKey = null;
    String keyData = "12345678";
    String plainData = "0123456789abcdefghijklmnopqrsxtuvxyz0123456789abcdefghijklmnopqrsxtuvxyz0123456789abcdefghijklmnopqrsxtuvxyz1234";
    int bitLen = 128;

    byte[] ivData = {};
    byte[] keyBin = {};
    byte[] plainDataBin = {};

    public static class BlockHolder implements Serializable {
        private long left = 0;
        private long right = 0;
        private byte[] ivData = {};
        private byte[] data = {};
        private boolean isFinalBlock = false;

        public BlockHolder(long left, long right, byte[] ivData, byte[] data, boolean isFinalBlock) {
            this.left = left;
            this.right = right;
            this.ivData = ivData;
            this.data = data;
            this.isFinalBlock = isFinalBlock;
        }

        public long getLeft() {
            return left;
        }

        public void setLeft(long left) {
            this.left = left;
        }

        public long getRight() {
            return right;
        }

        public void setRight(long right) {
            this.right = right;
        }

        public byte[] getData() {
            return data;
        }

        public void setData(byte[] data) {
            this.data = data;
        }

        public boolean isFinalBlock() {
            return isFinalBlock;
        }

        public void setFinalBlock(boolean finalBlock) {
            isFinalBlock = finalBlock;
        }

        public byte[] getIvData() {
            return ivData;
        }

        public void setIvData(byte[] ivData) {
            this.ivData = ivData;
        }
    }

    protected void init() throws UnsupportedEncodingException, NoSuchAlgorithmException {
        Provider provider = new BouncyCastleProvider();
        Security.insertProviderAt(provider, 1);
        ivData = new byte[bitLen / 8];
        for (int i = 0; i < ivData.length; i++) {
            ivData[i] = (byte) 0xAA;
        }
        logger.info("IV data:" + Hex.toHexString(ivData));
        initKey();
        initPlainData();
    }

    protected void initKey() throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        keyBin = messageDigest.digest(keyData.getBytes("utf-8"));
        logger.info("Key:" + Hex.toHexString(keyBin));
        logger.info("Key length:" + keyBin.length);
    }

    protected void initPlainData() throws UnsupportedEncodingException {
        plainDataBin = plainData.getBytes("utf-8");
        logger.info("Plain Data:" + plainData);
        logger.info("Plain Data length:" + plainDataBin.length);
    }

    protected byte[] createNewIV(byte[] oldIv, long deltaNumBlock) {
        BigInteger nonce = new BigInteger(1, oldIv);
        final BigInteger MODULUS = BigInteger.ONE.shiftLeft(bitLen);
        byte[] tmp = nonce.add(BigInteger.valueOf(deltaNumBlock)).mod(MODULUS).toByteArray();
        byte[] newIv = new byte[bitLen / 8];
        System.arraycopy(tmp, Math.max(0, tmp.length - newIv.length), newIv, 0, newIv.length);
        return newIv;
    }

    protected byte[] doCipher(Cipher cipher, int cipherMode, byte[] plainDataBin) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(ivData);
        cipher.init(cipherMode, secretKey, algorithmParameterSpec);
        byte[] cipherData = cipher.doFinal(plainDataBin);
        return cipherData;
    }

    protected void testEncryptAESCBC() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        secretKey = new SecretKeySpec(keyBin, "AES");
        byte[] cipherData = doCipher(cipher, Cipher.ENCRYPT_MODE, plainDataBin);
        String cipherString = Hex.toHexString(cipherData);
        logger.info("AES/CBC/PKCS5Padding Encrypted [" + cipherData.length + "]:" + cipherString);
        Files.write(Paths.get("data/enc.dat"), cipherData, StandardOpenOption.TRUNCATE_EXISTING);
    }

    protected void testDecryptAESCBC() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        secretKey = new SecretKeySpec(keyBin, "AES");
        byte[] cryptedData = Files.readAllBytes(Paths.get("data/enc.dat"));
        byte[] plainData = doCipher(cipher, Cipher.DECRYPT_MODE, cryptedData);
        logger.info("AES/CBC/PKCS5Padding Decrypted [" + plainData.length + "]:" + new String(plainData));
        Files.write(Paths.get("data/dec.dat"), plainData, StandardOpenOption.TRUNCATE_EXISTING);
    }

    protected void testEncryptAESCTR() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding", "BC");
        secretKey = new SecretKeySpec(keyBin, "AES");
//        String fileName = "E:\\training\\maven\\demo-console\\data\\dec.dat";
        String fileName = "E:\\OneDrive - VIDEA\\training\\maven\\demo-console.zip";
//        String fileName = "E:\\training\\maven\\demo-console\\data\\dec.dat";
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] plainData = Files.readAllBytes(Paths.get(fileName));
        long start = Calendar.getInstance().getTimeInMillis();
        byte[] cryptedData = doCipher(cipher, Cipher.ENCRYPT_MODE, plainData);
        long end = Calendar.getInstance().getTimeInMillis();
        byte[] hash = messageDigest.digest(cryptedData);
        logger.info("Cipher time:" + (end - start));
        logger.info("AES/CTR/PKCS5Padding Encrypted [" + cryptedData.length + "]:" + Hex.toHexString(hash));
//        Files.write(Paths.get("data/enc.dat"), cryptedData, StandardOpenOption.TRUNCATE_EXISTING);
    }

    protected void testEncryptAESCTRMultipart() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        Cipher cipherFinal = Cipher.getInstance("AES/CTR/PKCS5Padding", "BC");
        long numOfBlockNoPadding = plainDataBin.length / (bitLen / 8);
        int numOfRemainedByte = plainDataBin.length % (bitLen / 8);
        secretKey = new SecretKeySpec(keyBin, "AES");
        // calculate lastest block
        AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(ivData);
        AlgorithmParameterSpec algorithmParameterSpecFinal = new IvParameterSpec(createNewIV(ivData, numOfBlockNoPadding));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
        cipherFinal.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpecFinal);

        byte[] cipherData = null;
        InputStream is = null;
        ByteArrayOutputStream os = null;
        try {
            is = new ByteArrayInputStream(plainDataBin);
            os = new ByteArrayOutputStream();
            byte[] buffer = new byte[bitLen / 8];
            byte[] oBuffer = null;
            int avai = -1;

            for (long i = 1; ((avai = is.read(buffer)) > 0); i++) {
                // read from buffer
                if (avai == (bitLen / 8)) {
                    oBuffer = cipher.update(buffer);
                } else {
                    oBuffer = cipherFinal.doFinal(buffer, 0, avai);
                }
                os.write(oBuffer);
                os.flush();
            }
            if (numOfRemainedByte == 0) {
                buffer = new byte[0];
                oBuffer = cipherFinal.doFinal(buffer);
                os.write(oBuffer);
                os.flush();
            }
            cipherData = os.toByteArray();
        } finally {
            is.close();
            os.close();
        }
        Files.write(Paths.get("data/enc.dat"), cipherData, StandardOpenOption.TRUNCATE_EXISTING);
        String cipherString = Hex.toHexString(cipherData);
        logger.info("AES/CTR/PKCS5Padding Encrypted [" + cipherData.length + "]:" + cipherString);
    }

    protected void testDecryptAESCTR() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding", "BC");
        secretKey = new SecretKeySpec(keyBin, "AES");
        byte[] cryptedData = Files.readAllBytes(Paths.get("data/enc.dat"));
        byte[] plainData = doCipher(cipher, Cipher.DECRYPT_MODE, cryptedData);
        logger.info("AES/CTR/PKCS5Padding Decrypted [" + plainData.length + "]:" + new String(plainData));
        Files.write(Paths.get("data/dec.dat"), plainData, StandardOpenOption.TRUNCATE_EXISTING);
    }

    protected void testEncryptAESCTRBigFile() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        String fileName = "E:\\downloads\\film\\Alpha.2018.ViE.1080p.10bit.BluRay.6CH.x265.HEVC-PSA.mkv";
        String fileNameO = "E:\\downloads\\film\\Alpha.2018.ViE.1080p.10bit.BluRay.6CH.x265.HEVC-PSA.enc";
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        secretKey = new SecretKeySpec(keyBin, "AES");
        AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(ivData);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
        InputStream is = null;
        OutputStream os = null;
        is = new FileInputStream(fileName);
        os = new FileOutputStream(fileNameO);
        OutputStream cipherOs = null;
        cipherOs = new CipherOutputStream(os, cipher);
        byte[] buff = new byte[bitLen / 8];
        int avai = 0;
        long start = Calendar.getInstance().getTime().getTime();
        for (long i = 0; (avai = is.read(buff)) > 0; i++) {
            cipherOs.write(buff, 0, avai);
            if (i % 1000 == 0) {
                cipherOs.flush();
                os.flush();
            }
        }
        cipherOs.flush();
        os.flush();
        is.close();
        cipherOs.close();
        os.close();
        long end = Calendar.getInstance().getTime().getTime();
        byte[] hash = null;
        InputStream inputStream = new FileInputStream(fileNameO);
        int avaicheck = 0;
        byte[] buffCheck = new byte[1024 * 1024];
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1", "BC");
        while ((avaicheck = inputStream.read(buffCheck)) > 0) {
            messageDigest.update(buffCheck, 0, avaicheck);
        }
        inputStream.close();
        hash = messageDigest.digest();
        logger.info("Cipher big file time:" + (end - start) + "\nhash:" + Hex.toHexString(hash));
    }

    protected void testCipherAESCTRBigFileMultiThread(int cipherMode, String src, String dst) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        String inpFileName = src;// "E:\\downloads\\film\\Alpha.2018.ViE.1080p.10bit.BluRay.6CH.x265.HEVC-PSA.mkv";
        String outFileName = dst;//"E:\\downloads\\film\\Alpha.2018.ViE.1080p.10bit.BluRay.6CH.x265.HEVC-PSA.enc";
        secretKey = new SecretKeySpec(keyBin, "AES");
        int numOfThreadInput = 1;
        int numOfThreadProcess = 2;
        int numOfThreadOutput = 1;
        ForkJoinPool forkJoinPool = new ForkJoinPool(numOfThreadInput + numOfThreadProcess + numOfThreadOutput);
        BlockingQueue<BlockHolder> inputQueue = new ArrayBlockingQueue<>(1_000);
        BlockingQueue<BlockHolder> outputQueue = new ArrayBlockingQueue<>(1_000);
        long fileSize = Files.size(Paths.get(inpFileName));
        // batchsize divisible by blocksize
        int numBlockInBatch = 96 * 1024;
        int batchSize = numBlockInBatch * (bitLen / 8);
        long batchSizeRemain = fileSize % batchSize;
        long numBatch = fileSize / batchSize;
        long remainBatchSize = fileSize % batchSize;
        if (remainBatchSize > 0) {
            numBatch++;
        }
        final long finalNumBatch = numBatch;
        if (Files.exists(Paths.get(outFileName))) {
            Files.delete(Paths.get(outFileName));
        }
        AtomicLong countProc = new AtomicLong(0);
        long start = Calendar.getInstance().getTimeInMillis();
        List<Future<String>> lsResultAll = new ArrayList<>();
        List<Future<String>> lsResultInp = IntStream.range(0, numOfThreadInput).mapToObj(e -> forkJoinPool.submit(() -> {
            final String done = "inp";
            InputStream is = null;
            ReadableByteChannel readableByteChannel = null;
            try {
                is = new FileInputStream(inpFileName);
                readableByteChannel = Channels.newChannel(is);
                ByteBuffer buffer = ByteBuffer.allocate(batchSize);
                int avai = 0;
                boolean isFinal = false;
                long current = 0;
                while ((avai = readableByteChannel.read(buffer)) > 0) {
                    byte[] newIv = createNewIV(this.ivData, current / (bitLen / 8));
                    buffer.flip();
                    byte[] data = new byte[buffer.limit()];
                    buffer.get(data);
                    isFinal = ((current + avai == fileSize) || avai == batchSizeRemain);
                    BlockHolder blockHolder = new BlockHolder(current, current + data.length, newIv, data, isFinal);
                    inputQueue.put(blockHolder);
                    buffer.clear();
                    current += avai;
                }
            } catch (Exception ex) {
                logger.info("", ex);
            } finally {
                try {
                    readableByteChannel.close();
                    is.close();
                } catch (IOException ex) {
                    logger.info("", ex);
                }
            }
            return done;
        })).collect(Collectors.toCollection(ArrayList::new));
        List<Future<String>> lsResultProc = IntStream.range(0, numOfThreadProcess).mapToObj(e -> forkJoinPool.submit(() -> {
            final String done = "proc " + e;
//            logger.info("Proc " + e + " is startng...");
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
            Cipher cipherFinal = Cipher.getInstance("AES/CTR/PKCS5Padding", "BC");
            while (true) {
                boolean stop = (countProc.get() >= finalNumBatch);
                if (stop && inputQueue.isEmpty()) {
                    break;
                }
                BlockHolder blockHolder = inputQueue.poll();
                if (blockHolder != null) {
                    countProc.getAndAdd(1);
                    byte[] cipherData = null;
                    AlgorithmParameterSpec algorithmParameterSpec = new IvParameterSpec(blockHolder.getIvData());
                    if (blockHolder.isFinalBlock()) {
                        cipherFinal.init(cipherMode, secretKey, algorithmParameterSpec);
                        cipherData = cipherFinal.doFinal(blockHolder.getData());
                    } else {
                        cipher.init(cipherMode, secretKey, algorithmParameterSpec);
                        cipherData = cipher.update(blockHolder.getData());
                    }
                    if (cipherData != null) {
                        blockHolder.setData(cipherData);
                        blockHolder.setRight(blockHolder.getLeft() + cipherData.length);
                        outputQueue.put(blockHolder);
                    }
                }
            }
            return done;
        })).collect(Collectors.toCollection(ArrayList::new));
        List<Future<String>> lsResultOut = IntStream.range(0, numOfThreadOutput).mapToObj(e -> forkJoinPool.submit(() -> {
            final String done = "out";
            RandomAccessFile randomAccessFile = new RandomAccessFile(outFileName, "rw");
            long count = 0;
            while (true) {
                boolean stop = (count == finalNumBatch);
                if (stop && outputQueue.isEmpty()) {
                    break;
                }
                BlockHolder blockHolder = outputQueue.poll();
                if (blockHolder != null) {
//                    logger.info("out " + blockHolder.getLeft() + "-" + blockHolder.getRight());
                    count++;
                    randomAccessFile.seek(blockHolder.getLeft());
                    randomAccessFile.write(blockHolder.getData());
                }
            }
            randomAccessFile.close();
            return done;
        })).collect(Collectors.toCollection(ArrayList::new));
        lsResultAll.addAll(lsResultInp);
        lsResultAll.addAll(lsResultProc);
        lsResultAll.addAll(lsResultOut);
//        logger.info("Waiting...");
        lsResultAll.stream().forEach(e -> {
            try {
//                logger.info("Done: " + e.get());
                e.get();
            } catch (Exception ex) {
                logger.error("", ex);
            }
        });
        long end = Calendar.getInstance().getTimeInMillis();
        forkJoinPool.shutdown();
        byte[] hash = null;
        InputStream inputStream = new FileInputStream(outFileName);
        int avaicheck = 0;
        byte[] buffCheck = new byte[1024 * 1024];
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1", "BC");
        while ((avaicheck = inputStream.read(buffCheck)) > 0) {
            messageDigest.update(buffCheck, 0, avaicheck);
        }
        inputStream.close();
        hash = messageDigest.digest();
        logger.info("Cipher parallel[" + numOfThreadProcess + "] time:" + (end - start) + "\nhash:" + Hex.toHexString(hash));
    }

    public static void main(String[] args) throws Exception {
        TestCipher testCipher = new TestCipher();
        testCipher.init();
//        logger.info("==========");
//        testCipher.testEncryptAESCBC();
//        logger.info("==========");
//        testCipher.testDecryptAESCBC();
//        logger.info("==========");
//        testCipher.testEncryptAESCTR();
//        logger.info("==========");
//        testCipher.testEncryptAESCTRMultipart();
//        testCipher.testDecryptAESCTR();
        logger.info("==========");
//        testCipher.testEncryptAESCTRBigFile();
//        testCipher.testEncryptAESCTR();
        String org = "E:\\downloads\\film\\Alpha.2018.ViE.1080p.10bit.BluRay.6CH.x265.HEVC-PSA.mkv";
        String enc = "E:\\downloads\\film\\Alpha.2018.ViE.1080p.10bit.BluRay.6CH.x265.HEVC-PSA.mkv.enc";
        String dec = "E:\\downloads\\film\\Alpha.2018.ViE.1080p.10bit.BluRay.6CH.x265.HEVC-PSA.dec.mkv";
//        String org = "E:\\OneDrive - VIDEA\\training\\maven\\demo-console.zip";
//        String enc = "E:\\OneDrive - VIDEA\\training\\maven\\demo-console.zip.enc";
//        String org = "E:\\training\\maven\\demo-console\\data\\dec.dat";
//        String enc = "E:\\training\\maven\\demo-console\\data\\enc.dat";
        testCipher.testCipherAESCTRBigFileMultiThread(Cipher.ENCRYPT_MODE, org, enc);
        testCipher.testCipherAESCTRBigFileMultiThread(Cipher.DECRYPT_MODE, enc, dec);
    }
}
