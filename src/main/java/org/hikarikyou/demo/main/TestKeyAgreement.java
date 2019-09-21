package org.hikarikyou.demo.main;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class TestKeyAgreement {
    static Logger logger = LoggerFactory.getLogger(TestKeyAgreement.class);

    // ECC - for 02 parties only
//    private static String KEYGEN_ALGORITHM = "EC";
//    private static String KEYAGREEMENT_ALGORITHM = "ECDH";
//    private static int KEY_LENGTH = 224;
    // DH - for 02 parties or upper
    private static String KEYGEN_ALGORITHM = "DH";
    private static String KEYAGREEMENT_ALGORITHM = "DH";
    private static int KEY_LENGTH = 2048;

    private static String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static String HMAC_ALGORITHM = "MD5";

    private Map<String, KeyHolder> mapParties = new HashMap<>();
    private Map<SortedSet<String>, byte[]> mapComposedPublicKey = new TreeMap<>((e1, e2) -> {
        final int i = TestKeyAgreement.compareSetKey(e1, e2);
        return i;
    });
    private BigInteger p = BigInteger.ONE;
    private BigInteger g = BigInteger.ONE;

    public static class KeyHolder {
        SortedSet<String> id = new TreeSet<>();
        KeyPair keyPair = null;
        // can NOT shared
        Map<SortedSet<String>, byte[]> mapOtherSecretKey = new TreeMap<>(TestKeyAgreement::compareSetKey);
    }

    static int compareSetKey(SortedSet<String> e1, SortedSet<String> e2) {
        int rs = -1;
        if (e1 != null && e2 != null) {
            rs = e1.size() - e2.size();
            if (rs == 0) {
                StringBuilder stringBuilder1 = new StringBuilder();
                StringBuilder stringBuilder2 = new StringBuilder();
                e1.forEach(e -> stringBuilder1.append(e).append("."));
                e2.forEach(e -> stringBuilder2.append(e).append("."));
                rs = stringBuilder1.toString().compareTo(stringBuilder2.toString());
            }
        }
        return rs;
    }

    protected void init() {
        Provider provider = new BouncyCastleProvider();
        Security.insertProviderAt(provider, 1);

        SecureRandom secureRandom = new SecureRandom();
        p = BigInteger.probablePrime(KEY_LENGTH, secureRandom);
        g = BigInteger.probablePrime(KEY_LENGTH, secureRandom);
    }

    protected byte[] createSecretKeyFromHMAC(String hmac, byte[] data) throws NoSuchProviderException, NoSuchAlgorithmException {
        byte[] result = {};
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", "BC");
        messageDigest.update(data);
        result = messageDigest.digest();
        return result;
    }

    protected PublicKey getPublicKeyFromByteArray(byte[] dataBin) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance(KEYGEN_ALGORITHM, "BC");
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(dataBin);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        return publicKey;
    }

    protected List<byte[]> createKeysForBlockCipher(byte[] data) {
        List<byte[]> rs = new ArrayList<>(2);
        byte[] ivBytes = {};
        byte[] secretKeyBinBytes = {};
        if (!CIPHER_ALGORITHM.contains("/ECB")) {
            ivBytes = Arrays.copyOfRange(data, 0, data.length / 2);
            secretKeyBinBytes = Arrays.copyOfRange(data, data.length / 2, data.length);
        } else {
            secretKeyBinBytes = data;
        }
        rs.add(ivBytes);
        rs.add(secretKeyBinBytes);
        return rs;
    }

    protected void createKeyPair(String partyId) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEYGEN_ALGORITHM, "BC");
        AlgorithmParameterSpec algorithmParameterSpec = new DHParameterSpec(p, g);
        keyPairGenerator.initialize(algorithmParameterSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        byte[] pubKey = keyPair.getPublic().getEncoded();
        logger.info("[" + partyId + "] public key [" + pubKey.length + "]:" + Hex.toHexString(pubKey));

        KeyHolder keyHolder = new KeyHolder();
        keyHolder.id.add(partyId);
        keyHolder.keyPair = keyPair;
        mapParties.put(partyId, keyHolder);
    }

    protected void publishPublicKey(String partyId) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException {
        KeyHolder keyHolder = mapParties.get(partyId);
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEYAGREEMENT_ALGORITHM, "BC");
        keyAgreement.init(keyHolder.keyPair.getPrivate());
        SortedSet<String> id = new TreeSet<>();
        id.add(partyId);
        mapComposedPublicKey.put(id, keyHolder.keyPair.getPublic().getEncoded());
    }

    protected byte[] joinGroup(String partyId, byte[] publicKeyBin, String... otherIds) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException {
        byte[] rs = null;
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEYAGREEMENT_ALGORITHM, "BC");
        if (otherIds != null && otherIds.length > 0) {
            StringBuilder stringBuilder = new StringBuilder();
            Stream.of(otherIds).filter(otherId -> !partyId.equals(otherId)).forEach(otherId -> {
                stringBuilder.append(otherId).append(",");
            });
//            SortedSet<String> groupKey = Stream.of(otherIds).filter(e -> !e.equals(partyId)).collect(Collectors.toCollection(TreeSet::new));
            KeyHolder keyHolder = mapParties.get(partyId);
            byte[] composedKeyBin = null;
            composedKeyBin = publicKeyBin; //mapComposedPublicKey.get(groupKey);
            if (composedKeyBin != null) {
                PublicKey publicKey = getPublicKeyFromByteArray(composedKeyBin);
                // private work
                PrivateKey privateKey = keyHolder.keyPair.getPrivate();
                keyAgreement.init(privateKey);
                Key joinedComposedKey = keyAgreement.doPhase(publicKey, false);
                rs = joinedComposedKey.getEncoded();
            } else {
            }
        }
        return rs;
    }

    protected byte[] sendMsg(String partyId, String message, String... otherIds) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        KeyHolder keyHolder = mapParties.get(partyId);
        SortedSet<String> setIds = Stream.of(otherIds).collect(Collectors.toCollection(TreeSet::new));
        byte[] secretKeyBin = keyHolder.mapOtherSecretKey.get(setIds);
        if (secretKeyBin == null) {
            byte[] publicKeyBin = mapComposedPublicKey.get(setIds);
            if (publicKeyBin != null) {
                PublicKey publicKey = getPublicKeyFromByteArray(publicKeyBin);
                KeyAgreement keyAgreement = KeyAgreement.getInstance(KEYAGREEMENT_ALGORITHM, "BC");
                keyAgreement.init(keyHolder.keyPair.getPrivate());
                keyAgreement.doPhase(publicKey, true);
                secretKeyBin = createSecretKeyFromHMAC(HMAC_ALGORITHM, keyAgreement.generateSecret());
            }
        }
        byte[] dataBin = {};
        StringBuilder stringBuilder = new StringBuilder();
        Stream.of(otherIds).filter(otherId -> !partyId.equals(otherId)).forEach(otherId -> {
            stringBuilder.append(otherId).append(",");
        });
        // send msg
        if (secretKeyBin != null) {
            logger.info("[" + partyId + "] to [" + stringBuilder.toString() + "][" + secretKeyBin.length + "]:" + Hex.toHexString(secretKeyBin));
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, "BC");
            SecretKey secretKey = null;
            AlgorithmParameterSpec algorithmParameterSpec = null;
            List<byte[]> bytes = createKeysForBlockCipher(secretKeyBin);
            byte[] secretKeyBinBytes = bytes.get(1);
            byte[] ivBytes = bytes.get(0);
            if (ivBytes != null || ivBytes.length == 0) {
                algorithmParameterSpec = new IvParameterSpec(ivBytes);
            }
            secretKey = new SecretKeySpec(secretKeyBinBytes, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);
            dataBin = cipher.doFinal(message.getBytes("utf-8"));
            logger.info("[" + partyId + "] sent to [" + stringBuilder.toString() + "] message:" + message);
        } else {
            logger.info("[" + partyId + "] to [" + stringBuilder.toString() + "] cannot found shared key");
        }
        return dataBin;
    }

    protected boolean receiveMsg(String partyId, byte[] dataBin, String... otherIds) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        KeyHolder keyHolder = mapParties.get(partyId);
        SortedSet<String> setIds = Stream.of(otherIds).collect(Collectors.toCollection(TreeSet::new));
        byte[] secretKeyBin = keyHolder.mapOtherSecretKey.get(setIds);
        if (secretKeyBin == null) {
            byte[] publicKeyBin = mapComposedPublicKey.get(setIds);
            if (publicKeyBin != null) {
                PublicKey publicKey = getPublicKeyFromByteArray(publicKeyBin);
                KeyAgreement keyAgreement = KeyAgreement.getInstance(KEYAGREEMENT_ALGORITHM, "BC");
                keyAgreement.init(keyHolder.keyPair.getPrivate());
                keyAgreement.doPhase(publicKey, true);
                secretKeyBin = createSecretKeyFromHMAC(HMAC_ALGORITHM, keyAgreement.generateSecret());
            }
        }
        byte[] originData = {};
        // receive msg
        StringBuilder stringBuilder = new StringBuilder();
        Stream.of(otherIds).filter(otherId -> !partyId.equals(otherId)).forEach(otherId -> {
            stringBuilder.append(otherId).append(",");
        });
        if (dataBin == null || dataBin.length == 0) {
            logger.info("[" + partyId + "] from [" + stringBuilder.toString() + "] cannot found Encrypted doc");
            return false;
        }
        if (secretKeyBin != null) {
            logger.info("[" + partyId + "] from [" + stringBuilder.toString() + "]:" + Hex.toHexString(secretKeyBin));
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM, "BC");
            SecretKey secretKey = new SecretKeySpec(secretKeyBin, "AES");
            AlgorithmParameterSpec algorithmParameterSpec = null;
            List<byte[]> bytes = createKeysForBlockCipher(secretKeyBin);
            byte[] secretKeyBinBytes = bytes.get(1);
            byte[] ivBytes = bytes.get(0);
            if (ivBytes != null || ivBytes.length == 0) {
                algorithmParameterSpec = new IvParameterSpec(ivBytes);
            }
            secretKey = new SecretKeySpec(secretKeyBinBytes, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, algorithmParameterSpec);
            originData = cipher.doFinal(dataBin);
            String msg = new String(originData);
            logger.info("[" + partyId + "] received from [" + stringBuilder.toString() + "] message:" + msg);
            return true;
        } else {
            logger.info("[" + partyId + "] from [" + stringBuilder.toString() + "] cannot found shared key");
            return false;
        }
    }

    private void accumulatePublicKey(SortedSet<String> fromIds, SortedSet<String> toIds, AtomicInteger count) {
        byte[] publicKeyBin1 = mapComposedPublicKey.get(toIds);
        if (publicKeyBin1 != null) {
            Object[] newKh = fromIds.stream().map(e -> {
                Object[] rs = null;
                byte[] publicKeyBin = mapComposedPublicKey.get(Stream.of(e).collect(Collectors.toCollection(TreeSet::new)));
                if (publicKeyBin != null) {
                    rs = new Object[]{
                            Stream.of(e).collect(Collectors.toCollection(TreeSet::new)),
                            publicKeyBin};
                }
                return rs;
            }).reduce(new Object[]{toIds, publicKeyBin1}, (v1, v2) -> {
                Object[] rs = null;
                if (v1 != null && v2 != null) {
                    SortedSet<String> accumulatedId = new TreeSet<>();
                    SortedSet<String> idsFrom = (SortedSet<String>) v2[0];
                    SortedSet<String> idsTo = (SortedSet<String>) v1[0];
                    byte[] pubKeyBinTo = (byte[]) v1[1];
                    String[] idsToStr = idsTo.toArray(new String[idsTo.size()]);
                    try {
                        count.getAndIncrement();
                        accumulatedId.addAll(idsFrom);
                        accumulatedId.addAll(idsTo);
                        byte[] accumulatedKeyBin = joinGroup(idsFrom.first(), pubKeyBinTo, idsToStr);
                        rs = new Object[]{accumulatedId, accumulatedKeyBin};
                    } catch (Exception e) {
                        logger.info("", e);
                    }
                }
                return rs;
            });
            SortedSet<String> newId = (SortedSet<String>) newKh[0];
            byte[] newKey = (byte[]) newKh[1];
            mapComposedPublicKey.put(newId, newKey);
        }
    }

    protected void joinGroups(String[] ids) {
        Queue<KeyHolder> queue = new ArrayDeque<>();
        Stream.of(ids).forEach(e -> {
            KeyHolder keyHolder = mapParties.get(e);
            queue.offer(keyHolder);
        });
        AtomicInteger count = new AtomicInteger(0);
        while (true) {
            KeyHolder e1 = queue.poll();
            if (e1 == null) {
                break;
            }
            KeyHolder e2 = queue.poll();
            KeyHolder composeKh = new KeyHolder();
            if (e1.id.size() + e2.id.size() < ids.length) {
                // normal key
                SortedSet<String> composeKey = e2.id.stream().collect(Collectors.toCollection(TreeSet::new));
                composeKey.addAll(e1.id);
                accumulatePublicKey(e2.id, e1.id, count);
                composeKh.id = composeKey;
                queue.add(composeKh);
            } else {
                // before final key
                e1.id.stream().forEach(e -> {
                    SortedSet<String> fromKey = e1.id.stream().filter(elem -> !e.equals(elem))
                            .collect(Collectors.toCollection(TreeSet::new));
                    accumulatePublicKey(fromKey, e2.id, count);
                });
                e2.id.stream().forEach(e -> {
                    SortedSet<String> fromKey = e2.id.stream().filter(elem -> !e.equals(elem))
                            .collect(Collectors.toCollection(TreeSet::new));
                    accumulatePublicKey(fromKey, e1.id, count);
                });
            }
        }
        queue.clear();
        logger.warn("Total: " + count.get());
    }

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        TestKeyAgreement testKeyAgreement = new TestKeyAgreement();
        testKeyAgreement.init();
        int numberId = 11;
        List<String> lsIds = new ArrayList<>();
        IntStream.range(0, numberId).forEach(i -> {
            lsIds.add(String.format("p%02d", i + 1));
        });
        String[] ids = lsIds.toArray(new String[lsIds.size()]);
        Stream<String> streamIds = null;
        logger.info("===== init =====");
        streamIds = Stream.of(ids);
        streamIds.forEach(e -> {
            try {
                testKeyAgreement.createKeyPair(e);
            } catch (NoSuchProviderException ex) {
                logger.error("", e);
            } catch (NoSuchAlgorithmException ex) {
                logger.error("", e);
            } catch (InvalidAlgorithmParameterException ex) {
                logger.error("", e);
            }
        });
        streamIds.close();
        logger.info("===== exchange public key =====");
        streamIds = Stream.of(ids);
        streamIds.forEach(e -> {
            try {
                testKeyAgreement.publishPublicKey(e);
            } catch (NoSuchAlgorithmException ex) {
                logger.error("", e);
            } catch (InvalidKeyException ex) {
                logger.error("", e);
            } catch (NoSuchProviderException ex) {
                logger.error("", e);
            }
        });
        streamIds.close();
        logger.info("===== join group =====");
        long start = Calendar.getInstance().getTimeInMillis();
        testKeyAgreement.joinGroups(ids);
        long end = Calendar.getInstance().getTimeInMillis();
        logger.warn("Join groups time:" + (end - start));
        logger.info("===== send messages =====");
        SortedSet<String> sendDest = Stream.of(ids).collect(Collectors.toCollection(TreeSet::new));
        sendDest.remove(ids[0]);
        SortedSet<String> receiveDest = Stream.of(ids).collect(Collectors.toCollection(TreeSet::new));
        receiveDest.remove(ids[1]);
        byte[] encMsgAll = testKeyAgreement.sendMsg(ids[0], "Alice to All", sendDest.toArray(new String[sendDest.size()]));
        logger.info("===== receive messages =====");
        testKeyAgreement.receiveMsg(ids[1], encMsgAll, receiveDest.toArray(new String[receiveDest.size()]));
    }
}
