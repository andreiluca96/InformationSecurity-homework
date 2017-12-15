package com.company;

import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class CryptoUtils {
    public static final int KEY_SIZE_IN_BYTES = 16;
    private static final String initVector = "qqqqqqqqqqqqqqqq";

    public static List<String> encryptMessage(String key, String plainText, String cypherMode) {
        String paddedPlainText =
                rightPadding(plainText, plainText.length() + (KEY_SIZE_IN_BYTES - plainText.length() % KEY_SIZE_IN_BYTES));
        List<String> blocks = Arrays.asList(paddedPlainText.split("(?<=\\G.{" + KEY_SIZE_IN_BYTES + "})"));


        if (cypherMode.compareToIgnoreCase("ECB") == 0) {
            return blocks.stream()
                    .map(block -> encryptBlock(block, key))
                    .collect(Collectors.toList());
        }

        if (cypherMode.compareToIgnoreCase("CBC") == 0) {
            final String[] lastEntry = {initVector};

            return blocks.stream()
                    .map(block -> {
                        String xorResult = new String(xor(block.getBytes(), lastEntry[0].getBytes()));
                        String cypherBlock = encryptBlock(xorResult, key);
                        lastEntry[0] = cypherBlock;

                        return cypherBlock;
                    })
                    .collect(Collectors.toList());
        }

        return null;
    }

    public static String decryptMessage(List<String> blocks, String key, String cypherMode) {
        StringBuilder decryptedText = new StringBuilder();
        if (cypherMode.compareToIgnoreCase("ECB") == 0) {
            blocks.stream()
                .map(block -> decryptBlock(block,  key))
                .forEach(decryptedText::append);
        }

        if (cypherMode.compareToIgnoreCase("CBC") == 0) {
            List<String> plainTextBlocks = new ArrayList<>();
            for (int i = blocks.size() - 1; i > 0; i--) {
                String decryptedBlock = decryptBlock(blocks.get(i), key);
                String plainTextBlock = new String(xor(decryptedBlock.getBytes(), blocks.get(i - 1).getBytes()));

                plainTextBlocks.add(plainTextBlock);
            }

            String decryptedBlock = decryptBlock(blocks.get(0), key);
            String plainTextBlock = new String(xor(decryptedBlock.getBytes(), initVector.getBytes()));
            plainTextBlocks.add(plainTextBlock);

            for (int i = blocks.size() - 1; i >= 0; i--) {
                decryptedText.append(plainTextBlocks.get(i));
            }
        }

        return decryptedText.toString();
    }


    public static String encryptBlock(String value, String key) {
        try {
            String paddedKey = rightPadding(key, KEY_SIZE_IN_BYTES);
            SecretKeySpec secretKeySpec = new SecretKeySpec(paddedKey.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            byte[] encrypted = cipher.doFinal(value.getBytes());

            return Base64.encode(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static String decryptBlock(String encrypted, String key) {
        try {
            String paddedKey = rightPadding(key, KEY_SIZE_IN_BYTES);
            SecretKeySpec skeySpec = new SecretKeySpec(paddedKey.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec);

            byte[] original = cipher.doFinal(Base64.decode(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static String rightPadding(String str, int num) {
        return String.format("%1$-" + num + "s", str);
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }
}
