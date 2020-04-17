package Sha256;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class SHA256 {
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    private static final int[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf,
            0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
            0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc,
            0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
            0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
            0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
            0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
            0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
            0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2 };

    private static final int[] H0 = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372,
            0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    //Работни масиви
    private static final int[] W = new int[64];
    private static final int[] H = new int[8];
    private static final int[] TEMP = new int[8];

    public static String hash(String message){
        byte[] bytes = message.getBytes(UTF_8);

        //Казваме, че H = H0 масива
        System.arraycopy(H0, 0, H, 0, H0.length);

        //Разделяме съобщението с добавените байтове на думи (words) като думите се презентират в INT цели числа
        int[] words = SHA256Utilities.toIntArray(pad(bytes));

        //Този цикъл се върти от 0 докато i<n като n = words.length/16
        for (int i = 0, n = words.length / 16; i < n; ++i) {

            // Копираме words масива в W работния масив
            System.arraycopy(words, i * 16, W, 0, 16);


            for (int t = 16; t < W.length; ++t) {
                W[t] = SHA256Utilities.smallSig1(W[t - 2]) + W[t - 7] + SHA256Utilities.smallSig0(W[t - 15])
                        + W[t - 16];
            }

            // Казваме, че TEMP = H масива
            System.arraycopy(H, 0, TEMP, 0, H.length);

            // Операциите се извършват върху TEMP
            for (int t = 0; t < W.length; ++t) {
                int t1 = TEMP[7] + SHA256Utilities.bigSig1(TEMP[4])
                        + SHA256Utilities.ch(TEMP[4], TEMP[5], TEMP[6]) + K[t] + W[t];
                int t2 = SHA256Utilities.bigSig0(TEMP[0]) + SHA256Utilities.maj(TEMP[0], TEMP[1], TEMP[2]);
                System.arraycopy(TEMP, 0, TEMP, 1, TEMP.length - 1);
                TEMP[4] += t1;
                TEMP[0] = t1 + t2;
            }

            // add values in TEMP to values in H
            for (int t = 0; t < H.length; ++t) {
                H[t] += TEMP[t];
            }
        }
        byte[] result = SHA256Utilities.toByteArray(H);
        return SHA256Utilities.byteArrayToHex(result);
    }

    public static byte[] pad(byte[] bytes){
        //Статични променливи
        //512 бита
        final int blockBits = 512;

        // 64 байта == 512 бита ...... 1 байт = 8 бита
        final int blockBytes = blockBits / 8;

        // Към размера добавяме 1 байт + още 8 байта
        int newMessageLength = bytes.length + 1 + 8;


        //Намираме колко байта трябва да добавим така че съобщението да е кратно на 64 байта (512 бита) SHA-256
        int padBytes = (blockBytes - newMessageLength % blockBytes) % blockBytes;
        newMessageLength += padBytes;

        //Крайният масив, който е голям колкото изчислената дължина досега
        final byte[] paddedMessage = new byte[newMessageLength];

        //Копиране на масива bytes в масива paddedMessage в началото
        System.arraycopy(bytes, 0, paddedMessage, 0, bytes.length);

        // Записваме 1 бит
        paddedMessage[bytes.length] = (byte) 0b10000000;

        // пропускаме padBytes брой байтове (те вече са 0)
        int lenPos = bytes.length + 1 + padBytes; // Променлива за позиция където трябва да се добави размера на съобщението

        // Записваме 8-байтово цяло число в края на масива, което показва размера на съобщението (Пример: abc = 3 байта ==> 3 байта * 8 бита = 26 бита)
        ByteBuffer.wrap(paddedMessage, lenPos, 8).putLong(bytes.length * 8);
        return paddedMessage;
    }
}
