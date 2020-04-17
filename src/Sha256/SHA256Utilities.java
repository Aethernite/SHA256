package Sha256;

import java.nio.ByteBuffer;

public class SHA256Utilities {

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

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] toByteArray(int[] ints)
    {
        ByteBuffer buf = ByteBuffer.allocate(ints.length * Integer.BYTES);
        for (int anInt : ints) {
            buf.putInt(anInt);
        }

        return buf.array();
    }

    public static int[] toIntArray(byte[] bytes)
    {
        //Ако дължината на байтовете модулно деление с байтовете на Integer (4 байта) не е равно на 0 значи има някъде грешка
        if (bytes.length % Integer.BYTES != 0) {
            throw new IllegalArgumentException("Невалидна дължина на байтовете!");
        }

        ByteBuffer buf = ByteBuffer.wrap(bytes);

        //Този масив съдържа bytes.length / Integer.BYTES елемента ( или 16 думи - така наречените words)
        int[] result = new int[bytes.length / Integer.BYTES];
        for (int i = 0; i < result.length; ++i) {
            //The getInt() method of java.nio.ByteBuffer class is used to read the next four bytes
            // at this buffer’s current position, composing them into an int value
            // according to the current byte order, and then increments the position by four.
            // С други думи този метод превръща тези words (думи) в цели INT числа
            result[i] = buf.getInt();
        }

        return result;
    }


    public static int smallSig0(int x)
    {
        //Integer.rotateRight прилага определен брой right shifts >>> върху дадено число, но не заменя числата с 0 а ги премества в началото
        // В случая алгоритъма ни е такъв - rotate-ваме с 7 места ^ rotate-ваме с 18 места ^ и шифтваме с 3 бита
        return Integer.rotateRight(x, 7) ^ Integer.rotateRight(x, 18)
                ^ (x >>> 3);
    }

    public static int smallSig1(int x)
    {
        // В случая алгоритъма ни е такъв - rotate-ваме с 17 места ^ rotate-ваме с 19 места ^ и шифтваме с 10 бита
        return Integer.rotateRight(x, 17) ^ Integer.rotateRight(x, 19)
                ^ (x >>> 10);
    }


    public static int bigSig0(int x)
    {
        // В случая алгоритъма ни е такъв - rotate-ваме с 2 места ^ rotate-ваме с 13 места ^ rotate-ваме с 22 места
        return Integer.rotateRight(x, 2) ^ Integer.rotateRight(x, 13)
                ^ Integer.rotateRight(x, 22);
    }

    public static int bigSig1(int x)
    {
        // В случая алгоритъма ни е такъв - rotate-ваме с 6 места ^ rotate-ваме с 11 места ^ rotate-ваме с 25 места
        return Integer.rotateRight(x, 6) ^ Integer.rotateRight(x, 11)
                ^ Integer.rotateRight(x, 25);
    }


    public static int ch(int x, int y, int z)
    {
        return (x & y) | ((~x) & z);
    }

    public static int maj(int x, int y, int z)
    {
        return (x & y) | (x & z) | (y & z);
    }

}
