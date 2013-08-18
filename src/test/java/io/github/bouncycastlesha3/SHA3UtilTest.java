package io.github.bouncycastlesha3;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * http://en.wikipedia.org/wiki/SHA-3
 */
public class SHA3UtilTest {

    private static String EMPTYSTR224 = "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd";
    private static String EMPTYSTR256 = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    private static String EMPTYSTR384 = "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff";
    private static String EMPTYSTR512 = "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e";
    
    /**
     * Keccak-224("")
     */
    @Test
    public void doEMPTYSTR224() {
        String s = "";
        String result = SHA3Util.digest(s);
        assertEquals(EMPTYSTR224, result);
    }
    
    /**
     * Keccak-256("")
     */
    @Test
    public void doEMPTYSTR256() {
        String s = "";
        String result = SHA3Util.digest(s, SHA3Util.Size.S256);
        assertEquals(EMPTYSTR256, result);
    }
    
    /**
     * Keccak-384("")
     */
    @Test
    public void doEMPTYSTR384() {
        String s = "";
        String result = SHA3Util.digest(s, SHA3Util.Size.S384);
        assertEquals(EMPTYSTR384, result);
    }
    
    /**
     * Keccak-512("") using the toString(int) conversion will fail if the
     * resulting hash begins with 0.
     *
     */
    @Test(expected = AssertionError.class)
    public void doEMPTYSTR512WithBigIntegerEncoding() {
        String s = "";
        String result = SHA3Util.digest(s, SHA3Util.Size.S512, false);
        assertEquals(EMPTYSTR512, result);
    }
    
    /**
     * Keccak-512("")
     */
    @Test
    public void doEMPTYSTR512() {
        String s = "";
        String result = SHA3Util.digest(s, SHA3Util.Size.S512, true);
        assertEquals(EMPTYSTR512, result);
    }
}
