package com.zjw.common.utils.endecrypt.gm;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

/**
 * sm2
 *
 * @author zjw
 */
public class SM2Utils {

    private static final int C1_LEN = 65;
    private static final int C3_LEN = 32;

    /**
     * 将c1c3c2转成ASN1格式
     */
    public static byte[] changeC1C3C2ToAsn1(byte[] c1c3c2) throws IOException {
        byte[] c1 = Arrays.copyOfRange(c1c3c2, 0, C1_LEN);
        byte[] c3 = Arrays.copyOfRange(c1c3c2, C1_LEN, C1_LEN + C3_LEN);
        byte[] c2 = Arrays.copyOfRange(c1c3c2, C1_LEN + C3_LEN, c1c3c2.length);
        byte[] c1X = Arrays.copyOfRange(c1, 1, 33);
        byte[] c1Y = Arrays.copyOfRange(c1, 33, 65);

        BigInteger r = new BigInteger(1, c1X);
        BigInteger s = new BigInteger(1, c1Y);

        ASN1Integer x = new ASN1Integer(r);
        ASN1Integer y = new ASN1Integer(s);
        DEROctetString derDig = new DEROctetString(c3);
        DEROctetString derEnc = new DEROctetString(c2);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(x);
        v.add(y);
        v.add(derDig);
        v.add(derEnc);
        DERSequence seq = new DERSequence(v);
        return seq.getEncoded(ASN1Encoding.DER);
    }

    /**
     * 将ASN1格式（本来是C1C3C2格式）转成C1C3C2
     */
    public static byte[] changeAsn1ToC1C3C2(byte[] asn1) throws IOException {
        List<byte[]> bytes = changeAsn1ToList(asn1);
        return Arrays.concatenate(bytes.get(0), bytes.get(1), bytes.get(2));
    }

    /**
     * 将ASN1格式（本来是C1C3C2格式）转成C1C2C3
     */
    public static byte[] changeAsn1ToC1C2C3(byte[] asn1) throws IOException {
        List<byte[]> bytes = changeAsn1ToList(asn1);
        return Arrays.concatenate(bytes.get(0), bytes.get(2), bytes.get(1));
    }

    public static List<byte[]> changeAsn1ToList(byte[] asn1) throws IOException {
        try (ASN1InputStream aIn = new ASN1InputStream(asn1)) {
            ASN1Sequence seq = (ASN1Sequence) aIn.readObject();
            BigInteger x = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
            BigInteger y = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            byte[] c2 = ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
            byte[] c3 = ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();

            ECPoint c1Point = GMNamedCurves.getByName("sm2p256v1").getCurve().createPoint(x, y);
            byte[] c1 = c1Point.getEncoded(false);

            ArrayList<byte[]> result = new ArrayList<>(3);
            result.add(c1);
            result.add(c2);
            result.add(c3);
            return result;
        }
    }


    private SM2Utils() {
    }
}
