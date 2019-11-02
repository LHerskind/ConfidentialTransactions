package Lasse_Herskind.OneOutOfManyMW;

import Lasse_Herskind.OneOutOfMany.OneOutOfManyProof;
import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;

import java.math.BigInteger;

public class OneOutOfManyProofMW<T extends GroupElement<T>> implements Proof {

    private final T A;
    private final T B;
    private final T C;
    private final T D;
    private final T[] Gks;
    private final T[] Qks;

    private final BigInteger[][] fs;
    private final BigInteger zA;
    private final BigInteger zC;
    private final BigInteger zR;

    public OneOutOfManyProofMW(T A, T B, T C, T D, T[] Gks, T[] Qks, BigInteger[][] fs, BigInteger zA, BigInteger zC, BigInteger zR) {
        this.A = A;
        this.B = B;
        this.C = C;
        this.D = D;
        this.Gks = Gks;
        this.Qks = Qks;
        this.fs = fs;
        this.zA = zA;
        this.zC = zC;
        this.zR = zR;
    }

    public T getA() {
        return A;
    }

    public T getB() {
        return B;
    }

    public T getC() {
        return C;
    }

    public T getD() {
        return D;
    }

    public T[] getGks() {
        return Gks;
    }

    public T[] getQks() {
        return Qks;
    }

    public BigInteger[][] getFs() {
        return fs;
    }

    public BigInteger getzA() {
        return zA;
    }

    public BigInteger getzC() {
        return zC;
    }

    public BigInteger getzR() {
        return zR;
    }

    @Override
    public byte[] serialize() {
        return new byte[0];
    }
}
