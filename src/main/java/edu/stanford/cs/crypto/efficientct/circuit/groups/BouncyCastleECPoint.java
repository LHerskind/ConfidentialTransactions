package edu.stanford.cs.crypto.efficientct.circuit.groups;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class BouncyCastleECPoint implements GroupElement<edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint> {
    public static int expCount=0;
    public static int addCount=0;
    private final ECPoint point;

    public BouncyCastleECPoint(ECPoint point) {
        this.point = point;
    }

    @Override
    public edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint add(edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint other) {
        ++addCount;
        return from(point.add(other.point));
    }

    @Override
    public edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint multiply(BigInteger exp) {
        ++expCount;
        return from(point.multiply(exp));
    }

    @Override
    public edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint negate() {
        return from(point.negate());
    }

    @Override
    public byte[] canonicalRepresentation() {
        return point.getEncoded(true);
    }

    @Override
    public String stringRepresentation() {
        return point.normalize().toString();
    }

    private static edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint from(ECPoint point) {
        return new edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint(point);
    }

    public ECPoint getPoint() {
        return point;
    }

    @Override
    public String toString() {
        return point.normalize().toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint that = (edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint) o;

        return point != null ? point.equals(that.point) : that.point == null;
    }

    @Override
    public int hashCode() {
        return point != null ? point.hashCode() : 0;
    }
}
