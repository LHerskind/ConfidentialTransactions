package edu.stanford.cs.crypto.efficientct.commitments;

import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.linearalgebra.DoublePeddersenBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

/**
 * Created by buenz on 7/6/17.
 */
public class DoubleBlindedPedersenCommitment<T extends GroupElement<T>> implements HomomorphicCommitment<DoubleBlindedPedersenCommitment<T>> {
    private final DoublePeddersenBase<T> base;
    private final BigInteger serial;
    private final BigInteger value;
    private final BigInteger random;
    private T commitment;

    public DoubleBlindedPedersenCommitment(DoublePeddersenBase<T> base, BigInteger serial, BigInteger value, BigInteger random) {
        this.base = base;
        this.serial = serial;
        this.value = value;
        this.random = random;
    }

    public DoubleBlindedPedersenCommitment(DoublePeddersenBase<T> base, BigInteger value) {
        this(base, ProofUtils.randomNumber(), value, ProofUtils.randomNumber());
    }

    @Override
    public <C2 extends DoubleBlindedPedersenCommitment<T>> DoubleBlindedPedersenCommitment<T> add(C2 other) {
        return new DoubleBlindedPedersenCommitment<>(base, serial.add(other.getSerial()), value.add(other.getValue()), random.add(other.getRandom()));
    }

    public <C2 extends DoubleBlindedPedersenCommitment<T>> DoubleBlindedPedersenCommitment<T> sub(C2 other) {
        return new DoubleBlindedPedersenCommitment<>(base,serial.subtract(other.getSerial()),  value.subtract(other.getValue()),  random.subtract(other.getRandom()));
    }

    @Override
    public DoubleBlindedPedersenCommitment<T> times(BigInteger exponent) {
        return new DoubleBlindedPedersenCommitment<>(base, serial.multiply(exponent), value.multiply(exponent), random.multiply(exponent));
    }

    @Override
    public DoubleBlindedPedersenCommitment<T> addConstant(BigInteger constant) {
        return new DoubleBlindedPedersenCommitment<>(base, serial, value.add(constant),  random);
    }

    public BigInteger getValue() {
        return value;
    }

    public BigInteger getSerial() {
        return serial;
    }

    public BigInteger getRandom() {return random; }

    @Override
    public String toString() {
        return "Comm(" + this.serial + ", " + this.value +", " + this.random + ") = " + getCommitment().stringRepresentation();
    }

    public T getCommitment() {
        if (commitment == null) {
            commitment = base.commit(serial, value, random);
        }
        return commitment;
    }
}
