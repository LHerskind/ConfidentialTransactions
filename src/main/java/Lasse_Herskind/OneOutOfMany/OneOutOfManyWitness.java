package Lasse_Herskind.OneOutOfMany;

import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;

import java.math.BigInteger;

public class OneOutOfManyWitness<T extends GroupElement<T>> {

    private final int l;
    private BigInteger[] gammaK;
    private final DoubleBlindedPedersenCommitment<T> coin;

    public OneOutOfManyWitness(int l, DoubleBlindedPedersenCommitment<T> coin){
        this.l = l;
        this.coin = coin;
    }

    public void setGammaK(BigInteger[] gammaK) {
        this.gammaK = gammaK;
    }

    public BigInteger[] getGammaK() {
        return gammaK;
    }

    public int getL() {
        return l;
    }

    public DoubleBlindedPedersenCommitment<T> getCoin() {
        return coin;
    }

    public BigInteger getV() {
        return this.coin.getValue();
    }

    public BigInteger getR() {
        return this.coin.getRandom();
    }
}
