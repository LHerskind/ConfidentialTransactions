package Lasse_Herskind.OneOutOfManyMW;

import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;

import java.math.BigInteger;

public class OneOutOfManyWitnessMW<T extends GroupElement<T>> {

    private final int l;
    private BigInteger[] gammaK;
    private final DoubleBlindedPedersenCommitment<T> shielded_coin;
    private final DoubleBlindedPedersenCommitment<T> output_coin;

    public OneOutOfManyWitnessMW(int l, DoubleBlindedPedersenCommitment<T> shielded_coin, DoubleBlindedPedersenCommitment<T> output_coin){
        this.l = l;
        this.shielded_coin = shielded_coin;
        this.output_coin = output_coin;
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

    public DoubleBlindedPedersenCommitment<T> getShielded_coin() {
        return shielded_coin;
    }

    public DoubleBlindedPedersenCommitment<T> getOutput_coin() {
        return output_coin;
    }

    public BigInteger getV() {
        return this.shielded_coin.getValue();
    }

    public BigInteger getR() {
        return this.shielded_coin.getRandom().subtract(output_coin.getRandom());
    }
}
