package Lasse_Herskind.GeneralizedSchnorr;

import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;

public class GeneralizedSchnorrProof<T extends GroupElement> implements Proof {

    // TODO: Note to self, this is exactly the knowledge proof that we used in the bachelor thesis

    private final T A;
    private final T T;
    private final T S;

    public GeneralizedSchnorrProof(T A, T T, T S){
        this.A = A;
        this.T = T;
        this.S = S;
    }

    public T getA(){return this.A;}
    public T getT(){return this.T;}
    public T getS(){return this.S;}

    @Override
    public byte[] serialize() {
        return new byte[0];
    }
}
