package Lasse_Herskind.SingleKnowledgeProof;

import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;

public class KnowledgeProof<T extends GroupElement<T>> implements Proof {

    private final T A;
    private final T T;
    private final T S;

    public KnowledgeProof(T A, T T, T S) {
        this.A = A;
        this.T = T;
        this.S = S;
    }

    public T getA() {
        return A;
    }

    public T getT() {
        return T;
    }

    public T getS() {
        return S;
    }


    @Override
    public byte[] serialize() {
        return new byte[0];
    }
}
