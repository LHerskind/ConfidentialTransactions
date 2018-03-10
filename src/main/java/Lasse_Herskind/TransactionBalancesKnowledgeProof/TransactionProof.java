package Lasse_Herskind.TransactionBalancesKnowledgeProof;

import Lasse_Herskind.SingleKnowledgeProof.KnowledgeProof;
import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;

public class TransactionProof<T extends GroupElement<T>> implements Proof {

    private final KnowledgeProof<T> before;
    private final KnowledgeProof<T> amount;
    private final KnowledgeProof<T> after;
    private final RangeProof<T> afterRange;

    public TransactionProof(KnowledgeProof<T> before, KnowledgeProof<T> amount, KnowledgeProof<T> after, RangeProof<T> afterRange) {
        this.before = before;
        this.amount = amount;
        this.after = after;
        this.afterRange = afterRange;
    }

    public KnowledgeProof<T> getAfter() {
        return after;
    }

    public KnowledgeProof<T> getAmount() {
        return amount;
    }

    public KnowledgeProof<T> getBefore() {
        return before;
    }

    public RangeProof<T> getAfterRange() {
        return afterRange;
    }

    @Override
    public byte[] serialize() {
        return new byte[0];
    }
}
