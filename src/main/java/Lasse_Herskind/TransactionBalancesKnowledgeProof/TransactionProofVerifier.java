package Lasse_Herskind.TransactionBalancesKnowledgeProof;

import Lasse_Herskind.SingleKnowledgeProof.KnowledgeProof;
import Lasse_Herskind.SingleKnowledgeProof.KnowledgeProofVerifier;
import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.Proof;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProofVerifier;

public class TransactionProofVerifier<T extends GroupElement<T>> {

    public void verify(GeneratorParams<T> params, VectorX<T> commitments, VectorX<Proof> proofs) throws VerificationFailedException {
        KnowledgeProofVerifier knowledgeProofVerifier = new KnowledgeProofVerifier();
        knowledgeProofVerifier.verify(params, commitments.get(0), (KnowledgeProof) proofs.get(0));
        knowledgeProofVerifier.verify(params, commitments.get(1), (KnowledgeProof) proofs.get(1));
        knowledgeProofVerifier.verify(params, commitments.get(2), (KnowledgeProof) proofs.get(2));
        new RangeProofVerifier().verify(params, commitments.get(3), (RangeProof) proofs.get(3));
    }
}
