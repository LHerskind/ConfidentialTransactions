package Lasse_Herskind.SingleKnowledgeProof;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class KnowledgeProofProver<T extends GroupElement<T>> implements Prover<GeneratorParams<T>, T, PeddersenCommitment<T>, KnowledgeProof<T>> {
    @Override
    public KnowledgeProof<T> generateProof(GeneratorParams<T> parameter, T commitment, PeddersenCommitment<T> witness) {
        BigInteger q = parameter.getGroup().groupOrder();
        T A = witness.getCommitment();

        if(!commitment.equals(A)){
            return null;
        }

        BigInteger t1 = ProofUtils.randomNumber();
        BigInteger t2 = ProofUtils.randomNumber();

        T T = parameter.getBase().commit(t1, t2);

        BigInteger challenge = ProofUtils.computeChallenge(q, commitment, T);

        BigInteger s1 = t1.add(witness.getX().multiply(challenge));
        BigInteger s2 = t2.add(witness.getR().multiply(challenge));

        T S = parameter.getBase().commit(s1, s2);

        return new KnowledgeProof<>(A, T, S);
    }
}
