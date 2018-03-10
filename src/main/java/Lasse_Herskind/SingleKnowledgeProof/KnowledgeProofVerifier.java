package Lasse_Herskind.SingleKnowledgeProof;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class KnowledgeProofVerifier<T extends GroupElement<T>> implements Verifier<GeneratorParams<T>, T , KnowledgeProof<T>> {
    @Override
    public void verify(GeneratorParams<T> params, T commitment, KnowledgeProof<T> proof) throws VerificationFailedException {
        BigInteger challenge = ProofUtils.computeChallenge(params.getGroup().groupOrder(), commitment, proof.getT());
        T verificationPoint = proof.getA().multiply(challenge).add(proof.getT());

        if(!verificationPoint.equals(proof.getS())){
            throw new VerificationFailedException();
        }
    }
}
