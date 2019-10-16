package Lasse_Herskind.GeneralizedSchnorr;

import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class GeneralizedSchnorrProofProver<T extends GroupElement<T>> implements Prover<DoubleGeneratorParams<T>, T, DoubleBlindedPedersenCommitment<T>, GeneralizedSchnorrProof<T>> {
    @Override
    public GeneralizedSchnorrProof<T> generateProof(DoubleGeneratorParams<T> parameter, T commitment, DoubleBlindedPedersenCommitment<T> witness) {
        // Notation in this implementation is a bit different from the paper. y -> A. u -> T
        T A = witness.getCommitment();

        if(!commitment.equals(A)){
            return null;
        }

        BigInteger s0 = ProofUtils.randomNumber();
        BigInteger t0 = ProofUtils.randomNumber();

        T T = parameter.getBase().commit(s0, BigInteger.ZERO, t0);

        BigInteger challenge = ProofUtils.computeChallenge(parameter.getGroup().groupOrder(), commitment, T);

        BigInteger s1 = s0.add(witness.getSerial().multiply(challenge));
        BigInteger t1 = t0.add(witness.getRandom().multiply(challenge));

        T S = parameter.getBase().commit(s1, BigInteger.ZERO ,t1);

        return new GeneralizedSchnorrProof<>(A, T, S);
    }



}
