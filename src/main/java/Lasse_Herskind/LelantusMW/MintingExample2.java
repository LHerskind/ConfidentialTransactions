package Lasse_Herskind.LelantusMW;

import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProof;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofProver;
import Lasse_Herskind.GeneralizedSchnorr.GeneralizedSchnorrProofVerifier;
import Lasse_Herskind.LelantusUtils;
import edu.stanford.cs.crypto.efficientct.DoubleGeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.DoubleBlindedPedersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;

import java.math.BigInteger;

public class MintingExample2 {


    private static BN128Group curve;
    private static DoubleGeneratorParams params;
    private static GeneralizedSchnorrProofProver generalizedSchnorrProofProver;
    private static GeneralizedSchnorrProofVerifier generalizedSchnorrProofVerifier;


    private static void init(){
        curve = new BN128Group();
        params = DoubleGeneratorParams.generateParams(1, curve);
        generalizedSchnorrProofProver = new GeneralizedSchnorrProofProver();
        generalizedSchnorrProofVerifier = new GeneralizedSchnorrProofVerifier();
    }

    public static void main(String[] args) throws VerificationFailedException {
        init();

        // Inputs
        BigInteger V = BigInteger.valueOf(25);
        BigInteger R = ProofUtils.randomNumber();
        DoubleBlindedPedersenCommitment input_coin = LelantusUtils.getDBPedersen(params, BigInteger.ZERO, V, R);

        // Midway, we generate some stuff, known to the prover
        BigInteger q = ProofUtils.randomNumber();
        GroupElement Q = params.getBase().g.multiply(q);
        BigInteger S = ProofUtils.hash(Q.toString());
        // We need to make an offset with an additional R hence it will otherwise be possible to link transactions coming in and out of the pool.
        BigInteger R_offset = ProofUtils.randomNumber();

        System.out.println("C: " +input_coin);

        DoubleBlindedPedersenCommitment shielded_coin = LelantusUtils.getDBPedersen(params, S, BigInteger.ZERO, BigInteger.ZERO).add(input_coin);
        System.out.println("D: " + shielded_coin);

        DoubleBlindedPedersenCommitment discreteLogRelation = shielded_coin.sub(input_coin);
        System.out.println("D/C: " + discreteLogRelation);

        GeneralizedSchnorrProof generalizedSchnorrProof =  generalizedSchnorrProofProver.generateProof(params, discreteLogRelation.getCommitment(), discreteLogRelation);
        generalizedSchnorrProofVerifier.verify(params, discreteLogRelation.getCommitment(), generalizedSchnorrProof);
        System.out.println("The discrete relation holds! Proven with a generalized Schnorr Proof");

        // Down here we make sure he actually know the input
        GeneralizedSchnorrProof generalizedSchnorrProof2 =  generalizedSchnorrProofProver.generateProofNoS(params, input_coin.getCommitment(), input_coin);
        generalizedSchnorrProofVerifier.verifyNoS(params, input_coin.getCommitment(), generalizedSchnorrProof2);

        // Now we need to make sure that the excess holds? And can we by doing so discard the above? Would be cool
        DoubleBlindedPedersenCommitment inputs = input_coin;
        DoubleBlindedPedersenCommitment outputs = shielded_coin;

        DoubleBlindedPedersenCommitment excess = outputs.sub(inputs);
        System.out.println(excess); // Issue, this excess does not take into account that we need to prove
        // Seems stupid if we need to prove range on excess :/

    }

}
